#!/usr/bin/env python3

# Copyright 2024 s3rj1k
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-lines
"""IPMI BMC implementation for managing Libvirt domains."""

# https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf
#  * boot flags - Page 396

import argparse
import inspect
import logging
import os
import secrets
import string
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from enum import Enum, IntEnum, IntFlag
from functools import wraps
from socket import socket
from threading import Lock
from typing import Optional, Dict, Any, Tuple
from uuid import UUID

import libvirt
import pyghmi.ipmi.private.session as ipmisession
from pyghmi.ipmi.command import power_states
from pyghmi.ipmi.private import constants
from pyghmi.ipmi.private.serversession import IpmiServer
from pyghmi.ipmi.private.serversession import ServerSession

DEFAULT_LISTEN_TIMEOUT = 30

domain_locks: Dict[str, Lock] = defaultdict(Lock)


def setup_logger(log_level: str) -> logging.Logger:
    """Configure and return a logger with the specified log level."""
    logger = logging.getLogger("LibvirtIPMI")
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, log_level.upper()))
    return logger


def domain_lock(func):
    """Decorator to ensure concurency-safe domain operations."""

    @wraps(func)
    def wrapper(self: "LibvirtIPMI", *args, **kwargs) -> Any:
        session = self.find_session(args, kwargs)
        if not session or not session.domain:
            self.logger.debug(
                f"No session or domain found for {func.__name__}, executing without lock"
            )
            return func(self, *args, **kwargs)

        self.logger.debug(
            f"Attempting to acquire lock for domain '{session.domain}' in {func.__name__}"
        )
        lock = domain_locks[session.domain]
        acquired = lock.acquire(timeout=5)
        if not acquired:
            self.logger.debug(
                f"Lock acquisition failed for domain '{session.domain}' in {func.__name__} (timeout)"
            )
            return IpmiResponseCode.NODE_BUSY

        self.logger.debug(
            f"Lock acquired for domain '{session.domain}' in {func.__name__}"
        )
        try:
            return func(self, *args, **kwargs)
        finally:
            lock.release()
            self.logger.debug(
                f"Lock released for domain '{session.domain}' in {func.__name__}"
            )

    return wrapper


# https://github.com/ipmitool/ipmitool/blob/master/lib/ipmi_strings.c#L1229
class IpmiResponseCode(IntEnum):
    """Standard IPMI response codes used to indicate command execution status."""

    SUCCESS = 0x00
    NODE_BUSY = 0xC0
    INVALID_COMMAND = 0xC1
    INVALID_DATA_FIELD = 0xCC
    DESTINATION_UNAVAILABLE = 0xD3
    COMMAND_NOT_SUPPORTED_IN_PRESENT_STATE = 0xD5
    COMMAND_DISABLED = 0xD6
    UNSPECIFIED_ERROR = 0xFF


class IpmiNetFn(IntEnum):
    """IPMI Network Function codes defining categories of commands."""

    CHASSIS = 0x00
    APP = 0x06


class IpmiCommand(IntEnum):
    """IPMI command codes for specific operations within each Network Function."""

    GET_DEVICE_ID = 0x01
    GET_SYSTEM_GUID = 0x37

    GET_CHASSIS_STATUS = 0x01
    CHASSIS_CONTROL = 0x02
    SET_SYSTEM_BOOT_OPTIONS = 0x08
    GET_SYSTEM_BOOT_OPTIONS = 0x09


class BootDevice(Enum):
    """Mapping between IPMI boot device codes and Libvirt boot device names."""

    NETWORK = (0b0001, "network")
    HD = (0b0010, "hd")
    CDROM = (0b0101, "cdrom")
    FD = (0b1111, "fd")

    def __init__(self, code: int, name: str):
        self.ipmi_code = code
        self.libvirt_name = name

    @classmethod
    def from_ipmi(cls, code: int) -> Optional["BootDevice"]:
        """Convert IPMI boot device code to BootDevice enum value."""
        for device in cls:
            if device.ipmi_code == code:
                return device
        return None

    @classmethod
    def from_libvirt(cls, name: str) -> Optional["BootDevice"]:
        """Convert Libvirt boot device name to BootDevice enum value."""
        for device in cls:
            if device.libvirt_name == name:
                return device
        return None


class BootOptionParameters(IntEnum):
    """IPMI parameters for configuring system boot options."""

    SET_IN_PROGRESS = 0
    # SERVICE_PARTITION_SELECTOR = 1
    # SERVICE_PARTITION_SCAN = 2
    BOOT_FLAG_VALID_BIT_CLEARING = 3
    BOOT_INFO_ACKNOWLEDGE = 4
    BOOT_FLAGS = 5


class BootFlags(IntFlag):
    """IPMI boot flags for controlling boot behavior and state."""

    DEFAULT = 0b00000000
    VALID = 0b10000000
    PERSISTENT = 0b01000000
    EFI = 0b00100000
    LEGACY_BIOS = 0b00000000


class EnhancedServerSession(ServerSession):
    """Extended server session class that adds domain-aware authentication and management."""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        authdata: Dict[str, str],
        kg: Optional[str],
        clientaddr: tuple[str, int],
        netsocket: socket,
        request: bytes,
        uuid: Optional[UUID],
        bmc: "LibvirtIPMI",
    ) -> None:
        self._domain: Optional[str] = None
        self._bmc = bmc

        super().__init__(authdata, kg, clientaddr, netsocket, request, uuid, bmc)

    @property
    def domain(self) -> Optional[str]:
        """Get the domain name associated with the session."""
        if username := getattr(self, "username", None):
            return username.decode("utf-8")
        return None

    def get_sockaddr(self) -> Optional[Tuple[str, int, int, int]]:
        """Get the socket address tuple."""
        return getattr(self, "sockaddr", None)

    def close_server_session(self) -> None:
        """Override server session closure with error payload."""
        if hasattr(self, "clientsessionid"):
            self.send_payload(
                bytearray([0x00, 0x02, 0x00, 0x00]) + self.clientsessionid,
                constants.payload_types["rakp2"],
                retry=False,
            )

        super().close_server_session()

    def _got_rakp1(self, data: Any) -> None:
        """Override RAKP1 handling for faster domain validation."""
        if not hasattr(self, "_bmc") or not hasattr(self._bmc, "hypervisor"):
            self._bmc.logger.debug("BMC or hypervisor not properly configured")
            self.close_server_session()
            return

        try:
            domain_name = bytes(data[28:]).decode("utf-8")
            if not domain_name:
                self._bmc.logger.debug("Empty domain name in RAKP1")
                self.close_server_session()
                return

            with libvirt.openReadOnly(self._bmc.hypervisor) as conn:
                try:
                    conn.lookupByName(domain_name)
                    self.authdata = {domain_name: self._bmc.password}
                except libvirt.libvirtError:
                    self._bmc.logger.debug(f"Domain '{domain_name}' not found")
                    self.close_server_session()
                    return

            super()._got_rakp1(data)

        # pylint: disable=broad-exception-caught
        except (UnicodeDecodeError, libvirt.libvirtError, Exception) as e:
            self._bmc.logger.debug(f"Error in RAKP1 handling: {e}")
            self.close_server_session()
            return


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class LibvirtIPMI(IpmiServer):
    """Baseboard Management Controller implementation for Libvirt domains using IPMI protocol."""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        address: str,
        port: int,
        password: str,
        hypervisor: str,
        logger: logging.Logger,
    ) -> None:
        random_username = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(12)
        )
        super().__init__(
            authdata={random_username: password}, address=address, port=port
        )
        self.logger = logger

        self.password = password
        self.hypervisor = hypervisor

        self.lib_major_ver: int = 0
        self.lib_minor_ver: int = 0
        self.major_ver: int = 0
        self.minor_ver: int = 0

        self.conn = None
        self.get_connection()

    def format_bytes(self, data: Any) -> str:
        """Format byte data consistently for logging."""
        match data:
            case bytes() | bytearray():
                return f"[{', '.join(f'0x{b:02x}' for b in data)}]"
            case list():
                return f"[{', '.join(f'0x{b:02x}' for b in data)}]"
            case None:
                return "[]"
            case _:
                return str(data)

    def format_ipmi_message(
        self, prefix: str, session: Any, code: Optional[int] = None, data: Any = None
    ) -> str:
        """Format IPMI message consistently for logging."""
        parts = [
            f"{prefix} -",
            f"Domain[{session.domain if hasattr(session, 'domain') else 'Unknown'}]",
        ]

        if prefix == "Request" and hasattr(session, "get_sockaddr"):
            if clientaddr := session.get_sockaddr():
                parts.extend([f"RAddr[{clientaddr[0]}]", f"RPort[{clientaddr[1]}]"])

        if prefix == "Request" and isinstance(data, dict):
            parts.extend(
                [
                    f"NetFn[0x{data.get('netfn', 0):02x}]",
                    f"Cmd[0x{data.get('command', 0):02x}]",
                    f"Data{self.format_bytes(data.get('data', []))}",
                ]
            )

        if prefix == "Response":
            parts.append(f"Code[0x{code:02x}]")
            if data is not None:
                parts.append(f"Data{self.format_bytes(data)}")

        return " ".join(parts)

    def send_ipmi_response(self, session: Any, code: int, data: Any) -> None:
        """Send an IPMI response to the session."""
        try:
            self.logger.info(self.format_ipmi_message("Response", session, code, data))

            if data is not None:
                session.send_ipmi_response(code=code, data=data)
            else:
                session.send_ipmi_response(code=code)
        # pylint: disable=broad-exception-caught
        except Exception as e:
            if hasattr(session, "domain") and session.domain:
                self.logger.error(
                    f"Failed to send IPMI response for domain {session.domain}: {e}"
                )
            else:
                self.logger.error(f"Failed to send IPMI response: {e}")

    def find_session(self, args: tuple, kwargs: dict) -> Optional[Any]:
        """Find and return the session from args or kwargs."""
        if session := kwargs.get("session"):
            if session.domain:
                return session
            return None

        for arg in args:
            if hasattr(arg, "domain"):
                if arg.domain:
                    return arg
                return None
        return None

    def free_connection(self) -> None:
        """Free the Libvirt connection."""
        try:
            if hasattr(self, "conn") and self.conn:
                try:
                    self.logger.debug("Attempting to close Libvirt connection")
                    self.conn.close()
                    self.conn = None
                    self.logger.debug("Successfully closed Libvirt connection")
                # pylint: disable=broad-exception-caught
                except Exception as e:
                    self.logger.error(f"Failed to close connection: {e}")
        # pylint: disable=broad-exception-caught
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def __del__(self):
        self.free_connection()

    def parse_versions(self, version: int, libversion: int) -> None:
        """Parse and store version information."""
        self.logger.debug(
            f"Parsing versions - Raw Version: {version}, Raw Library: {libversion}"
        )

        if not version or not libversion:
            self.logger.debug("Version or libversion is empty/zero")
            raise libvirt.libvirtError("Failed to get version information")

        self.lib_major_ver = libversion // 1_000_000
        self.lib_minor_ver = (libversion // 1_000) % 1_000

        if version < 1_000_000:
            self.major_ver = version
            self.minor_ver = 0
            self.logger.warning(
                f"Version number {version} is smaller than expected format. "
                "Treating entire number as major version."
            )
        else:
            self.major_ver = version // 1_000_000
            self.minor_ver = (version // 1_000) % 1_000

        self.logger.debug(
            f"Parsed versions - Version: {self.major_ver}.{self.minor_ver}, "
            f"Library: {self.lib_major_ver}.{self.lib_minor_ver}"
        )

    def get_connection(self) -> Optional[libvirt.virConnect]:
        """Get or establish a Libvirt connection."""
        try:
            if self.conn and self.conn.isAlive():
                self.logger.debug("Reusing existing live connection")
                return self.conn

            if self.conn:
                self.logger.debug(
                    "Existing connection found but not alive, attempting to close"
                )
                try:
                    self.conn.close()
                # pylint: disable=broad-exception-caught
                except Exception:
                    self.logger.debug(
                        "Failed to close existing connection, ignoring error"
                    )
                    # pylint: disable=unnecessary-pass
                    pass

            self.logger.debug(
                f"Attempting to open new connection to hypervisor: {self.hypervisor}"
            )
            self.conn = libvirt.open(self.hypervisor)
            if not self.conn:
                self.logger.error("Failed to get connection: undefined object")
                self.conn = None
                return None

            self.parse_versions(self.conn.getVersion(), self.conn.getLibVersion())

            self.logger.debug("Successfully established new connection")
            return self.conn

        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to get connection: {e}")
            self.conn = None
            return None

    def get_domain(self, session: Any) -> Optional[libvirt.virDomain]:
        """Get the Libvirt domain associated with the session."""
        if not hasattr(session, "domain") or not session.domain:
            self.logger.debug("No domain specified in session")
            return None

        try:
            self.logger.debug(f"Looking up domain: {session.domain}")
            if conn := self.get_connection():
                self.logger.debug(f"Successfully found domain: {session.domain}")
                return conn.lookupByName(session.domain)

            self.logger.error(f"Failed to lookup domain: {session.domain}")
            return None
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to lookup domain: {e}")
            return None

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password mc info
    def get_device_id(self, session: Any) -> None:
        """Handle IPMI Get Device ID command."""
        data = [
            # Byte 1: Device ID
            self.lib_major_ver & 0xFF,
            # Byte 2: Device Revision
            self.lib_minor_ver & 0xFF,
            # Bytes 3-4: Firmware Revision
            self.major_ver & 0b01111111,
            self.minor_ver,
            # Byte 5: IPMI Version
            0b00000010,
            # Byte 6: Additional Device Support
            0b10000000,
            # Bytes 7-9: Manufacturer ID
            # (Libvirt https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers)
            0x5D,
            0x90,
            0x00,
            # Bytes 10-11: Product ID
            0xAF,
            0x10,
        ]
        self.send_ipmi_response(session, IpmiResponseCode.SUCCESS, data)

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password mc guid
    @domain_lock
    def get_system_guid(self, session: Any) -> None:
        """Handle IPMI Get System GUID command."""
        self.logger.debug("Getting domain GUID")
        domain = self.get_domain(session)
        if not domain:
            self.logger.debug("Domain unavailable for GUID retrieval")
            self.send_ipmi_response(
                session, IpmiResponseCode.DESTINATION_UNAVAILABLE, None
            )
            return

        try:
            guid = UUID(domain.UUIDString())
            self.logger.debug(
                f"Successfully retrieved domain '{session.domain}' GUID: {guid}"
            )
            self.send_ipmi_response(session, IpmiResponseCode.SUCCESS, guid.bytes_le)
        except (libvirt.libvirtError, ValueError) as e:
            self.logger.error(f"Failed to get domain '{session.domain}' UUID: {e}")
            self.send_ipmi_response(session, IpmiResponseCode.NODE_BUSY, None)

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password power off
    @domain_lock
    def power_off(self, session: Any) -> IpmiResponseCode:
        """Power off the virtual machine."""
        self.logger.debug("Attempting to power off domain")
        domain = self.get_domain(session)
        if not domain:
            self.logger.debug("Domain unavailable for power off")
            return IpmiResponseCode.DESTINATION_UNAVAILABLE

        try:
            if not domain.isActive():
                self.logger.debug(f"Domain '{session.domain}' is already powered off")
                return IpmiResponseCode.SUCCESS

            self.logger.debug(
                f"Domain '{session.domain}' is active, sending destroy command"
            )
            domain.destroy()
            self.logger.debug(f"Successfully powered off domain '{session.domain}'")
            return IpmiResponseCode.SUCCESS
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to power off domain '{session.domain}': {e}")
            return IpmiResponseCode.NODE_BUSY

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password power on
    @domain_lock
    def power_on(self, session: Any) -> IpmiResponseCode:
        """Power on the virtual machine."""
        self.logger.debug("Attempting to power on domain")
        domain = self.get_domain(session)
        if not domain:
            self.logger.debug("Domain unavailable for power on")
            return IpmiResponseCode.DESTINATION_UNAVAILABLE

        try:
            if domain.isActive():
                self.logger.debug(f"Domain '{session.domain}' is already powered on")
                return IpmiResponseCode.SUCCESS

            self.logger.debug(
                f"Domain '{session.domain}' is inactive, sending create command"
            )
            domain.create()
            self.logger.debug(f"Successfully powered on domain '{session.domain}'")
            return IpmiResponseCode.SUCCESS
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to power on domain '{session.domain}': {e}")
            return IpmiResponseCode.NODE_BUSY

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password chassis power cycle
    def power_cycle(self, session: Any) -> IpmiResponseCode:
        """Perform power cycle operation on the virtual machine."""
        self.logger.debug("Starting power cycle operation")
        rc = self.power_off(session)
        if rc != IpmiResponseCode.SUCCESS:
            self.logger.debug("Power off failed during cycle")
            return rc

        self.logger.debug("Power off successful, waiting before power on")
        time.sleep(1)

        self.logger.debug("Attempting power on after cycle delay")
        return self.power_on(session)

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password chassis power reset
    @domain_lock
    def power_reset(self, session: Any) -> IpmiResponseCode:
        """Perform hard reset on the virtual machine."""
        self.logger.debug("Attempting domain reset")
        domain = self.get_domain(session)
        if not domain:
            self.logger.debug("Domain unavailable for reset")
            return IpmiResponseCode.DESTINATION_UNAVAILABLE

        try:
            if not domain.isActive():
                self.logger.debug(f"Cannot reset inactive domain '{session.domain}'")
                return IpmiResponseCode.COMMAND_NOT_SUPPORTED_IN_PRESENT_STATE

            self.logger.debug(
                f"Domain '{session.domain}' is active, sending reset command"
            )
            domain.reset()
            self.logger.debug(f"Successfully reset domain '{session.domain}'")
            return IpmiResponseCode.SUCCESS
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to reset domain '{session.domain}': {e}")
            return IpmiResponseCode.NODE_BUSY

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password chassis power diag
    @domain_lock
    def pulse_diag(self, session: Any) -> IpmiResponseCode:
        """Inject NMI (diagnostic interrupt) into the virtual machine."""
        self.logger.debug("Attempting to inject NMI (diagnostic interrupt)")
        domain = self.get_domain(session)
        if not domain:
            self.logger.debug("Domain unavailable for NMI injection")
            return IpmiResponseCode.DESTINATION_UNAVAILABLE

        try:
            if not domain.isActive():
                self.logger.debug(
                    f"Cannot inject NMI into inactive domain '{session.domain}'"
                )
                return IpmiResponseCode.COMMAND_NOT_SUPPORTED_IN_PRESENT_STATE

            self.logger.debug(f"Domain '{session.domain}' is active, injecting NMI")
            domain.injectNMI()
            self.logger.debug(
                f"Successfully injected NMI into domain '{session.domain}'"
            )
            return IpmiResponseCode.SUCCESS
        except libvirt.libvirtError as e:
            self.logger.error(
                f"Failed to inject NMI into domain '{session.domain}': {e}"
            )
            return IpmiResponseCode.NODE_BUSY

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password chassis power soft
    @domain_lock
    def power_shutdown(self, session: Any) -> IpmiResponseCode:
        """Perform soft shutdown of the virtual machine."""
        self.logger.debug("Attempting soft shutdown of domain")
        domain = self.get_domain(session)
        if not domain:
            self.logger.debug("Domain unavailable for shutdown")
            return IpmiResponseCode.DESTINATION_UNAVAILABLE

        try:
            if not domain.isActive():
                self.logger.debug(f"Cannot shutdown inactive domain '{session.domain}'")
                return IpmiResponseCode.COMMAND_NOT_SUPPORTED_IN_PRESENT_STATE

            self.logger.debug(
                f"Domain '{session.domain}' is active, sending shutdown command"
            )
            domain.shutdown()
            self.logger.debug(
                f"Successfully initiated domain '{session.domain}' shutdown"
            )
            return IpmiResponseCode.SUCCESS
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to shutdown domain '{session.domain}': {e}")
            return IpmiResponseCode.NODE_BUSY

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password chassis power status
    @domain_lock
    def get_power_state(self, session: Any) -> int:
        """Get current power state of the virtual machine."""
        self.logger.debug("Getting domain power state")
        domain = self.get_domain(session)
        if not domain:
            self.logger.debug("Domain unavailable for power state check")
            raise ConnectionError("Unable to get domain")

        try:
            is_active = domain.isActive()
            state = power_states["on"] if is_active else power_states["off"]
            self.logger.debug(
                f"Domain '{session.domain}' power state: {'on' if is_active else 'off'}"
            )
            return state
        except libvirt.libvirtError as e:
            self.logger.error(
                f"Failed to get domain '{session.domain}' power state: {e}"
            )
            raise

    def get_chassis_status(self, session: Any) -> None:
        """Handle IPMI Get Chassis Status command."""
        self.logger.debug("Getting chassis status")
        try:
            power_state = self.get_power_state(session)
            self.logger.debug(f"Retrieved power state: {power_state}")

            match power_state:
                case state if state not in (0, 1):
                    self.logger.debug(f"Invalid power state value: {state}")
                    return self.send_ipmi_response(
                        session, IpmiResponseCode.UNSPECIFIED_ERROR, None
                    )
                case state:
                    self.logger.debug(
                        f"Sending chassis status response with power state: {state}"
                    )
                    self.send_ipmi_response(
                        session, IpmiResponseCode.SUCCESS, [state, 0, 0]
                    )
        except ConnectionError:
            self.logger.debug("Domain unavailable for chassis status")
            return self.send_ipmi_response(
                session, IpmiResponseCode.DESTINATION_UNAVAILABLE, None
            )
        except libvirt.libvirtError as e:
            self.logger.debug(f"Libvirt error while getting chassis status: {e}")
            return self.send_ipmi_response(session, IpmiResponseCode.NODE_BUSY, None)
        except (KeyError, IndexError, TypeError, AttributeError) as e:
            self.logger.debug(f"Invalid data field in chassis status request: {e}")
            return self.send_ipmi_response(
                session, IpmiResponseCode.INVALID_DATA_FIELD, None
            )
        except NotImplementedError:
            self.logger.debug("Command not supported in current state")
            return self.send_ipmi_response(
                session, IpmiResponseCode.COMMAND_NOT_SUPPORTED_IN_PRESENT_STATE, None
            )

    def control_chassis(self, session: Any, request: dict[str, Any]) -> None:
        """Handle IPMI Chassis Control commands."""
        try:
            command = request["data"][0]
            self.logger.debug(f"Processing chassis control command: {command}")

            match command:
                case 0:
                    rc = self.power_off(session)
                case 1:
                    rc = self.power_on(session)
                case 2:
                    rc = self.power_cycle(session)
                case 3:
                    rc = self.power_reset(session)
                case 4:
                    rc = self.pulse_diag(session)
                case 5:
                    rc = self.power_shutdown(session)
                case _:
                    self.logger.debug(
                        f"Received unknown chassis control command: {command}"
                    )
                    rc = IpmiResponseCode.UNSPECIFIED_ERROR

            self.logger.debug(
                f"Chassis control command completed with response code: {rc}"
            )
            self.send_ipmi_response(session, rc, None)
        except (
            KeyError,
            IndexError,
            TypeError,
            AttributeError,
            NotImplementedError,
        ) as e:
            self.logger.debug(f"Invalid data in chassis control request: {e}")
            self.send_ipmi_response(session, IpmiResponseCode.INVALID_DATA_FIELD, None)

    def get_boot_device_name(self, domain_xml: ET.Element) -> Optional[str]:
        """Extract boot device name from domain XML."""
        try:
            boot_element = domain_xml.find(".//os/boot")
            if boot_element is None:
                return None
            return boot_element.attrib.get("dev")
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse boot device: {e}")
            return None
        # pylint: disable=broad-exception-caught
        except Exception:
            return None

    def is_efi_boot(self, domain_xml: ET.Element) -> bool:
        """Check if domain is configured for EFI boot."""
        try:
            os_element = domain_xml.find(".//os")
            if os_element is None:
                return False

            if os_element.get("firmware") == "efi":
                return True

            loader = os_element.find("loader")
            if loader is None:
                return False

            secure_boot = loader.get("secure") == "yes"
            is_ovmf_pflash = (
                loader.get("type") == "pflash"
                and loader.text is not None
                and "OVMF" in loader.text
            )

            return secure_boot or is_ovmf_pflash

        # pylint: disable=broad-exception-caught
        except Exception:
            return False

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password chassis bootparam get 5
    @domain_lock
    def get_boot_options(self, session: Any, request: Dict[str, Any]) -> None:
        """Handle IPMI Get System Boot Options command."""
        self.logger.debug("Processing get boot options request")

        if request["data"][0] != BootOptionParameters.BOOT_FLAGS:
            self.logger.debug(
                f"Unsupported boot parameter requested: {request['data'][0]}"
            )
            self.send_ipmi_response(session, IpmiResponseCode.COMMAND_DISABLED, None)
            return

        try:
            domain = self.get_domain(session)
            if not domain:
                self.logger.debug("Domain unavailable for boot options")
                self.send_ipmi_response(
                    session, IpmiResponseCode.DESTINATION_UNAVAILABLE, None
                )
                return

            try:
                self.logger.debug(f"Getting domain '{session.domain}' XML description")
                domain_xml = ET.fromstring(
                    domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
                )

                name = self.get_boot_device_name(domain_xml)
                if not name:
                    self.logger.debug(
                        f"No boot device name found in domain '{session.domain}'"
                    )
                    raise NotImplementedError

                self.logger.debug(
                    f"Converting Libvirt boot device '{name}' for domain '{session.domain}' to IPMI format"
                )
                raw = BootDevice.from_libvirt(name)
                if not raw:
                    self.logger.debug(
                        f"Failed to convert boot device for domain '{session.domain}' to IPMI format"
                    )
                    raise NotImplementedError

                boot_flags = BootFlags.VALID | BootFlags.PERSISTENT

                self.logger.debug(f"Checking for EFI boot in domain '{session.domain}'")
                if self.is_efi_boot(domain_xml):
                    self.logger.debug(f"EFI boot detected in domain '{session.domain}'")
                    boot_flags |= BootFlags.EFI
                else:
                    self.logger.debug(
                        f"Legacy BIOS boot detected in domain '{session.domain}'"
                    )
                    boot_flags |= BootFlags.LEGACY_BIOS

                self.logger.debug(
                    f"Sending boot options response with flags: {boot_flags:08b}, device: {raw.ipmi_code}, domain '{session.domain}'"
                )
                self.send_ipmi_response(
                    session,
                    IpmiResponseCode.SUCCESS,
                    [
                        1,  # Version
                        BootOptionParameters.BOOT_FLAGS,
                        boot_flags,
                        raw.ipmi_code << 2,
                        0,  # Reserved
                        0,  # Reserved
                        0,  # Reserved
                    ],
                )
            except (libvirt.libvirtError, ET.ParseError) as e:
                self.logger.error(
                    f"Failed to get domain '{session.domain}' boot options: {e}"
                )
                self.send_ipmi_response(session, IpmiResponseCode.NODE_BUSY, None)
                return
        except NotImplementedError:
            self.logger.debug("Sending default boot options response")
            self.send_ipmi_response(
                session,
                IpmiResponseCode.SUCCESS,
                [
                    1,  # Version
                    BootOptionParameters.BOOT_FLAGS,
                    BootFlags.DEFAULT,
                    0,  # Default
                    0,  # Reserved
                    0,  # Reserved
                    0,  # Reserved
                ],
            )
        # pylint: disable=broad-exception-caught
        except Exception as e:
            self.logger.error(f"Failed to get domain boot options: {e}")
            self.send_ipmi_response(session, IpmiResponseCode.UNSPECIFIED_ERROR, None)

    def update_boot_device(self, tree: ET.Element, boot_device_name: str) -> None:
        """Update boot device in domain XML configuration."""
        if tree is None or not isinstance(boot_device_name, str):
            raise ValueError("Invalid arguments for update_boot_device")

        for device_element in tree.findall("devices/*"):
            for boot_element in device_element.findall("boot"):
                device_element.remove(boot_element)

        os_element = tree.find("os")
        if os_element is not None:
            for boot_element in os_element.findall("boot"):
                os_element.remove(boot_element)

            boot_element = ET.SubElement(os_element, "boot")
            boot_element.set("dev", boot_device_name)

    # ipmitool -I lanplus -H 127.0.0.1 -U vm -P password chassis bootdev pxe|disk|cdrom|floppy
    @domain_lock
    def set_boot_options(self, session: Any, request: Dict[str, Any]) -> None:
        """Handle IPMI Set System Boot Options command."""
        self.logger.debug("Processing set boot options request")

        if request["data"][0] in (
            BootOptionParameters.SET_IN_PROGRESS,
            BootOptionParameters.BOOT_FLAG_VALID_BIT_CLEARING,
            BootOptionParameters.BOOT_INFO_ACKNOWLEDGE,
        ):
            self.logger.debug(
                f"Ignoring unsupported boot parameter: {request['data'][0]}"
            )
            self.send_ipmi_response(session, IpmiResponseCode.SUCCESS, None)
            return

        if request["data"][0] != BootOptionParameters.BOOT_FLAGS:
            self.logger.debug(f"Invalid boot parameter requested: {request['data'][0]}")
            self.send_ipmi_response(session, IpmiResponseCode.INVALID_DATA_FIELD, None)
            return

        # Extract boot device from request data
        raw = (request["data"][2] >> 2) & 0b1111
        self.logger.debug(f"Extracted raw boot device code: {raw}")

        try:
            boot_device = BootDevice.from_ipmi(raw)
            if not boot_device:
                self.logger.debug(f"Invalid IPMI boot device code: {raw}")
                self.send_ipmi_response(
                    session, IpmiResponseCode.INVALID_DATA_FIELD, None
                )
                return

            self.logger.debug(
                f"Converted IPMI boot device to Libvirt name: {boot_device.libvirt_name}"
            )

            domain = self.get_domain(session)
            if not domain:
                self.logger.debug("Domain unavailable for setting boot device")
                self.send_ipmi_response(
                    session, IpmiResponseCode.DESTINATION_UNAVAILABLE, None
                )
                return

            self.logger.debug(f"Getting domain '{session.domain}' XML description")
            tree = ET.fromstring(
                domain.XMLDesc(
                    flags=libvirt.VIR_DOMAIN_XML_SECURE
                    | libvirt.VIR_DOMAIN_XML_INACTIVE
                )
            )

            self.logger.debug(
                f"Updating domain '{session.domain}' boot device in XML to: {boot_device.libvirt_name}"
            )
            self.update_boot_device(tree, boot_device.libvirt_name)

            try:
                if conn := self.get_connection():
                    self.logger.debug(
                        f"Applying new domain '{session.domain}' XML configuration"
                    )
                    xml_str = ET.tostring(tree, encoding="unicode", method="xml")

                    conn.defineXML(xml_str)
                    self.logger.debug(
                        f"Successfully updated domain '{session.domain}' boot device"
                    )
                    self.send_ipmi_response(session, IpmiResponseCode.SUCCESS, None)

                    return
            except libvirt.libvirtError as e:
                self.logger.error(
                    f"Failed to define new domain '{session.domain}' XML configuration: {e}"
                )
                self.send_ipmi_response(session, IpmiResponseCode.NODE_BUSY, None)
                return
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to set domain boot device: {e}")
            self.send_ipmi_response(session, IpmiResponseCode.NODE_BUSY, None)
        # pylint: disable=broad-exception-caught
        except Exception as e:
            self.logger.error(f"Failed to set domain boot device: {e}")
            self.send_ipmi_response(session, IpmiResponseCode.UNSPECIFIED_ERROR, None)

    # pylint: disable=too-many-return-statements
    def handle_raw_request(self, request: Dict[str, Any], session: Any) -> None:
        """Process raw IPMI requests."""
        try:
            if not hasattr(session, "domain") or not session.domain:
                raise AttributeError("Session domain is not defined")

            self.logger.info(self.format_ipmi_message("Request", session, data=request))

            match (request["netfn"], request["command"]):
                case (IpmiNetFn.APP, IpmiCommand.GET_DEVICE_ID):
                    return self.get_device_id(session)
                case (IpmiNetFn.APP, IpmiCommand.GET_SYSTEM_GUID):
                    return self.get_system_guid(session)
                case (IpmiNetFn.CHASSIS, IpmiCommand.GET_CHASSIS_STATUS):
                    return self.get_chassis_status(session)
                case (IpmiNetFn.CHASSIS, IpmiCommand.CHASSIS_CONTROL):
                    return self.control_chassis(session, request)
                case (IpmiNetFn.CHASSIS, IpmiCommand.SET_SYSTEM_BOOT_OPTIONS):
                    return self.set_boot_options(session, request)
                case (IpmiNetFn.CHASSIS, IpmiCommand.GET_SYSTEM_BOOT_OPTIONS):
                    return self.get_boot_options(session, request)
                case _:
                    return self.send_ipmi_response(
                        session, IpmiResponseCode.INVALID_COMMAND, None
                    )
        except (NotImplementedError, AttributeError) as e:
            if hasattr(session, "domain") and session.domain:
                self.logger.error(f"Session error for domain {session.domain}: {e}")
            else:
                self.logger.error(f"Session error: {e}")
            return self.send_ipmi_response(
                session, IpmiResponseCode.INVALID_COMMAND, None
            )
        # pylint: disable=broad-exception-caught
        except Exception as e:
            if hasattr(session, "domain") and session.domain:
                self.logger.error(
                    f"Unhandled exception in raw request handler for domain {session.domain}, sending unspecified error: {e!r}"
                )
            else:
                self.logger.error(
                    f"Unhandled exception in raw request handler, sending unspecified error: {e!r}"
                )
            return self.send_ipmi_response(
                session, IpmiResponseCode.UNSPECIFIED_ERROR, None
            )
            # pylint: disable=protected-access
            # session._send_ipmi_net_payload(code=IpmiResponseCode.UNSPECIFIED_ERROR)
            # return None

    def listen(self, timeout: int = DEFAULT_LISTEN_TIMEOUT) -> None:
        """Listen for incoming IPMI requests."""
        while True:
            ipmisession.Session.wait_for_rsp(timeout)


def main() -> int:
    """Main entry point for the LibvirtIPMI application."""

    def get_env_or_default(env_name: str, default: Any) -> Any:
        """Get environment variable with LIBVIRT_IPMI prefix or return default value."""
        return os.environ.get(f"LIBVIRT_IPMI_{env_name}", default)

    def generate_random_password(length: int = 16) -> str:
        """Generate a secure random password."""
        charset = string.ascii_letters + string.digits
        return "".join(secrets.choice(charset) for _ in range(length))

    parser = argparse.ArgumentParser(
        prog="LibvirtIPMI",
        description="Pretend to be a IPMI server for Libvirt Domains",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--address",
        default=get_env_or_default("ADDRESS", "::"),
        help="Address to bind the IPMI server to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(get_env_or_default("PORT", 623)),
        help="(UDP) port to listen on",
    )
    # Connection URIs (https://libvirt.org/uri.html), examples:
    #  - qemu:///system
    #  - qemu+ssh://root@IP/system?&keyfile=/root/.ssh/id_ecdsa&no_tty=1
    #  - qemu+libssh://root@IP/system?&keyfile=/root/.ssh/id_ecdsa&known_hosts_verify=ignore&sshauth=privkey
    parser.add_argument(
        "--connect",
        dest="hypervisor",
        default=get_env_or_default("CONNECT", "qemu:///system"),
        help="The Libvirt hypervisor to connect to",
    )
    parser.add_argument(
        "--password",
        default=get_env_or_default("PASSWORD", None),
        help="Password used for authentication (all Libvirt Domains)",
    )
    parser.add_argument(
        "--listen-timeout",
        type=int,
        default=int(get_env_or_default("TIMEOUT", DEFAULT_LISTEN_TIMEOUT)),
        help="Timeout in seconds for listening to IPMI connections",
    )
    parser.add_argument(
        "--log-level",
        default=get_env_or_default("LOG_LEVEL", "DEBUG"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level",
    )
    args = parser.parse_args()

    logger = setup_logger(args.log_level)

    logger.info(
        'Starting IPMI server on address "%s" and port "%s"', args.address, args.port
    )

    if not args.password:
        args.password = generate_random_password()
        logger.warning("Generated random password: %s", args.password)

    def libvirt_event_loop():
        """Run the Libvirt event loop."""
        while True:
            try:
                if libvirt.virEventRunDefaultImpl() < 0:
                    logger.error("Error running Libvirt event loop")
                time.sleep(0.01)
            # pylint: disable=broad-exception-caught
            except Exception as e:
                logger.error("Error in Libvirt event loop: %s", e)
                break

    def libvirt_error_handler(_ctx: Any, _error: list) -> None:
        pass

    libvirt.registerErrorHandler(libvirt_error_handler, None)

    libvirt.virEventRegisterDefaultImpl()
    libvirt_event_thread = threading.Thread(target=libvirt_event_loop, daemon=True)
    libvirt_event_thread.start()

    bmc = LibvirtIPMI(
        address=args.address,
        port=args.port,
        hypervisor=args.hypervisor,
        password=args.password,
        logger=logger,
    )

    for module_name, module in sys.modules.items():
        if module_name.startswith("pyghmi"):
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and obj.__name__ == "ServerSession":
                    setattr(module, name, EnhancedServerSession)

    try:
        bmc.listen(args.listen_timeout)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        if hasattr(bmc, "free_connection"):
            bmc.free_connection()

    return 0


if __name__ == "__main__":
    sys.exit(main())
