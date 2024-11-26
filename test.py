#!/usr/bin/env python3

# Copyright 2024 s3rj1k
# SPDX-License-Identifier: Apache-2.0

"""Tool for validating IPMI server."""

import argparse
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


class IPMIValidator:
    """Validates IPMI server responses using ipmitool."""

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self.base_cmd: list[str] = [
            "ipmitool",
            "-I",
            "lanplus",
            "-H",
            host,
            "-p",
            str(port),
            "-U",
            username,
            "-P",
            password,
        ]

    def execute_command(self, command_args: list[str]) -> str:
        """Execute an IPMI command and return its output."""
        cmd = self.base_cmd + command_args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Command failed with exit code {e.returncode}: {e.stderr}"
            ) from e

    def validate_mc_info(self) -> None:
        """Validate 'mc info' command output."""
        output = self.execute_command(["mc", "info"])

        required_values = {
            "Device Available": "yes",
            "IPMI Version": "2.0",
            "Provides Device SDRs": "no",
        }

        for key, expected_value in required_values.items():
            pattern = rf"{key}\s*:\s*{expected_value}"
            if not re.search(pattern, output):
                raise ValueError(
                    f"Missing or incorrect value for {key}. Expected: {expected_value}"
                )

        chassis_pattern = r"Additional Device Support\s*:.*?Chassis Device"
        if not re.search(chassis_pattern, output, re.DOTALL):
            raise ValueError(
                "Missing 'Chassis Device' in Additional Device Support section"
            )

        logger.info("BMC info validation successful")

    def validate_mc_guid(self) -> None:
        """Validate 'mc guid' command output."""
        output = self.execute_command(["mc", "guid"])

        uuid_pattern = r"([0-9A-F]{32})"

        match = re.search(uuid_pattern, output.upper())
        if not match:
            raise ValueError("No valid UUID found in output")

        logger.info("BMC guid validation successful")

    def validate_power_off(self) -> None:
        """Validate 'power off' command output."""
        output = self.execute_command(["power", "off"])

        expected_output = "Chassis Power Control: Down/Off"

        if output.strip() != expected_output:
            raise ValueError(
                f"Power off command output doesn't match. Expected: '{expected_output}', Got: '{output.strip()}'"
            )

        logger.info("Power off command validation successful")

    def validate_power_on(self) -> None:
        """Validate 'power on' command output."""
        output = self.execute_command(["power", "on"])

        expected_output = "Chassis Power Control: Up/On"

        if output.strip() != expected_output:
            raise ValueError(
                f"Power on command output doesn't match. Expected: '{expected_output}', Got: '{output.strip()}'"
            )

        logger.info("Power on command validation successful")

    def validate_power_cycle(self) -> None:
        """Validate 'power cycle' command output."""
        output = self.execute_command(["power", "cycle"])

        expected_output = "Chassis Power Control: Cycle"

        if output.strip() != expected_output:
            raise ValueError(
                f"Power cycle command output doesn't match. Expected: '{expected_output}', Got: '{output.strip()}'"
            )

        logger.info("Power cycle command validation successful")

    def validate_power_reset(self) -> None:
        """Validate 'power reset' command output."""
        output = self.execute_command(["power", "reset"])

        expected_output = "Chassis Power Control: Reset"

        if output.strip() != expected_output:
            raise ValueError(
                f"Power reset command output doesn't match. Expected: '{expected_output}', Got: '{output.strip()}'"
            )

        logger.info("Power reset command validation successful")

    def validate_power_diag(self) -> None:
        """Validate 'power diag' command output."""
        output = self.execute_command(["power", "diag"])

        expected_output = "Chassis Power Control: Diag"

        if output.strip() != expected_output:
            raise ValueError(
                f"Power diag command output doesn't match. Expected: '{expected_output}', Got: '{output.strip()}'"
            )

        logger.info("Power diag command validation successful")

    def validate_power_soft(self) -> None:
        """Validate 'power soft' command output."""
        output = self.execute_command(["power", "soft"])

        expected_output = "Chassis Power Control: Soft"

        if output.strip() != expected_output:
            raise ValueError(
                f"Power soft command output doesn't match. Expected: '{expected_output}', Got: '{output.strip()}'"
            )

        logger.info("Power soft command validation successful")

    def validate_power_status(self, expected: str) -> None:
        """Validate 'power status' command output."""
        output: str = self.execute_command(["power", "status"])
        output = output.strip()

        pattern: str = r"^Chassis Power is (on|off)$"
        match: re.Match[str] | None = re.match(pattern, output)

        if not match:
            raise ValueError(f"Power status output format invalid. Got: '{output}'")

        if match.group(1) != expected:
            raise ValueError(
                f"Power status doesn't match expected state. Expected: '{expected}', Got: '{match.group(1)}'"
            )

        logger.info("Power status validation successful - power is %s", match.group(1))

    def validate_chassis_bootparam_get_5(self, device: str) -> None:
        """Validate 'chassis bootparam get 5' command output."""
        device_data_map = {
            "pxe": "c004000000",
            "disk": "c008000000",
            "cdrom": "c014000000",
            "floppy": "c03c000000",
        }

        if device not in device_data_map:
            raise ValueError(
                f"Invalid device type. Must be one of: {', '.join(device_data_map.keys())}"
            )

        output = self.execute_command(["chassis", "bootparam", "get", "5"])

        required_patterns = [rf"Boot parameter data: {device_data_map[device]}"]

        for pattern in required_patterns:
            if not re.search(pattern, output):
                raise ValueError(f"Missing or incorrect pattern: {pattern}")

        logger.info("Chassis bootparam get 5 validation successful")

    def validate_chassis_bootdev(self, device: str) -> None:
        """Validate 'chassis bootdev' command output for different devices."""

        if device not in ["pxe", "disk", "cdrom", "floppy"]:
            raise ValueError(f"Invalid boot device: {device}")

        output = self.execute_command(["chassis", "bootdev", device])
        expected_output = f"Set Boot Device to {device}"

        if output.strip() != expected_output:
            raise ValueError(
                f"Boot device command output doesn't match. Expected: '{expected_output}', Got: '{output.strip()}'"
            )

        logger.info("Chassis bootdev %s validation successful", device)


class IPMILoadTester:
    """Validates IPMI server responses stability."""

    def __init__(self, validator: IPMIValidator) -> None:
        self.validator = validator
        self.should_stop = False
        self.error_count = 0
        self.success_count = 0
        self._lock = threading.Lock()
        self.attempt_count = 0

    def increment_counters(self, success: bool) -> None:
        """Thread-safe counter incrementing."""
        with self._lock:
            self.attempt_count += 1
            if success:
                self.success_count += 1
            else:
                self.error_count += 1

    def run_test_function(self, func: Callable) -> None:
        """Continuously runs a test function until the stop flag is set."""
        while not self.should_stop:
            try:
                func()
                self.increment_counters(True)
            # pylint: disable=broad-exception-caught
            except Exception:
                self.increment_counters(False)
            time.sleep(0.01)

    def run_load_test(self, duration_minutes: int = 5) -> None:
        """Runs the load test for the specified duration."""
        logger.info("Starting load test for %d minutes...", duration_minutes)

        threads = [
            threading.Thread(
                target=self.run_test_function,
                args=(self.validator.validate_mc_info,),
                daemon=True,
            ),
            threading.Thread(
                target=self.run_test_function,
                args=(self.validator.validate_mc_guid,),
                daemon=True,
            ),
            threading.Thread(
                target=self.run_test_function,
                args=(lambda: self.validator.validate_power_status("on"),),
                daemon=True,
            ),
        ]

        for thread in threads:
            thread.start()

        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        try:
            while datetime.now() < end_time:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.warning("Load test interrupted by user...")
        finally:
            self.should_stop = True

            for thread in threads:
                thread.join()

        logger.info("Load Test Results:")
        logger.info("Total successful operations: %d", self.success_count)
        logger.info("Total failed operations: %d", self.error_count)
        logger.info(
            "Success rate: %.2f%%",
            (self.success_count / (self.success_count + self.error_count) * 100),
        )


def main():
    """Executes a series of IPMI command validations using configurable credentials."""

    def get_env_or_default(env_name: str, default: Any) -> Any:
        """Get environment variable with LIBVIRT_IPMI_ prefix or return default value."""
        return os.environ.get(f"LIBVIRT_IPMI_{env_name}", default)

    parser = argparse.ArgumentParser(description="IPMI Validation Tool")
    parser.add_argument(
        "--host",
        default=get_env_or_default("HOST", "localhost"),
        help="IPMI host",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(get_env_or_default("PORT", "6230")),
        help="IPMI port",
    )
    parser.add_argument(
        "--username",
        default=get_env_or_default("USERNAME", "test"),
        help="IPMI username",
    )
    parser.add_argument(
        "--password",
        default=get_env_or_default("PASSWORD", "password"),
        help="IPMI password",
    )

    args = parser.parse_args()

    validator = IPMIValidator(
        host=args.host, port=args.port, username=args.username, password=args.password
    )

    try:
        logger.info("Starting IPMI server verification test")

        validator.validate_mc_info()
        validator.validate_mc_guid()

        validator.validate_power_off()
        validator.validate_power_status("off")

        validator.validate_power_on()
        validator.validate_power_status("on")

        validator.validate_power_cycle()
        validator.validate_power_status("on")

        validator.validate_power_reset()
        validator.validate_power_status("on")

        validator.validate_power_diag()
        validator.validate_power_status("on")

        validator.validate_power_soft()
        validator.validate_power_status("off")

        validator.validate_power_cycle()
        validator.validate_power_status("on")

        for device in ["pxe", "disk", "cdrom", "floppy"]:
            validator.validate_chassis_bootdev(device)
            validator.validate_chassis_bootparam_get_5(device)

        validator.validate_power_off()
        validator.validate_power_status("off")

        for device in ["pxe", "disk", "cdrom", "floppy"]:
            validator.validate_chassis_bootdev(device)
            validator.validate_chassis_bootparam_get_5(device)

        validator.validate_power_on()
        validator.validate_power_status("on")

        load_tester = IPMILoadTester(validator)
        load_tester.run_load_test(duration_minutes=1)

    except (RuntimeError, ValueError) as e:
        logger.error("Validation failed: %s", str(e))


if __name__ == "__main__":
    main()
