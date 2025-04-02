# LibvirtIPMI

LibvirtIPMI is a Python-based IPMI Baseboard Management Controller (BMC) implementation for managing Libvirt domains.

This project was influenced by the [virtualbmc](https://opendev.org/openstack/virtualbmc) project, taking a more stateless approach to configuration by mapping domain names directly to IPMI usernames and using a single password for all domains.

**WARNING**: This software is intended for CI and development use only. Please do not run it in a production environment for any reason.

## Features

Supported `ipmitool` commands:
```bash
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis bootdev pxe|disk|cdrom|floppy
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis bootparam get 5
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis power diag
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis power off
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis power on
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis power reset
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis power soft
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis power status
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> chassis status
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> mc guid
ipmitool -I lanplus -H <host> -U <domain_name> -P <pass> mc info
```

Additional features:
- IPMI v2.0 protocol support (leverages `pyghmi`)
- EFI/BIOS boot mode detection (according to Libvirt Domain XML)
- Multi-domain support with concurrent access control (domain name is used as IPMI username)

## Requirements

- Any modern Linux distribution
- Python 3.10+
- libvirt-python
- pyghmi
- A running libvirt daemon

## Installation

There are three ways to install LibvirtIPMI:

1. From the repository:
```bash
# Clone the repository
git clone https://github.com/s3rj1k/libvirt-ipmi.git
cd libvirt-ipmi

# Install using pipx
pipx install .
```

2. Manual installation:
```bash
# Create a virtual environment
python3.12 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Copy libvirtipmi.py to your preferred location
# Install runtime dependencies
pip install -r requirements.txt

# Run the server (while virtual environment is activated)
python libvirtipmi.py [options]

# When you're done, you can deactivate the virtual environment
deactivate
```

## Usage

### Command Line Interface

The basic syntax for running LibvirtIPMI:

```bash
libvirt-ipmi [options]
```

Available options:
- `--address`: Address to bind the IPMI server to (default: `::`)
- `--port`: UDP port to listen on (default: `623`)
- `--connect`: Libvirt hypervisor connection URI (default: `qemu:///system`)
- `--password`: Authentication password for all domains
- `--listen-timeout`: Connection timeout in seconds (default: `30`)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

### Environment Variables

All command-line options can be configured using environment variables with the `LIBVIRT_IPMI_` prefix:

- `LIBVIRT_IPMI_ADDRESS`
- `LIBVIRT_IPMI_PORT`
- `LIBVIRT_IPMI_CONNECT`
- `LIBVIRT_IPMI_PASSWORD`
- `LIBVIRT_IPMI_TIMEOUT`
- `LIBVIRT_IPMI_LOG_LEVEL`

### Libvirt Connection URIs

LibvirtIPMI supports various connection URIs for different hypervisor configurations. For detailed information about Libvirt URIs, see the [Libvirt URI documentation](https://libvirt.org/uri.html).

```bash
# Local system connection
qemu:///system

# Remote SSH connection
qemu+ssh://root@hostname/system?keyfile=/root/.ssh/id_ecdsa&no_tty=1

# Remote libssh connection
qemu+libssh://root@hostname/system?keyfile=/root/.ssh/id_ecdsa&known_hosts_verify=ignore&sshauth=privkey
```

## Testing

Testing is performed using a Docker container:

```bash
# Build the test container
docker build --network=host -f test.Dockerfile -t libvirtipmi.test .

# Run the tests
docker run -it --rm --network=host --name=libvirtipmi.test libvirtipmi.test
```

## Sponsorship

This work was sponsored by, but is not an official product of, [Mirantis Inc.](https://www.mirantis.com/)

## Liability

All warranty disclaimers and liability limitations for this project are governed by the Apache License 2.0 terms.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Limitations

- `IPMI Username` / `Libvirt Domain name`: Must not exceed 16 bytes
- `IPMI Password`: Must not exceed 20 bytes
- Cipher suite `3` support only
   - authentication – RAKP-HMAC-SHA1
   - integrity – HMAC-SHA1-96
   - confidentiality – AES-CBC-128

## Authors

- s3rj1k (evasive.gyron@gmail.com)
