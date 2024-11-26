# Copyright 2024 s3rj1k
# SPDX-License-Identifier: Apache-2.0

# docker build --network=host -f test.Dockerfile -t libvirtipmi.test .
# docker run -it --rm --network=host --name=libvirtipmi.test libvirtipmi.test
# docker run -it --rm --network=host -e SKIP_TESTS=1 --name=libvirtipmi.test libvirtipmi.test
# docker exec -it libvirtipmi.test bash

# syntax=docker/dockerfile:1.4
FROM alpine:3.21

RUN apk add --no-cache \
    gcc \
    ipmitool \
    libvirt \
    libvirt-client \
    libvirt-daemon \
    libvirt-dev \
    libvirt-libs \
    musl-dev \
    pkgconf \
    py3-pip \
    python3 \
    python3-dev \
    socat

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /opt/libvirtipmi
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY <<EOF /etc/libvirt/libvirtd.conf
listen_tls = 0
listen_tcp = 1
tcp_port = "16509"
listen_addr = "localhost"
unix_sock_group = "libvirt"
unix_sock_rw_perms = "0777"
auth_tcp = "none"
auth_unix_ro = "none"
auth_unix_rw = "none"
unix_sock_dir = "/var/run/libvirt"
EOF

COPY . .

ENV LIBVIRT_DEFAULT_URI="test+tcp://localhost/default"
ENV LIBVIRT_IPMI_ADDRESS="localhost"
ENV LIBVIRT_IPMI_PORT=6230
ENV LIBVIRT_IPMI_PASSWORD="password"
ENV LIBVIRT_IPMI_TIMEOUT=60
ENV LIBVIRT_IPMI_CONNECT="test+tcp://localhost/default"

COPY <<EOF /entrypoint.sh
#!/usr/bin/env sh
set -e

# Cleanup background processes.
cleanup() {
    echo "Cleaning up..."
    kill \$(jobs -p) 2>/dev/null || true
    exit 0
}

# Set up trap for cleanup.
trap cleanup INT TERM

# Start libvirtd.
echo "Starting libvirtd..."
/usr/sbin/libvirtd -l -f /etc/libvirt/libvirtd.conf &
libvirtd_pid=\$!

# Wait for libvirtd to be ready.
echo "Waiting for libvirtd..."
for i in \$(seq 1 30); do
    if virsh connect test+tcp://$LIBVIRT_IPMI_ADDRESS/default >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Adjust log level if skipping tests.
if [ "\${SKIP_TESTS:-0}" = "1" ]; then
    export LIBVIRT_IPMI_LOG_LEVEL="DEBUG"
    echo "Setting log level to DEBUG mode"
else
    export LIBVIRT_IPMI_LOG_LEVEL="ERROR"
fi

# Start LibvirtIPMI.
echo "Starting LibvirtIPMI..."
/opt/venv/bin/python3 /opt/libvirtipmi/libvirtipmi.py &
bmc_pid=\$!

# Wait for LibvirtIPMI to be ready.
echo "Waiting for LibvirtIPMI..."
for i in \$(seq 1 30); do
    if ipmitool -I lanplus -H $LIBVIRT_IPMI_ADDRESS -p $LIBVIRT_IPMI_PORT -U test -P $LIBVIRT_IPMI_PASSWORD power status >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Run tests only if SKIP_TESTS is not set to 1.
if [ "\${SKIP_TESTS:-0}" != "1" ]; then
    echo "Running tests..."
    cd /opt/libvirtipmi
    /opt/venv/bin/python3 test.py
    test_exit=\$?
    cleanup
    exit \$test_exit
fi

# If SKIP_TESTS=1, keep services running.
echo "Services started in DEBUG mode. Press Ctrl+C to exit."
wait
EOF

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
