# Use Ubuntu 24.04 as the base image
FROM ubuntu:24.04

# Install required packages (snmpd for agent, snmp for manager tools, and vim)
RUN apt-get update && \
    apt-get install -y \
    snmpd \
    snmp \
    netcat-openbsd \
    wireshark \
    tcpdump \
    iproute2 \
    inetutils-ping \
    net-tools \
    vim \
    libsnmp-dev \
    tshark \
    build-essential \
    python3 \
    python3-pip \
    python3-dev \
    && \
    # Clean up apt cache to reduce image size
    rm -rf /var/lib/apt/lists/*

# Create the snmp user and group before setting directory ownership
RUN groupadd -r snmp && useradd -r -g snmp snmp

# SNMP configuration for agent (configure snmpd with SNMPv3 user)
RUN net-snmp-create-v3-user -ro -A AuthPassword -X PrivPassword -a SHA -x AES128 User

# Create directories for SNMP and change ownership to snmp user
RUN mkdir -p /var/lib/snmp/cert_indexes && \
    chown snmp:snmp /var/lib/snmp /var/lib/snmp/cert_indexes

# Copy your local snmpd.conf to the container
COPY snmpd.conf /etc/snmp/snmpd.conf

# Copy the custom MIB file into the container
COPY TEST-MIB.txt /usr/share/snmp/mibs/TEST-MIB.txt

# Expose SNMP port
EXPOSE 161/udp

# Entry point will start both snmpd daemon and allow interactive exec
CMD /bin/bash
