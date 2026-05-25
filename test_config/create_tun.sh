#!/bin/sh

# Create a tun interface that can be used by the current user and pre-configure it with the
# IP address that OpenVPN wants to assing to it. This makes it possible to test oxide-vpn without
# running it as root.

TUN_NAME="tun0"
TUN_IP="192.168.23.2/24"

set -e
USER=`whoami`
sudo ip tuntap add $TUN_NAME mode tun user $USER
sudo ip address add $TUN_IP dev $TUN_NAME
sudo ip link set dev $TUN_NAME up
