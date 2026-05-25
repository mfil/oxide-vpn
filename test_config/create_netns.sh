#!/bin/sh

# Create a network namespace to run an OpenVPN server in.
# It is difficult to send packets between two tun interfaces in the same namespace.
#
# This script creates:
# - a namespace called ns_server
# - a veth interface in the main namespace called veth_client with IP address 192.168.24.1
# - a peer veth interface called veth_server in ns_server with IP address 192.168.24.2

VETH_CLIENT_IP="192.168.24.1/24"
VETH_SERVER_IP="192.168.24.2/24"

set -e
sudo ip netns add ns_server
sudo ip link add dev veth_client type veth peer veth_server netns ns_server
sudo ip address add $VETH_CLIENT_IP dev veth_client
sudo ip link set dev veth_client up
sudo ip -netns ns_server address add $VETH_SERVER_IP dev veth_server
sudo ip -netns ns_server link set dev veth_server up
