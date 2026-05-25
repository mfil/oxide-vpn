#!/bin/sh

# Run an OpenVPN server in the network namespace from create_netns.sh
sudo ip netns exec ns_server openvpn --config server/conf
