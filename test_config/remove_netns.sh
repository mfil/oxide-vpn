#!/bin/sh

# Remove the network namespace an veth interfaces created by create_netns.sh

sudo ip link delete veth_client
sudo ip netns delete ns_server
