#!/bin/bash

# Check if the script has the correct arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 <port> <interface> <source_ip> <storage_dst> <protocol_pkt_seq> <ssh_key_path> <v6_target_file>"
    exit 1
fi

port="$1"
interface="$2"
source_ip="$3"
storage_dst="$4"
protocol_pkt_seq="$5"
SSH_KEY="$6"
v6_target_file="$7"

# Start ssh agent for transferring data to storage machine
if [ -z "$SSH_AGENT_PID" ]; then
    eval "$(ssh-agent -s)"
fi

# Add ssh key to ssh agent
ssh-add "$SSH_KEY"

# Run ZMap Censored Domain Scans
sudo SSH_AUTH_SOCK=$SSH_AUTH_SOCK python3 global_censored_zmap_scan.py --port $port --interface $interface --source_ip $source_ip --storage_dst "${storage_dst}/v6/${protocol_pkt_seq}" --protocol_pkt_seq $protocol_pkt_seq --v6_target_file $v6_target_file