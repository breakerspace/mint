#!/bin/bash

# Check if the script has the correct arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 <port> <interface> <source_ip> <storage_dst> <protocol_pkt_seq> <ssh_key_path> <ipv6_slash_48_file_path> <path_to_regular_zmap>"
    exit 1
fi

port="$1"
interface="$2"
source_ip="$3"
storage_dst="$4"
protocol_pkt_seq="$5"
SSH_KEY="$6"
ipv6_slash_48_file_path="$7"
path_to_regular_zmap="$8"

# Start ssh agent for transferring data to storage machine
if [ -z "$SSH_AGENT_PID" ]; then
    eval "$(ssh-agent -s)"
fi

# Add ssh key to ssh agent
ssh-add "$SSH_KEY"

# --------------------- ONLY RUN ONCE ------------------------------------
# Create the target IPv6 addresses using the slash 48 file
python3 create_v6_targets.py --ipv6_slash_48_file_path "${ipv6_slash_48_file_path}" --output_file v6_target_ips.txt

# Run TCP SYN scan on the target IPv6 addresses to find all the aliased networks and live IPs
sudo "${path_to_regular_zmap}/src/zmap" -M ipv6_tcp_synscan --ipv6-source-ip "${source_ip}" --ipv6-target-file v6_target_ips.txt --output-filter="" -p "$port" -i "$interface" -B 10M -o live_ips.txt 

# Exclude all the /48s that are in the live_ips.txt file from the v6_target_ips.txt file
sudo tail -n +2 live_ips.txt | awk -F':' '{print "^"$1":"$2":"$3}' | grep -Ev -f - v6_target_ips.txt > v6_target_ips_final.txt

# Shuffle the final IPv6 target IPs
shuf v6_target_ips_final.txt > shuffled_v6_target_ips_final.txt

# ---------------------------------------------------------------------------

# Run ZMap Censored Domain Scans
sudo SSH_AUTH_SOCK=$SSH_AUTH_SOCK python3 global_censored_zmap_scan.py --port $port --interface $interface --source_ip $source_ip --storage_dst "${storage_dst}/v6/${protocol_pkt_seq}" --protocol_pkt_seq $protocol_pkt_seq --v6_target_file shuffled_v6_target_ips_final.txt