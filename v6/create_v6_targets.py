import os
import random
import ipaddress
import argparse
import tqdm
import bz2

def get_random_ipv6_addr(slash_64):
    random_last_64_bits = random.getrandbits(64)
    ipv6_addr = int(slash_64.network_address) + random_last_64_bits
    return str(ipaddress.IPv6Address(ipv6_addr))

def get_random_slash_64(slash_48):
    network_int = int(slash_48.network_address)
    random_last_16_bits = random.getrandbits(16)
    slash_64 = network_int + (random_last_16_bits << 64)
    return ipaddress.IPv6Network((slash_64, 64))

def create_v6_targets(ipv6_slash_48_file_path, output_file):
    with open(output_file, "w") as v6_output_file:
        with bz2.open(ipv6_slash_48_file_path, "rt") as slash_48_file:
            lines = slash_48_file.readlines()
            for l in tqdm.tqdm(lines):
                l = l.strip()
                if '/' not in l:
                    l += "::/48"
                slash_48 = ipaddress.IPv6Network(l)
                
                for _ in range(3):
                    slash_64 = get_random_slash_64(slash_48)
                    ipv6_addr = get_random_ipv6_addr(slash_64)
                    v6_output_file.write(ipv6_addr + "\n")

if __name__ == "__main__":
    ''' This script is used to create IPv6 targets from the /48 allocated prefixes from the IPv6 Observatory (ipv6observatory.org)'''
    # Initialize argparse
    parser = argparse.ArgumentParser()

    # Add command-line arguments
    parser.add_argument('--ipv6_slash_48_file_path', type=str, help='The slash 48 file')
    parser.add_argument('--output_file', type=str, help='The file to store the output to')

    # Parse the command-line arguments
    args = parser.parse_args()

    create_v6_targets(args.ipv6_slash_48_file_path, args.output_file)