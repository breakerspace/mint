import sys
import random
import socket

def generate_ips(filename):
    with open(filename, "w") as file:
        for i in range(0, 2**32, 256):  # Iterating over /24 subnets
            last_octet = random.randint(1, 254)  # Avoiding 0 and 255
            ip = socket.inet_ntoa(i.to_bytes(4, byteorder='big'))
            # Add the last octet to the IP
            ip = f"{ip.rsplit('.', 1)[0]}.{last_octet}"
            file.write(f"{ip}\n")

if __name__ == "__main__":
    protocol_pkt_seq = sys.argv[1]
    generate_ips(f"{protocol_pkt_seq}/ip_addresses.txt")
