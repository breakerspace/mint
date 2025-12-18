import os
import sys
import subprocess
import time
import random
import datetime
import argparse
import ipaddress
import json

from subprocess import check_output, CalledProcessError

scan_metadata_dict = {}
scan_metadata_dict["source_ports"] = {}

def run_rsync(source, destination, log_file):
    cmd = ["rsync", "-avz", "--progress", source, destination]
    file_name = os.path.basename(source)
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        log_file.write(f"Rsync output for {file_name}: {result.stdout}\n")
    except subprocess.CalledProcessError as e:
        log_file.write(f"Rsync for {file_name} failed with error: {e.stdout}\n")
        log_file.write(f"Rsync stdout:\n{e.stdout}\n")
        log_file.write(f"Rsync stderr:\n{e.stderr}\n")
        
def reliable_rsync(source, destination, log_file, retries=3, delay=5):
    file_name = os.path.basename(source)
    
    for attempt in range(0, 3):
        try:
            run_rsync(source, destination, log_file)
            log_file.write(f"Rsync for {file_name} completed successfully.\n")
            return True
        except Exception as e:
            log_file.write(f"Rsync for {file_name} failed. Attempt {attempt}: {e}\n")
            if attempt < retries:
                log_file.write(f"Retrying rsync for {file_name} in {delay} seconds\n")
                time.sleep(delay)
    log_file.write(f"Rsync for {file_name} failed after multiple attempts.\n")
    # raise RuntimeError(f"Rsync for {file_name} failed after multiple attempts.\n")
    return False

def get_ip_per_slash_24(protocol_pkt_seq):
    """
    Returns a set of IP addresses 
    """
    os.system(f"python3 enumerate_ips.py {protocol_pkt_seq}")
    
    ip_addresses = []
    
    with open(f"{protocol_pkt_seq}/ip_addresses.txt") as file:
        ips = file.readlines()
        for ip in ips:
            ip_addresses.append(ip.strip())
            
    return ip_addresses
            
def find_live_ips(protocol_pkt_seq, ip_addresses, port, interface):
    """
    Runs ZMap to discover whether any of the IP addresses in the argument list are live. If so, return a set of 
    all of the live IP addresses.
    """
    
    # Run zmap to find all live ips
    os.system(f"zmap -I {protocol_pkt_seq}/ip_addresses.txt -p {port} --probe-module=tcp_synscan --output-file={protocol_pkt_seq}/live_ips.txt --output-module=csv -B 10M -i {interface} -c 60")
    
    live_ips = set()
    
    # Parse out the live IP addresses from the zmap results
    with open(f"{protocol_pkt_seq}/live_ips.txt", "r") as f:
        lines = f.readlines()[1:] #skipping the saddr header line
        for l in lines:
            live_ips.add(l.strip())

    return live_ips

def get_non_responsive_ips(port, interface, protocol_pkt_seq, log_file):
    """
    Gets non-responsive IP addresses for each country in the ooni list. Chooses 1 IP per /24 prefix.
    """
        
    # Get one random IP address from each /24 that is globally routable
    log_file.write("Getting one random IP address from each /24\n")
    ip_addresses = get_ip_per_slash_24(protocol_pkt_seq)
    
    # Find out whether any of the IP addresses we obtained are live
    log_file.write("Using ZMap to determine whether any of the random IP addresses are live\n")
    live_ips_set = find_live_ips(protocol_pkt_seq, ip_addresses, port, interface)
        
    # Remove all live IP addresses from list
    log_file.write("Removing all live IP addresses from list\n")
    ip_addresses = list(set(ip_addresses).difference(live_ips_set))
    
    # Write nonresponsive IP addresses to file
    log_file.write("Writing nonresponsive IP addresses to file\n")

    with open(f"{protocol_pkt_seq}/nonresponsive_ips.txt", "w") as ip_address_file_zmap:
        ip_address_file_zmap.writelines("\n".join(list(ip_addresses)))

def global_censored_zmap_scan(port, interface, source_ip, storage_dst, protocol_pkt_seq):
    # Create directory to store scan data
    if not os.path.exists(f"{protocol_pkt_seq}/"):
        os.mkdir(f"{protocol_pkt_seq}/")
        
    # Create log file directory
    if not os.path.exists(f"logs/"):
        os.mkdir(f"logs/")
    
    # Create timestamped log file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file_path = f"logs/{protocol_pkt_seq}_{timestamp}.log"
    log_file = open(log_file_path, "a", buffering=1)
    
    scan_metadata_dict["start_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Gets nonresponsive IPs
    log_file.write("Getting nonresponsive IP addresses\n")
    get_non_responsive_ips(port, interface, protocol_pkt_seq, log_file)
    
    # Transfer all IP address files to storage machine
    ip_address_files = ["ip_addresses.txt", "live_ips.txt", "nonresponsive_ips.txt"]
    for file_name in ip_address_files:
        full_file_path = os.path.abspath(f"{protocol_pkt_seq}/{file_name}")
        try:
            reliable_rsync(full_file_path, storage_dst, log_file)
        except Exception as e:
            log_file.write(f"Rsync failed with error {e}\n for file {file_name}. Not removing file.")
    
    # Get the OONI list of domains to test
    hosts = []
    
    with open(f"../resources/top5_ooni_confirmed_domains.txt") as f:
        lines = f.readlines()
        for l in lines:
            hosts.append(l.strip())
            
    os.chdir("zmap_v4_modules/")
    os.system(f"git checkout {protocol_pkt_seq}")
    
    # Determine source port range for each host
    start_port = 1024
    end_port = 65535
    sport_range = ((end_port - start_port) + 1) // len(hosts)
    
    curr_sport = 1024
        
    # Iterate through the list of domains
    for host in hosts:
        sport_range_end = curr_sport + sport_range - 1
        scan_metadata_dict["source_ports"][host] = (curr_sport, sport_range_end)
                
        # Do a make clean
        os.system("make clean")
            
        # Get zmap allowlist file path
        allowlist_file_path = f"../{protocol_pkt_seq}/nonresponsive_ips.txt"
        
        # Ensure no other tcpdumps are running
        os.system("sudo killall tcpdump")
    
        # Run tcpdump in the background
        try:
            check_output('tmux new -s tcpdump_scan -d ' + 
                '''"tcpdump -i {} -w ../{}/{}.pcap 'tcp and (dst {} and port {})'"'''.format(interface, protocol_pkt_seq, host, source_ip, port), shell=True)
        except Exception as e:
            print(e)
        time.sleep(5)  # wait for tcpdump completely ON

        print("*" * 100)
        print("INITIATING SCAN FOR %s" % host)
        cmd = """
        sed "s/#define HOST .*/#define HOST \\\"%s\\\"/g" src/probe_modules/module_forbidden_scan.c > src/probe_modules/.backup
        """ % host
        print(cmd)
        os.system(cmd)
        time.sleep(1)
        os.system("mv src/probe_modules/.backup src/probe_modules/module_forbidden_scan.c")
        time.sleep(1)
        os.system(f"cmake . && make -j4 && sudo src/zmap -M forbidden_scan -p {port} -I {allowlist_file_path} -f \"saddr,len,payloadlen,flags,validation_type,sport,dport,seqnum,acknum,window,ipid,ttl\" -o ../{protocol_pkt_seq}/{host}.csv -O csv -B 10M -i {interface} -c 60 -s {curr_sport}-{sport_range_end}")
        
        # Kill tcpdump session
        check_output('tmux send-keys -t tcpdump_scan "C-c"', shell=True)
        time.sleep(2)
        try:
            check_output('tmux kill-session -t tcpdump_scan', shell=True)
        except CalledProcessError:
            pass
        
        # Compress the pcap
        os.system(f"sudo pigz --best ../{protocol_pkt_seq}/{host}.pcap")

        # Ensure zmap module is restored to the original version without the modified host name
        os.system("git checkout -- src/probe_modules/module_forbidden_scan.c")

        curr_sport += sport_range
        
        # Transfer scan files for storage and remove the files afterwards
        domain_csv_full_file_path = os.path.abspath(f"../{protocol_pkt_seq}/{host}.csv")
        domain_pcap_full_file_path = os.path.abspath(f"../{protocol_pkt_seq}/{host}.pcap.gz")
        
        domain_csv_success = False
        try:
            domain_csv_success = reliable_rsync(domain_csv_full_file_path, storage_dst, log_file)
        except Exception as e:
            log_file.write(f"Rsync failed with error {e}\n for file {domain_csv_full_file_path}. Not removing file.")
        
        if domain_csv_success:
            try:
                os.remove(domain_csv_full_file_path)
            except Exception as e:
                log_file.write(f"Failed to remove {domain_csv_full_file_path}: {e}\n")
        
        domain_pcap_success = False
        try:
            domain_pcap_success = reliable_rsync(domain_pcap_full_file_path, storage_dst, log_file)
        except Exception as e:
            log_file.write(f"Rsync failed with error {e}\n for file {domain_pcap_full_file_path}. Not removing file.")
        
        if domain_pcap_success:
            try:
                os.remove(domain_pcap_full_file_path)
            except Exception as e:
                log_file.write(f"Failed to remove {domain_pcap_full_file_path}: {e}\n")
        
    with open(f"../{protocol_pkt_seq}/scan_metadata.txt", "w") as json_file:
        json.dump(scan_metadata_dict, json_file)
        
    # Transfer the scan_metadata.txt to storage machine and remove the file afterwards
    scan_metadata_full_file_path = os.path.abspath(f"../{protocol_pkt_seq}/scan_metadata.txt")
    scan_metadata_success = False
    try:
        scan_metadata_success = reliable_rsync(scan_metadata_full_file_path, storage_dst, log_file)
    except Exception as e:
         log_file.write(f"Rsync failed with error {e}\n for file {scan_metadata_full_file_path}. Not removing file.")
         
    if scan_metadata_success:
        try:
            os.remove(scan_metadata_full_file_path)
        except Exception as e:
            log_file.write(f"Failed to remove {scan_metadata_full_file_path}: {e}\n")
    
    log_file.close()

def get_args():
    """
    Gets arguments from user.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("--port", type=str, help="port to send HTTP request to")
    parser.add_argument("--interface", type=str, help="interface to send probes to")
    parser.add_argument("--source_ip", type=str, help="source IP address of the measurement machine")
    parser.add_argument("--storage_dst", type=str, help="destination for storage of scans")
    parser.add_argument("--protocol_pkt_seq", type=str, help="protocol and packet sequence used for scan")
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    global_censored_zmap_scan(args.port, args.interface, args.source_ip, args.storage_dst, args.protocol_pkt_seq)
