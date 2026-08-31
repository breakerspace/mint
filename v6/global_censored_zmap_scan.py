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

def global_censored_zmap_scan(port, interface, source_ip, storage_dst, protocol_pkt_seq, v6_target_file):
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
    
    # Transfer the v6 target file to the storage machine
    full_file_path = os.path.abspath(f"{v6_target_file}")
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
            
    os.chdir("zmap_v6_modules/")
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
        sed "s/#define HOST .*/#define HOST \\\"%s\\\"/g" src/probe_modules/module_ipv6_forbidden_scan.c > src/probe_modules/.backup
        """ % host
        print(cmd)
        os.system(cmd)
        time.sleep(1)
        os.system("mv src/probe_modules/.backup src/probe_modules/module_ipv6_forbidden_scan.c")
        time.sleep(1)
        os.system(f"cmake . && make -j4 && sudo src/zmap -M ipv6_forbidden_scan -p {port} --ipv6-source-ip {source_ip} --ipv6-target-file {v6_target_file} -f \"saddr,len,payloadlen,flags,validation_type,sport,dport,seqnum,acknum,window,ttl\" -o ../{protocol_pkt_seq}/{host}.csv -O csv -B 10M -i {interface} -c 60 -s {curr_sport}-{sport_range_end}")
        
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
        os.system("git checkout -- src/probe_modules/module_ipv6_forbidden_scan.c")

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
    parser.add_argument("--v6_target_file", type=str, help="the IPv6 targets to send the probes to")
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    global_censored_zmap_scan(args.port, args.interface, args.source_ip, args.storage_dst, args.protocol_pkt_seq, args.v6_target_file)