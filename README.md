# Mint
Mint (Measuring Interference with Nonresponsive Targets) is a tool that measures network interference without live endhosts.

Mint works by crafting specific packet sequences and sending them to nonresponsive IP addresses (IP addresses with no live machines behind them), triggering middleboxes that interfere with traffic bidirectionally and that do not follow the TCP protocol fully to send injections back to the client. 

To learn more about Mint, feel free to read our paper ["Is Nobody There? Good! Globally Measuring Connection Tampering without Responsive Endhosts"](https://snourin.github.io/files/oakland2025_mint.pdf). 

# Running Mint
This repository contains the code used to run Mint over both IPv4 and IPv6. When cloning the repository, please ensure that all
submodules are also cloned.

``` 
git clone --recursive https://github.com/breakerspace/mint.git
```

Mint will be running global scans over both IPv4 and IPv6. For IPv4, Mint will run a ZMap SYN scan for 1 IP address per /24 over the entire IPv4 space in order to find nonresponsive IPs. It will then send packet sequences to these nonresponsive IPs for each domain listed in `resources/top5_ooni_confirmed_domains.txt`. For IPv6, Mint will read from a file that lists IPv6 addresses, which are presumably nonresponsive, and send packet sequences to these nonresponsive IPs for each domain.

## IPv4
To run Mint over IPv4, run `v4/run_zmap_scan.sh` while providing the correct arguments. These arguments include:
* `port`: The destination port of the ZMap scans. For packet sequences with HTTP payloads, this is usually 80 while for those with HTTPS payloads, this is usually 443.
* `interface`: The network interface to be used for the scans.
* `source_ip`: The IP address of the scanning machine being used.
* `storage_dst`: The full file path of a storage machine to which the scan files will be transferred to via rsync. 
* `protocol_pkt_seq`: The protocol and packet sequence to run for the scan. There are a total of 12 such possible values for this argument: `http_syn`, `http_syn_psh`, `http_syn_pshack`, `http_psh`, `http_pshack`, `http_pshack_sleep_pshack`, `https_syn`, `https_syn_psh`, `https_syn_pshack`, `https_psh`, `https_pshack`, and `https_pshack_sleep_pshack`.
* `ssh_key_path`: The path to the ssh key used to ssh into the storage machine from the scanning machine.

A sample list of arguments may be the following:
```
bash run_zmap_scan.sh 80 eth0 1.2.3.4 user@host:/home/user/mint_scans/ http_syn_pshack "/home/user/.ssh/id_ed25519"
```

The current scanning rate for Mint is set at 10 MB/s, but this can be increased or decreased depending on limits of the scanning machine.

## IPv6
IPv6 uses the same arguments as IPv4 with the addition of one argument:
* `v6_target_file`: The file that lists the IPv6 addresses to scan. These IPv6 addresses should be nonresponsive.

In order to obtain IPv6 addresses for this file, feel free to obtain allocated /48 prefixes from [The IPv6 Observatory](https://ipv6observatory.org/) and enumerate random IPv6 addresses within these /48 prefixes.

## Notes
Depending on your scanning machine you may see the following message appear when running our scripts:
```
zmap: unrecognized option '--blocklist-file=/etc/zmap/blocklist.conf'
```
This is a problem that occurs when the machine has an older version of ZMap that still uses the old term for blocklists.
Feel free to change the term on line 21 in `v4/zmap_v4_modules/src/zopt.ggo.in` and line 589 (or line 674 for the `http_pshack_sleep_pshack` and `https_pshack_sleep_pshack`) on `v4/zmap_v4_modules/src/zmap.c` to remedy this problem.

Furthermore, if any other bugs arise when running the scripts, or if you would like access to some of our analysis code, feel free to [contact us](https://geneva.cs.umd.edu/people/).

# License
This repository has a BSD 3-Clause license. However, the repository contains multiple submodules to other repositories which each have their own license. Please consult these other licenses as well.

# Citation
If you'd like to use any of our scripts in this repo for your projects, please feel free to cite our work:
```
@inproceedings{Nourin2025:Oakland,
author     = {Nourin, Sadia and Rye, Erik and Bock, Kevin and Hoang, Nguyen Phong and Levin, Dave},
title      = {Is Nobody There? Good! Globally Measuring Connection Tampering Without Responsive Endhosts},
booktitle  = {2025 IEEE Symposium on Security and Privacy (SP)},
series     = {IEEE S&P '25},
year       = {2025},
}
```
