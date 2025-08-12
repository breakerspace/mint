# Mint
Mint (Measuring Interference with Nonresponsive Targets) is a tool that measures network interference without endhosts within the network.

Mint works by crafting specific packet sequences and sending them to nonresponsive IP addresses (IP addresses with no live machines behind them),
triggering middleboxes that interfere with traffic bidirectionally and that do not follow the TCP protocol fully to send injections back to the client. 

This repository contains the code used to run Mint over both IPv4 and IPv6.


If you get a message like this:
zmap: unrecognized option '--blocklist-file=/etc/zmap/blocklist.conf'

Change line 21 on zopt.ggo.in and 589 on zmap.c 
