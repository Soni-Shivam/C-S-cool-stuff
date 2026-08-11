#!/usr/bin/env bash
set -euo pipefail

# Preserve established IAP SSH, local services, and adb/emulator host communication.
iptables -F OUTPUT
iptables -F FORWARD
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 169.254.169.254/32 -j REJECT
iptables -A OUTPUT -d 10.0.0.0/8 -j REJECT
iptables -A OUTPUT -d 172.16.0.0/12 -j REJECT
iptables -A OUTPUT -d 192.168.0.0/16 -j REJECT
iptables -A OUTPUT -j DROP

# Emulator traffic may reach only host-local fake C2/proxy endpoints; never metadata,
# another VPC host, or an uplink. The final DROP is required by containment signing.
iptables -A FORWARD -s 10.0.2.0/24 -d 169.254.169.254/32 -j REJECT
iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.0.0/8 -j REJECT
iptables -A FORWARD -s 10.0.2.0/24 -d 172.16.0.0/12 -j REJECT
iptables -A FORWARD -s 10.0.2.0/24 -d 192.168.0.0/16 -j REJECT
iptables -A FORWARD -j DROP
netfilter-persistent save
