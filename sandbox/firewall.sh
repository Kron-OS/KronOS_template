#!/usr/bin/env bash
#
# Egress firewall for the KronOS sandbox. Applied by the entrypoint as root
# *before* any workload runs. The sandbox processes untrusted evidence and may
# be compromised, so it must not be able to reach the local network (your
# home/office LAN, the host, or other containers). It MAY reach the public
# internet (for pip/plaso/apt) unless the compose network is set internal.
#
# Why this is safe even if the workload is popped: the workload runs as the
# unprivileged 'sandbox' user with no CAP_NET_ADMIN, so it cannot flush or
# alter these rules. Only the root entrypoint (which exits into sshd) sets them.
#
# Why blocking RFC1918 does NOT also kill internet access: packets to the
# public internet carry *public* destination IPs, so they never match the
# private-range REJECT rules — they are ACCEPTed and NAT'd out via the gateway
# as usual. Only packets whose *destination* is a private/LAN address are
# dropped. Inbound SSH from a LAN client keeps working because its reply
# traffic matches the ESTABLISHED,RELATED accept placed before the REJECTs.

set -euo pipefail

IPT="iptables"

# Ranges considered "local network" — RFC1918, link-local, CGNAT, multicast.
PRIVATE_NETS=(
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
    169.254.0.0/16
    100.64.0.0/10
    224.0.0.0/4
)

# --- OUTBOUND: block the local network, allow internet + replies -----------
"$IPT" -F OUTPUT
"$IPT" -A OUTPUT -o lo -j ACCEPT
"$IPT" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Docker's embedded DNS resolver (name resolution for pip/plaso).
"$IPT" -A OUTPUT -d 127.0.0.11 -j ACCEPT
for net in "${PRIVATE_NETS[@]}"; do
    "$IPT" -A OUTPUT -d "$net" -j REJECT --reject-with icmp-admin-prohibited
done
# Everything left has a public destination -> allow (internet).
"$IPT" -A OUTPUT -j ACCEPT

# --- INBOUND: only SSH + established replies + loopback --------------------
"$IPT" -F INPUT
"$IPT" -P INPUT DROP
"$IPT" -A INPUT -i lo -j ACCEPT
"$IPT" -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
"$IPT" -A INPUT -p tcp --dport 22 -j ACCEPT

echo "[firewall] local network blocked; internet + inbound SSH allowed" >&2
