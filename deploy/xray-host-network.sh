#!/usr/bin/env bash
set -euo pipefail
umask 077

# Dedicated firewall for the static Xray host-mode service account.  DNS
# access to local resolvers is required by Xray itself; proxy destinations are
# independently constrained by the signed configuration and Freedom rules.
table=mcui_xray_host
snapshot=/run/mcui-xray-host-guard/firewall.rules
uid=$(/usr/bin/id -u mcui-xray-host)
[[ $uid =~ ^[0-9]+$ ]] && (( uid > 0 && uid < 1000 )) || { echo 'Invalid Xray host service account UID' >&2; exit 1; }
[[ $(getent passwd "$uid" | cut -d: -f1) == mcui-xray-host ]] || { echo 'Xray host UID belongs to another account' >&2; exit 1; }
[[ $(getent passwd mcui-xray-host | cut -d: -f7) == /usr/sbin/nologin && $(id -G mcui-xray-host) != *' '* ]] ||
  { echo 'Xray host account must have no login shell or supplementary groups' >&2; exit 1; }

verify() {
  [[ -f $snapshot && ! -L $snapshot && $(stat -c '%u:%a' -- "$snapshot") == 0:600 ]] || return 1
  /usr/sbin/nft -s list table inet "$table" | cmp -s -- "$snapshot" -
}

case ${1:-} in
  start)
    if /usr/sbin/nft list table inet "$table" >/dev/null 2>&1; then
      verify || { echo 'Xray host firewall does not match its saved policy' >&2; exit 1; }
      /usr/sbin/nft delete table inet "$table"
    fi
    /usr/sbin/nft -f - <<EOF
table inet $table {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid $uid ct state established,related accept
    meta skuid $uid ip daddr { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } meta l4proto { tcp, udp } th dport 53 accept
    meta skuid $uid ip6 daddr { ::1/128, fc00::/7, fe80::/10 } meta l4proto { tcp, udp } th dport 53 accept
    meta skuid $uid fib daddr type local reject
    meta skuid $uid ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } reject
    meta skuid $uid ip6 daddr { ::/128, ::1/128, ::ffff:0.0.0.0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 } reject
  }
}
EOF
    /usr/sbin/nft -s list table inet "$table" >"$snapshot"
    verify
    ;;
  verify) verify ;;
  stop)
    if /usr/sbin/nft list table inet "$table" >/dev/null 2>&1; then
      verify || { echo 'Xray host firewall changed; leaving it in place' >&2; exit 1; }
      /usr/sbin/nft delete table inet "$table"
    fi
    rm -f -- "$snapshot"
    ;;
  *) echo 'Usage: xray-host-network start|verify|stop' >&2; exit 2 ;;
esac
