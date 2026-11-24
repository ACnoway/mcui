#!/usr/bin/env bash
set -euo pipefail

/usr/sbin/ip netns add mcui-xray
trap '/usr/sbin/ip netns delete mcui-xray' EXIT
/usr/sbin/ip -n mcui-xray link set lo up

coproc SLIRP {
  exec /usr/bin/unshare --mount --propagation private -- /usr/bin/slirp4netns \
    --configure --disable-host-loopback --disable-dns \
    --enable-sandbox --ready-fd=3 --netns-type=path /run/netns/mcui-xray tap0 3>&1 1>&2
}
network_pid=$SLIRP_PID
trap 'kill "$network_pid" 2>/dev/null || true; wait "$network_pid" || true; exit 0' TERM INT
if ! IFS= read -r -n 1 -t 10 -u "${SLIRP[0]}"; then
  kill "$network_pid" 2>/dev/null || true
  wait "$network_pid" || true
  exit 1
fi
/usr/bin/systemd-notify --ready
wait "$network_pid"
