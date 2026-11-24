#!/bin/sh
set -eu
umask 077
if [ "${1:-}" = -managed ]; then
  /usr/sbin/chronyd -d -U -x -f /opt/mcui/chrony.conf &
fi
exec /usr/local/bin/mcui-panel "$@"
