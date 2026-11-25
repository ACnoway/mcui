#!/bin/sh
set -eu
umask 077
if [ "${1:-}" = -managed ]; then
  (
    while :; do
      if /usr/sbin/chronyd -d -U -x -f /opt/mcui/chrony.conf; then
        echo 'chronyd exited; restarting in 5 seconds' >&2
      else
        echo 'chronyd failed; restarting in 5 seconds' >&2
      fi
      sleep 5
    done
  ) &
fi
exec /usr/local/bin/mcui-panel "$@"
