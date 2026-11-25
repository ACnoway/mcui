#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/bin" "$work/release"
cp deploy/master/install-compose.sh "$work/release/install-mcui-compose.sh"
cp deploy/master/setup-host-clock.sh "$work/release/setup-host-clock.sh"
cat >"$work/bin/id" <<'EOF'
#!/bin/sh
echo 0
EOF
cat >"$work/bin/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >>"$MOCK_LOG"
case "$1" in
  show|enable) exit 0 ;;
  is-active) [ "$MOCK_CASE" = active ] && [ "$3" = systemd-timesyncd.service ] ;;
  cat) [ "$MOCK_CASE" = installed ] && [ "$2" = chrony.service ] ;;
  *) exit 1 ;;
esac
EOF
cat >"$work/bin/timedatectl" <<'EOF'
#!/bin/sh
if [ "$MOCK_CASE" = timeout ]; then echo no; else echo yes; fi
EOF
cat >"$work/bin/docker" <<'EOF'
#!/bin/sh
echo "docker $*" >>"$MOCK_LOG"
EOF
cat >"$work/bin/apt-get" <<'EOF'
#!/bin/sh
echo "apt-get $*" >>"$MOCK_LOG"
EOF
cat >"$work/bin/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH" MOCK_LOG="$work/log"

export MOCK_CASE=active
: >"$MOCK_LOG"
bash "$work/release/install-mcui-compose.sh" -f compose.yaml >/dev/null
grep -q 'docker compose -f compose.yaml config --quiet' "$MOCK_LOG"
grep -q 'docker compose -f compose.yaml up -d' "$MOCK_LOG"
! grep -Eq '^(apt-get|systemctl enable)' "$MOCK_LOG"

export MOCK_CASE=installed
: >"$MOCK_LOG"
bash "$work/release/install-mcui-compose.sh" >/dev/null
grep -q 'systemctl enable --now chrony.service' "$MOCK_LOG"
! grep -q '^apt-get' "$MOCK_LOG"

export MOCK_CASE=missing
: >"$MOCK_LOG"
bash "$work/release/install-mcui-compose.sh" >/dev/null
grep -q '^apt-get install .*systemd-timesyncd' "$MOCK_LOG"
grep -q 'systemctl enable --now systemd-timesyncd.service' "$MOCK_LOG"

export MOCK_CASE=timeout
: >"$MOCK_LOG"
if bash "$work/release/install-mcui-compose.sh" >/dev/null 2>&1; then
  echo 'Unsynchronized host unexpectedly accepted' >&2
  exit 1
fi
! grep -q 'docker compose up -d' "$MOCK_LOG"
echo 'Host clock installer checks passed'
