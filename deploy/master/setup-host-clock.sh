#!/usr/bin/env bash
set -euo pipefail

die() { printf 'MCUI clock setup: %s\n' "$*" >&2; exit 1; }
[[ $# == 0 && $(id -u) == 0 ]] || die 'Run as root without arguments'
command -v systemctl >/dev/null && command -v timedatectl >/dev/null || die 'A running systemd with timedatectl is required'
systemctl show --property=Version --value >/dev/null || die 'A running systemd instance is required'

active=
for service in chrony.service chronyd.service systemd-timesyncd.service ntp.service ntpsec.service openntpd.service; do
  if systemctl is-active --quiet "$service"; then
    active=$service
    break
  fi
done

if [[ -z $active ]]; then
  # Prefer an installed service over installing a second clock controller.
  for service in chrony.service chronyd.service systemd-timesyncd.service ntp.service ntpsec.service openntpd.service; do
    if systemctl cat "$service" >/dev/null 2>&1; then
      active=$service
      break
    fi
  done
  if [[ -z $active ]]; then
    [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null || die 'No supported time service found; configure one for this host'
    printf '%s\n' 'Installing systemd-timesyncd to maintain the host clock.'
    apt-get update </dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd-timesyncd </dev/null
    active=systemd-timesyncd.service
  fi
  printf 'Enabling host time synchronization: %s\n' "$active"
  systemctl enable --now "$active" || die "Could not enable $active; check the host time service"
else
  printf 'Using active host time synchronization: %s\n' "$active"
fi

printf '%s\n' 'Waiting up to 120 seconds for the host to report synchronization...'
for ((attempt=0; attempt<60; attempt++)); do
  if [[ $(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true) == yes ]]; then
    printf '%s\n' 'The host reports synchronized time. MCUI will independently verify authenticated time before signing tasks.'
    exit 0
  fi
  sleep 2
done
die "Host time synchronization is not ready ($active). Check timedatectl status, the service logs and network access, then retry. MCUI requires a working authenticated time source as well."
