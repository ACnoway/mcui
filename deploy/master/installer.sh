#!/usr/bin/env bash
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 0 && $(id -u) == 0 ]] || die 'Run the verified installer as root, without arguments'
[[ $(uname -s) == Linux ]] || die 'Linux with systemd is required'
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) die 'Unsupported Linux architecture' ;;
esac
for tool in awk flock getent install runuser sha256sum systemctl tar useradd; do
  command -v "$tool" >/dev/null || die "Missing required command: $tool"
done
systemctl show --property=Version --value >/dev/null || die 'A running systemd instance is required'

root=/opt/mcui-master
state=/var/lib/mcui-master
unit=/etc/systemd/system/mcui-master.service
exec 9>/run/mcui-master-install.lock
flock -n 9 || die 'Another MCUI Master installation is in progress'
install -d -m 0755 "$root" "$root/releases" /etc/mcui-master
stage=$(mktemp -d "$root/.install.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
previous=
if [[ -L $root/current ]]; then
  previous=$(readlink -- "$root/current")
  [[ $previous == "$root"/releases/* && -x $previous/mcui-panel && -f $unit ]] ||
    die 'Existing MCUI Master installation is inconsistent'
  cp -- "$unit" "$stage/previous.service"
elif [[ -e $root/current || -e $unit || -L $unit ]]; then
  die 'Existing MCUI Master files require manual reconciliation'
fi

payload=$(awk '/^__MCUI_MASTER_PAYLOAD__$/ { print NR+1; exit }' "$0")
[[ -n $payload ]] || die 'Installer payload is missing'
tail -n +"$payload" "$0" | tar -xzf - -C "$stage" "$arch" web mcui-master.service
sum=$(sha256sum -- "$0")
version=${sum%% *}
release=$root/releases/$version
if [[ ! -d $release ]]; then
  install -m 0755 "$stage/$arch/mcui-panel" "$stage/mcui-panel"
  mkdir "$stage/release"
  mv "$stage/mcui-panel" "$stage/web" "$stage/release/"
  chmod -R a+rX "$stage/release"
  mv -T "$stage/release" "$release"
fi

if ! getent passwd mcui-master >/dev/null; then
  useradd --system --user-group --home-dir "$state" --shell /usr/sbin/nologin mcui-master
fi
install -d -o mcui-master -g mcui-master -m 0750 "$state"
if [[ -z $previous ]]; then
  runuser -u mcui-master -- "$release/mcui-panel" -init-admin-only -db "$state/mcui.db"
fi

ln -s -- "$release" "$stage/current"
mv -Tf -- "$stage/current" "$root/current"
if ! install -m 0644 "$stage/mcui-master.service" "$unit" ||
  ! systemctl daemon-reload || ! systemctl restart mcui-master.service; then
  systemctl stop mcui-master.service || true
  if [[ -n $previous ]]; then
    ln -s -- "$previous" "$stage/current"
    mv -Tf -- "$stage/current" "$root/current"
    install -m 0644 "$stage/previous.service" "$unit"
    systemctl daemon-reload
    systemctl start mcui-master.service || die 'Failed to restore the previous service; inspect the journal'
  fi
  die 'MCUI Master failed to start; inspect journalctl -u mcui-master'
fi
systemctl enable mcui-master.service
printf 'MCUI Master is running. The default address is http://127.0.0.1:8080.\n'
exit 0
__MCUI_MASTER_PAYLOAD__
