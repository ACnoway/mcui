# Sourced by the verified Agent installer after both task ledgers are checked.

install_xray_bootstrap() {
  local profile=$stage/xray-bootstrap
  local units=/etc/systemd/system
  local source_dir=/etc/chrony/sources.d
  local xray_config=/etc/mcui-xray
  local chrony_source=$source_dir/mcui-nts.sources
  local expected_id host_uid
  local panel_inbounds=false
  if [[ -f $profile/managed ]]; then
    printf '%s\n' "$provided_core_key" >"$profile/xray-install.pub"
    chmod 0644 "$profile/xray-install.pub"
    printf 'MCUI_XRAY_INSTALL_KEY_ID=%s\n' "$provided_core_id" >"$profile/xray-install.env"
    cat "$profile/xray-install.defaults" >>"$profile/xray-install.env"
  fi
  [[ -f $profile/xray-install.pub && -f $profile/xray-install.env ]] || die 'Xray bootstrap is missing install-task trust'
  expected_id=$(sed -n 's/^MCUI_XRAY_INSTALL_KEY_ID=//p' "$profile/xray-install.env")
  [[ $expected_id =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || die 'Invalid Xray install-task key ID'
  if file_exists "$config/xray-install.pub"; then
    check_config "$config/xray-install.pub"
    cmp -s -- "$profile/xray-install.pub" "$config/xray-install.pub" || die 'Existing Xray install key differs'
  fi
  if file_exists "$config/xray-install.env"; then
    check_config "$config/xray-install.env"
    [[ $(sed -n 's/^MCUI_XRAY_INSTALL_KEY_ID=//p' "$config/xray-install.env") == "$expected_id" ]] ||
      die 'Existing Xray install key ID differs'
  fi

  [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null ||
    die 'Automatic Xray bootstrap requires Debian with APT'
  if [[ $arch == amd64 && ( $preserve == false || $enable_panel_inbounds == true ) ]]; then
    panel_inbounds=true
    if [[ ! -x /usr/sbin/ip || ! -x /usr/bin/slirp4netns || ! -x /usr/sbin/modprobe || ! -x /usr/sbin/nft ]]; then
      apt-get update </dev/null
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 kmod slirp4netns nftables </dev/null
    fi
    if [[ ! -c /dev/net/tun ]]; then
      /usr/sbin/modprobe tun || die 'The Xray panel network requires the TUN kernel device'
      [[ -c /dev/net/tun ]] || die 'The Xray panel network requires access to /dev/net/tun'
    fi
  fi
  if [[ ! -x /usr/bin/chronyc || ! -x /usr/sbin/chronyd ]] || ! command -v cmp >/dev/null; then
    apt-get update </dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends chrony diffutils </dev/null
  fi
  id _chrony >/dev/null 2>&1 && [[ -d $source_dir && ! -L $source_dir ]] ||
    die 'Debian chrony with sources.d is required'

  chmod 0755 "$profile"
  if ! file_exists "$xray_config"; then
    install -d -o root -g root -m 0700 "$xray_config"
  fi
  [[ -d $xray_config && ! -L $xray_config && $(stat -c '%u:%a' -- "$xray_config") == 0:700 ]] ||
    die 'Insecure Xray configuration directory'

  "$stage/$arch/mcui-xray" initialize >/dev/null
  getent group mcui-xray-stats >/dev/null || groupadd --system mcui-xray-stats
  if [[ $panel_inbounds == true ]]; then
    "$stage/$arch/mcui-xray" initialize-panel-inbounds >/dev/null
    id mcui-xray-host >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin mcui-xray-host
    host_uid=$(id -u mcui-xray-host)
    [[ $host_uid =~ ^[0-9]+$ ]] && (( host_uid > 0 && host_uid < 1000 )) &&
      [[ $(getent passwd "$host_uid" | cut -d: -f1) == mcui-xray-host &&
         $(getent passwd mcui-xray-host | cut -d: -f7) == /usr/sbin/nologin &&
         $(id -G mcui-xray-host) != *' '* ]] || die 'Invalid Xray host service account'
    install -d -o root -g root -m 0755 /usr/local/libexec "$units/mcui-xray.service.d"
    install -o root -g root -m 0755 -- "$profile/xray-network.sh" /usr/local/libexec/mcui-xray-network
    install -o root -g root -m 0755 -- "$profile/xray-host-network.sh" /usr/local/libexec/mcui-xray-host-network
    install -o root -g root -m 0644 -- "$stage/units/mcui-xray-panel-network.conf" "$units/mcui-xray.service.d/panel-network.conf"
  fi

  if ! /usr/sbin/chronyd -p | awk -v sources="$source_dir" '
    $1 == "sourcedir" { for (i = 2; i <= NF; ++i) if ($i == sources) found = 1 }
    END { exit !found }
  '; then
    die 'Chrony must load the Debian sources.d directory'
  fi
  printf 'server time.cloudflare.com iburst nts prefer require\n' >"$profile/mcui-nts.sources"
  if file_exists "$chrony_source"; then
    check_config "$chrony_source"
    cmp -s -- "$profile/mcui-nts.sources" "$chrony_source" || die 'Existing MCUI NTS source differs'
  else
    install -o root -g root -m 0644 -- "$profile/mcui-nts.sources" "$chrony_source"
  fi

  install -o root -g root -m 0755 -- "$stage/$arch/mcui-xray" /usr/local/bin/mcui-xray
  install -o root -g root -m 0644 -- "$stage/units/"mcui-xray*.service \
    "$stage/units/mcui-node-clock.socket" "$stage/units/mcui-node-clock@.service" "$units/"
  install -d -o root -g root -m 0755 "$units/mcui-helper.service.d"
  install -o root -g root -m 0644 -- "$stage/units/mcui-helper-xray-install.conf" "$units/mcui-helper.service.d/xray-install.conf"
  install -o root -g root -m 0644 -- "$profile/xray-install.pub" "$config/xray-install.pub"
  install -o root -g root -m 0644 -- "$profile/xray-install.env" "$config/xray-install.env"
  systemctl daemon-reload
  systemctl enable --now chrony.service mcui-node-clock.socket
  /usr/bin/chronyc reload sources
  systemctl enable mcui-xray-recover.service
}
