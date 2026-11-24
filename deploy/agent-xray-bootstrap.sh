# Sourced by the verified Agent installer after both task ledgers are checked.

install_xray_bootstrap() {
  local profile=$stage/xray-bootstrap
  local manifest_tool=$stage/$arch/mcui-manifest
  local units=/etc/systemd/system
  local source_dir=/etc/chrony/sources.d
  local xray_config=/etc/mcui-xray
  local xray_state=/var/lib/mcui-xray
  local helper_manifest=$xray_state/control/xray-manifest
  local agent_manifest=$agent_state/xray-manifest
  local chrony_source=$source_dir/mcui-nts.sources
  local file panel_inbounds=false
  if file_exists "$config/xray-install.env" || file_exists "$xray_state/current"; then
    for file in "$helper_manifest/accepted.json" "$agent_manifest/accepted.json"; do
      [[ -f $file && ! -L $file ]] || die 'Restore accepted Xray manifest state before enrolling this node'
    done
  fi
  [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null ||
    die 'Automatic Xray bootstrap requires Debian with APT'
  if [[ $arch == amd64 && ( $preserve == false || $enable_panel_inbounds == true ) ]]; then
    panel_inbounds=true
    if [[ ! -x /usr/sbin/ip || ! -x /usr/bin/slirp4netns || ! -x /usr/sbin/modprobe ]]; then
      apt-get update </dev/null
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 kmod slirp4netns </dev/null
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

  chmod 0755 -- "$profile" "$manifest_tool"
  "$manifest_tool" verify -public-key "$profile/release.pub" -manifest "$profile/manifest.json" \
    -signature "$profile/manifest.json.sig" -distinct-public-key "$profile/xray-install.pub" \
    -distinct-public-key "$effective_key"
  for file in xray-install.pub release.pub xray-install.env; do
    if file_exists "$config/$file"; then
      check_config "$config/$file"
      cmp -s -- "$profile/$file" "$config/$file" || die "Existing Xray bootstrap differs: $config/$file"
    fi
  done
  if ! file_exists "$xray_config"; then
    install -d -o root -g root -m 0700 "$xray_config"
  fi
  [[ -d $xray_config && ! -L $xray_config && $(stat -c '%u:%a' -- "$xray_config") == 0:700 ]] ||
    die 'Insecure Xray configuration directory'
  if file_exists "$xray_config/release.pub"; then
    [[ -f $xray_config/release.pub && ! -L $xray_config/release.pub && $(stat -c '%u:%a' -- "$xray_config/release.pub") == 0:444 ]] &&
      cmp -s -- "$profile/release.pub" "$xray_config/release.pub" || die 'Existing local Xray release key differs'
  else
    install -o root -g root -m 0444 -- "$profile/release.pub" "$xray_config/release.pub"
  fi

  "$stage/$arch/mcui-xray" initialize >/dev/null
  if [[ $panel_inbounds == true ]]; then
    "$stage/$arch/mcui-xray" initialize-panel-inbounds >/dev/null
    install -d -o root -g root -m 0755 /usr/local/libexec "$units/mcui-xray.service.d"
    install -o root -g root -m 0755 -- "$profile/xray-network.sh" /usr/local/libexec/mcui-xray-network
    install -o root -g root -m 0644 -- "$stage/units/mcui-xray-panel-network.conf" "$units/mcui-xray.service.d/panel-network.conf"
  fi
  if ! file_exists "$helper_manifest/accepted.json"; then
    "$manifest_tool" init-state -state "$helper_manifest" -public-key "$profile/release.pub" \
      -manifest "$profile/manifest.json" -signature "$profile/manifest.json.sig"
  fi
  if ! file_exists "$agent_manifest/accepted.json"; then
    runuser -u mcui-agent -- "$manifest_tool" init-state -state "$agent_manifest" -public-key "$profile/release.pub" \
      -manifest "$profile/manifest.json" -signature "$profile/manifest.json.sig"
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
  install -o root -g root -m 0755 -- "$stage/$arch/mcui-xray" "$manifest_tool" /usr/local/bin/
  install -o root -g root -m 0644 -- "$stage/units/"mcui-xray*.service \
    "$stage/units/mcui-node-clock.socket" "$stage/units/mcui-node-clock@.service" "$units/"
  install -d -o root -g root -m 0755 "$units/mcui-helper.service.d"
  install -o root -g root -m 0644 -- "$stage/units/mcui-helper-xray-install.conf" "$units/mcui-helper.service.d/xray-install.conf"
  for file in xray-install.pub release.pub xray-install.env; do
    file_exists "$config/$file" || install_trust "$profile/$file" "$config/$file"
  done
  systemctl daemon-reload
  systemctl enable --now chrony.service mcui-node-clock.socket
  /usr/bin/chronyc reload sources
  systemctl enable mcui-xray-recover.service
}
