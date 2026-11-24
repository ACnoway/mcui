#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }

master=
node_id=
preserve=false
enable_panel_inbounds=false
provided_key_id=
provided_key=
provided_ca=
provided_core_id=
provided_core_key=
while (($#)); do
  case "$1" in
    --master) (($# >= 2)) || die 'Missing Master address'; master=$2; shift 2 ;;
    --node-id) (($# >= 2)) || die 'Missing node ID'; node_id=$2; shift 2 ;;
    --preserve-state) preserve=true; shift ;;
    --enable-panel-inbounds) enable_panel_inbounds=true; shift ;;
    --task-key-id) (($# >= 2)) || die 'Missing task key ID'; provided_key_id=$2; shift 2 ;;
    --task-public-key) (($# >= 2)) || die 'Missing task public key'; provided_key=$2; shift 2 ;;
    --core-key-id) (($# >= 2)) || die 'Missing Core key ID'; provided_core_id=$2; shift 2 ;;
    --core-public-key) (($# >= 2)) || die 'Missing Core public key'; provided_core_key=$2; shift 2 ;;
    --master-ca-base64) (($# >= 2)) || die 'Missing Master CA'; provided_ca=$2; shift 2 ;;
    *) die 'Unknown installer option' ;;
  esac
done

[[ $(id -u) == 0 ]] || die 'Run the verified installer with sudo'
[[ $master == https://* && ! $master =~ [[:space:]] ]] || die 'Invalid Master origin'
[[ $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die 'Invalid node ID'
if [[ $provided_key_id || $provided_key || $provided_ca ]]; then
  [[ $provided_key_id =~ ^[A-Za-z0-9._:-]{1,128}$ && $provided_key =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
    die 'Automatic trust setup requires a valid task key ID and Base64 Ed25519 public key'
  (( ${#provided_ca} <= 21848 )) || die 'Master CA exceeds the enrollment limit'
fi
if [[ $provided_core_id || $provided_core_key ]]; then
  [[ $provided_key_id && $provided_core_id =~ ^[A-Za-z0-9._:-]{1,128}$ &&
     $provided_core_key =~ ^[A-Za-z0-9+/]{43}=$ && $provided_core_id != "$provided_key_id" ]] ||
    die 'Core trust requires distinct task and Core key IDs and Base64 Ed25519 public keys'
fi
[[ $(uname -s) == Linux ]] || die 'Linux with systemd is required'
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) die 'Unsupported Linux architecture' ;;
esac
if [[ $enable_panel_inbounds == true && ( $preserve != true || $arch != amd64 ) ]]; then
  die 'Panel inbound migration requires --preserve-state and an amd64 node'
fi
command -v systemctl >/dev/null || die 'A running systemd instance is required'
systemctl show --property=Version --value >/dev/null || die 'A running systemd instance is required'

required_tools=(runuser groupadd useradd getent install flock stat awk tar tail gzip base64 ln mktemp)
missing=()
for tool in "${required_tools[@]}"; do
  command -v "$tool" >/dev/null || missing+=("$tool")
done
if (( ${#missing[@]} )) || [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
  [[ -f /etc/debian_version ]] && command -v apt-get >/dev/null ||
    die "Install system CA certificates and required commands first: ${missing[*]}"
  apt-get update </dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates passwd util-linux coreutils tar gzip mawk </dev/null
fi
for tool in "${required_tools[@]}"; do
  command -v "$tool" >/dev/null || die "Missing required command: $tool"
done
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || die 'Install ca-certificates first'

exec 9>/run/mcui-agent-install.lock
flock -n 9 || die 'Another Agent installation is in progress'

config=/etc/mcui-agent
agent_state=/var/lib/mcui-agent
helper_state=/var/lib/mcui-helper
key_file=$config/task-signing.pub
key_id_file=$config/task-key-id
ca_file=
pending_trust=
file_exists() { [[ -e $1 || -L $1 ]]; }
check_config() {
  local mode
  [[ -f $1 && ! -L $1 ]] || die "Missing or invalid trusted configuration: $1"
  mode=$(stat -c '%u:%a' -- "$1")
  [[ $mode == 0:644 || $mode == 0:640 || $mode == 0:600 ]] || die "Insecure trusted configuration: $1"
}
if ! file_exists "$config" && [[ $provided_key_id ]]; then
  install -d -o root -g root -m 0755 "$config"
fi
[[ -d $config && ! -L $config ]] || die "Provision trusted configuration in $config"
config_mode=$(stat -c '%u:%a' -- "$config")
[[ $config_mode == 0:755 || $config_mode == 0:750 ]] || die 'Insecure Agent configuration directory'
stage=$(mktemp -d /var/tmp/mcui-install.XXXXXXXX)
restart_agent=false
cleanup() {
  local result=$?
  if [[ $restart_agent == true && $result != 0 ]]; then
    systemctl start mcui-agent.service >/dev/null 2>&1 || true
  fi
  if [[ $pending_trust ]]; then
    rm -f -- "$pending_trust"
  fi
  rm -rf -- "$stage"
}
trap cleanup EXIT
archive_line=$(awk '/^__MCUI_ARCHIVE__$/ { print NR + 1; exit }' "$0")
[[ $archive_line ]] || die 'Installer archive is missing'
tail -n "+$archive_line" "$0" | tar --no-same-owner -xz -C "$stage"
# The service account needs read/execute access to the staged Agent for preflight.
chmod 0755 "$stage"
agent=$stage/$arch/mcui-agent
helper=$stage/$arch/mcui-helper
[[ -x $agent && -x $helper ]] || die 'Installer is missing the required binaries'
if [[ $enable_panel_inbounds == true && ! -d $stage/xray-bootstrap ]]; then
  die 'Panel inbound migration requires an installer with the Xray bootstrap profile'
fi
chmod 0755 "$stage/$arch" "$agent"
if [[ -f $stage/xray-bootstrap/managed ]]; then
  [[ $provided_core_id ]] || die 'The managed installer requires the Core management public key from the panel'
elif [[ $provided_core_id ]]; then
  die 'This installer does not accept the Core management public key'
fi

install_trust() {
  pending_trust=$(mktemp "$config/.mcui-trust.XXXXXXXX")
  install -o root -g root -m 0644 "$1" "$pending_trust"
  ln -T -- "$pending_trust" "$2"
  rm -f -- "$pending_trust"
  pending_trust=
}

if file_exists "$config/master-ca.pem"; then
  ca_file=$config/master-ca.pem
  check_config "$ca_file"
fi
effective_key=$key_file
effective_ca=$ca_file
if [[ $provided_key_id ]]; then
  printf '%s\n' "$provided_key" >"$stage/task-signing.pub"
  printf '%s\n' "$provided_key_id" >"$stage/task-key-id"
  if file_exists "$key_file"; then
    check_config "$key_file"
  else
    chmod 0644 "$stage/task-signing.pub"
    effective_key=$stage/task-signing.pub
  fi
  if file_exists "$key_id_file"; then
    check_config "$key_id_file"
    [[ $(<"$key_id_file") == "$provided_key_id" ]] ||
      die 'Task key ID differs from the installed trust; use the local trust rotation workflow'
  fi
  trust_check=(-task-public-key "$effective_key" -expected-enrollment-key "$stage/task-signing.pub")
  if [[ $provided_ca ]]; then
    printf '%s' "$provided_ca" | base64 --decode >"$stage/master-ca.pem" || die 'Invalid Master CA encoding'
    if [[ -z $ca_file ]]; then
      chmod 0644 "$stage/master-ca.pem"
      effective_ca=$stage/master-ca.pem
      ca_file=$config/master-ca.pem
    fi
    trust_check+=(-master-ca "$effective_ca" -expected-enrollment-ca "$stage/master-ca.pem")
  fi
  "$helper" "${trust_check[@]}"
  key_id=$provided_key_id
else
  check_config "$key_file"
  check_config "$key_id_file"
  key_id=$(<"$key_id_file")
  [[ $key_id =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || die 'Invalid task signing key ID'
fi

getent group mcui-agent >/dev/null || groupadd --system mcui-agent
id mcui-agent >/dev/null 2>&1 || useradd --system --gid mcui-agent --no-create-home --home-dir "$agent_state" --shell /usr/sbin/nologin mcui-agent
[[ $(id -u mcui-agent) != 0 && $(id -gn mcui-agent) == mcui-agent ]] || die 'Invalid existing Agent account'
runuser -u mcui-agent -- test -r "$effective_key" || die 'The Agent cannot read the task signing public key'
if [[ $effective_ca ]]; then
  runuser -u mcui-agent -- test -r "$effective_ca" || die 'The Agent cannot read the private Master CA'
fi

if [[ $preserve == true ]]; then
  [[ -f $agent_state/tasks.db && -f $helper_state/ledger.json ]] || die 'Existing task state is missing. Restore or reconcile both ledgers before enrolling.'
fi
[[ ! -L $agent_state && ! -L $helper_state ]] || die 'State directories may not be symlinks'
[[ -d $agent_state ]] || install -d -o mcui-agent -g mcui-agent -m 0700 "$agent_state"
[[ -d $helper_state ]] || install -d -o root -g mcui-agent -m 0700 "$helper_state"

agent_args=(-master "$master" -node-id "$node_id" "-server-ca=$effective_ca")
helper_args=(-master "$master" -node-id "$node_id" "-master-ca=$effective_ca" -task-key-id "$key_id" -task-public-key "$effective_key")
if systemctl is-active --quiet mcui-agent.service; then
  systemctl stop mcui-agent.service
  restart_agent=true
fi
if [[ ! -e $helper_state/ledger.json && ! -L $helper_state/ledger.json ]]; then
  [[ $preserve == false && ! -e $agent_state/tasks.db && ! -e $agent_state/identity.json ]] || die 'Helper ledger is missing; reconcile existing state'
  "$helper" "${helper_args[@]}" -initialize-ledger
fi
"$helper" "${helper_args[@]}" -check-ledger
prepare_args=(-prepare-enrollment)
if [[ $preserve == false ]]; then
  prepare_args+=(-allow-new-ledger)
fi
runuser -u mcui-agent -- env "MCUI_AGENT_STATE=$agent_state/identity.json" "$agent" "${agent_args[@]}" "${prepare_args[@]}"

if [[ -d $stage/xray-bootstrap ]]; then
  # This profile is part of the same SHA-256 verified installer archive.
  source "$stage/xray-bootstrap/install.sh"
  install_xray_bootstrap
fi
runtime_profile=
runtime_config=/etc/mcui-runtime
if [[ -d $stage/runtime-bootstrap && $preserve == false ]]; then
  runtime_profile=$stage/runtime-bootstrap
  runtime_binary=$stage/$arch/mcui-runtime
  [[ -x $runtime_binary ]] || die 'Installer is missing the runtime supervisor'
  if file_exists "$runtime_config"; then
    [[ -d $runtime_config && ! -L $runtime_config && $(stat -c '%u:%a' -- "$runtime_config") == 0:700 ]] ||
      die 'Insecure runtime trust directory'
  fi
  for key in release.pub update.pub; do
    if file_exists "$runtime_config/$key"; then
      check_config "$runtime_config/$key"
      cmp -s -- "$runtime_profile/$key" "$runtime_config/$key" || die 'Existing runtime trust differs from the installer'
    fi
  done
  runtime_trust=(-distinct-public-key "$effective_key")
  for key in "$config/xray-install.pub" "$config/release.pub"; do
    if file_exists "$key"; then
      runtime_trust+=(-distinct-public-key "$key")
    fi
  done
  "$runtime_binary" init -node-id "$node_id" -version "$(<"$runtime_profile/version")" \
    -installer-source "$stage/$arch" -release-key "$runtime_profile/release.pub" \
    -update-key "$runtime_profile/update.pub" "${runtime_trust[@]}"
fi

# Redeem only after local prerequisites and both ledgers have been checked.
runuser -u mcui-agent -- env "MCUI_AGENT_STATE=$agent_state/identity.json" "$agent" "${agent_args[@]}" -enroll
restart_agent=false

if [[ $provided_key_id ]]; then
  file_exists "$key_file" || install_trust "$stage/task-signing.pub" "$key_file"
  file_exists "$key_id_file" || install_trust "$stage/task-key-id" "$key_id_file"
  if [[ $provided_ca ]] && ! file_exists "$ca_file"; then
    install_trust "$stage/master-ca.pem" "$ca_file"
  fi
fi

install -o root -g root -m 0755 "$agent" /usr/local/bin/mcui-agent
install -o root -g root -m 0755 "$helper" /usr/local/bin/mcui-helper
install -o root -g root -m 0644 "$stage/units/mcui-agent.service" "$stage/units/mcui-helper.service" /etc/systemd/system/
install -d -o root -g root -m 0755 /etc/systemd/system/mcui-agent.service.d
install -o root -g root -m 0644 "$stage/units/mcui-agent-task-runtime.conf" /etc/systemd/system/mcui-agent.service.d/phase2.conf
printf 'MCUI_MASTER_URL=%s\nMCUI_NODE_ID=%s\nMCUI_SERVER_CA=%s\n' "$master" "$node_id" "$ca_file" >"$stage/agent.env"
printf 'MCUI_TASK_KEY_ID=%s\n' "$key_id" >"$stage/agent-task-runtime.env"
cat "$stage/agent.env" "$stage/agent-task-runtime.env" >"$stage/helper.env"
install -o root -g mcui-agent -m 0640 "$stage/agent.env" "$stage/agent-task-runtime.env" "$stage/helper.env" "$config/"
if [[ $runtime_profile ]]; then
  install -d -o root -g root -m 0700 "$runtime_config"
  install -o root -g root -m 0644 "$runtime_profile/release.pub" "$runtime_profile/update.pub" "$runtime_config/"
  install -o root -g root -m 0755 "$runtime_binary" /usr/local/bin/mcui-runtime
  install -o root -g root -m 0644 "$stage/units/"mcui-runtime-{recover,update,remote}.service \
    "$stage/units/mcui-runtime-remote.timer" /etc/systemd/system/
  install -d -o root -g root -m 0755 /etc/systemd/system/mcui-helper.service.d
  install -o root -g root -m 0644 "$stage/units/mcui-agent-paired-runtime.conf" /etc/systemd/system/mcui-agent.service.d/zz-paired-runtime.conf
  install -o root -g root -m 0644 "$stage/units/mcui-helper-paired-runtime.conf" /etc/systemd/system/mcui-helper.service.d/zz-paired-runtime.conf
fi
systemctl daemon-reload
systemctl enable mcui-helper.service mcui-agent.service
systemctl restart mcui-helper.service mcui-agent.service
printf 'MCUI Agent enrolled for %s\n' "$node_id"
exit 0
__MCUI_ARCHIVE__
