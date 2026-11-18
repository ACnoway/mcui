#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }

master=
node_id=
preserve=false
while (($#)); do
  case "$1" in
    --master) (($# >= 2)) || die 'Missing Master address'; master=$2; shift 2 ;;
    --node-id) (($# >= 2)) || die 'Missing node ID'; node_id=$2; shift 2 ;;
    --preserve-state) preserve=true; shift ;;
    *) die 'Unknown installer option' ;;
  esac
done

[[ $(id -u) == 0 ]] || die 'Run the verified installer with sudo'
[[ $master == https://* && ! $master =~ [[:space:]] ]] || die 'Invalid Master origin'
[[ $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die 'Invalid node ID'
[[ $(uname -s) == Linux ]] || die 'Linux with systemd is required'
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) die 'Unsupported Linux architecture' ;;
esac
for tool in systemctl runuser groupadd useradd getent install flock stat awk tar tail; do
  command -v "$tool" >/dev/null || die "Missing required command: $tool"
done
systemctl show --property=Version --value >/dev/null || die 'A running systemd instance is required'
[[ -r /etc/ssl/certs/ca-certificates.crt ]] || die 'Install ca-certificates first'

exec 9>/run/mcui-agent-install.lock
flock -n 9 || die 'Another Agent installation is in progress'

config=/etc/mcui-agent
agent_state=/var/lib/mcui-agent
helper_state=/var/lib/mcui-helper
key_file=$config/task-signing.pub
ca_file=
check_config() {
  local mode
  [[ -f $1 && ! -L $1 ]] || die "Missing or invalid trusted configuration: $1"
  mode=$(stat -c '%u:%a' -- "$1")
  [[ $mode == 0:644 || $mode == 0:640 || $mode == 0:600 ]] || die "Insecure trusted configuration: $1"
}
[[ -d $config && ! -L $config ]] || die "Provision trusted configuration in $config"
config_mode=$(stat -c '%u:%a' -- "$config")
[[ $config_mode == 0:755 || $config_mode == 0:750 ]] || die 'Insecure Agent configuration directory'
check_config "$key_file"
check_config "$config/task-key-id"
key_id=$(<"$config/task-key-id")
[[ $key_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || die 'Invalid task signing key ID'
if [[ -e $config/master-ca.pem || -L $config/master-ca.pem ]]; then
  ca_file=$config/master-ca.pem
  check_config "$ca_file"
fi

stage=$(mktemp -d /var/tmp/mcui-install.XXXXXXXX)
restart_agent=false
cleanup() {
  local result=$?
  if [[ $restart_agent == true && $result != 0 ]]; then
    systemctl start mcui-agent.service >/dev/null 2>&1 || true
  fi
  rm -rf -- "$stage"
}
trap cleanup EXIT
archive_line=$(awk '/^__MCUI_ARCHIVE__$/ { print NR + 1; exit }' "$0")
[[ $archive_line ]] || die 'Installer archive is missing'
tail -n "+$archive_line" "$0" | tar -xz -C "$stage"
# The service account needs read/execute access to the staged Agent for preflight.
chmod 0755 "$stage"
agent=$stage/$arch/mcui-agent
helper=$stage/$arch/mcui-helper
[[ -x $agent && -x $helper ]] || die 'Installer is missing the required binaries'
chmod 0755 "$stage/$arch" "$agent"

getent group mcui-agent >/dev/null || groupadd --system mcui-agent
id mcui-agent >/dev/null 2>&1 || useradd --system --gid mcui-agent --no-create-home --home-dir "$agent_state" --shell /usr/sbin/nologin mcui-agent
[[ $(id -u mcui-agent) != 0 && $(id -gn mcui-agent) == mcui-agent ]] || die 'Invalid existing Agent account'
runuser -u mcui-agent -- test -r "$key_file" || die 'The Agent cannot read the task signing public key'
if [[ $ca_file ]]; then
  runuser -u mcui-agent -- test -r "$ca_file" || die 'The Agent cannot read the private Master CA'
fi

if [[ $preserve == true ]]; then
  [[ -f $agent_state/tasks.db && -f $helper_state/ledger.json ]] || die 'Existing task state is missing. Restore or reconcile both ledgers before enrolling.'
fi
[[ ! -L $agent_state && ! -L $helper_state ]] || die 'State directories may not be symlinks'
[[ -d $agent_state ]] || install -d -o mcui-agent -g mcui-agent -m 0700 "$agent_state"
[[ -d $helper_state ]] || install -d -o root -g mcui-agent -m 0700 "$helper_state"

agent_args=(-master "$master" -node-id "$node_id" "-server-ca=$ca_file")
helper_args=(-master "$master" -node-id "$node_id" "-master-ca=$ca_file" -task-key-id "$key_id" -task-public-key "$key_file")
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

# Redeem only after local prerequisites and both ledgers have been checked.
runuser -u mcui-agent -- env "MCUI_AGENT_STATE=$agent_state/identity.json" "$agent" "${agent_args[@]}" -enroll
restart_agent=false

install -o root -g root -m 0755 "$agent" /usr/local/bin/mcui-agent
install -o root -g root -m 0755 "$helper" /usr/local/bin/mcui-helper
install -o root -g root -m 0644 "$stage/units/mcui-agent.service" "$stage/units/mcui-helper.service" /etc/systemd/system/
install -d -o root -g root -m 0755 /etc/systemd/system/mcui-agent.service.d
install -o root -g root -m 0644 "$stage/units/mcui-agent-task-runtime.conf" /etc/systemd/system/mcui-agent.service.d/phase2.conf
printf 'MCUI_MASTER_URL=%s\nMCUI_NODE_ID=%s\nMCUI_SERVER_CA=%s\n' "$master" "$node_id" "$ca_file" >"$stage/agent.env"
printf 'MCUI_TASK_KEY_ID=%s\n' "$key_id" >"$stage/agent-task-runtime.env"
cat "$stage/agent.env" "$stage/agent-task-runtime.env" >"$stage/helper.env"
install -o root -g mcui-agent -m 0640 "$stage/agent.env" "$stage/agent-task-runtime.env" "$stage/helper.env" "$config/"
systemctl daemon-reload
systemctl enable mcui-helper.service mcui-agent.service
systemctl restart mcui-helper.service mcui-agent.service
printf 'MCUI Agent enrolled for %s\n' "$node_id"
exit 0
__MCUI_ARCHIVE__
