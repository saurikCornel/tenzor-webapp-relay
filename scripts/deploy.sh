#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${TENZOR_WEBAPP_RELAY_SSH_TARGET:-}"
binary="${TENZOR_WEBAPP_RELAY_BINARY:-${repo_root}/dist/tenzor-webapp-relay}"
remote_env="${TENZOR_WEBAPP_RELAY_REMOTE_ENV_FILE:-/etc/tenzor-webapp-relay/relay.env}"
ssh_port="${TENZOR_WEBAPP_RELAY_SSH_PORT:-22}"
identity="${TENZOR_WEBAPP_RELAY_SSH_IDENTITY:-}"

[[ -n "${target}" ]] || {
  echo "error: TENZOR_WEBAPP_RELAY_SSH_TARGET is required" >&2
  exit 1
}
[[ -x "${binary}" ]] || {
  echo "error: release binary not found: ${binary}" >&2
  exit 1
}
[[ "${remote_env}" =~ ^/[A-Za-z0-9_./-]+$ ]] || {
  echo "error: remote environment-file path contains unsupported characters" >&2
  exit 1
}
[[ "${ssh_port}" =~ ^[1-9][0-9]{0,4}$ ]] && ((10#${ssh_port} <= 65535)) || {
  echo "error: invalid SSH port" >&2
  exit 1
}

ssh_options=(-p "${ssh_port}" -o BatchMode=yes -o StrictHostKeyChecking=yes)
scp_options=(-P "${ssh_port}" -o BatchMode=yes -o StrictHostKeyChecking=yes)
if [[ -n "${identity}" ]]; then
  ssh_options+=(-i "${identity}")
  scp_options+=(-i "${identity}")
fi

stage="/tmp/tenzor-webapp-relay-deploy-${RANDOM}-${RANDOM}"
cleanup() {
  ssh "${ssh_options[@]}" "${target}" "rm -rf -- '${stage}'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ssh "${ssh_options[@]}" "${target}" "install -d -m 0700 '${stage}/packaging/systemd' '${stage}/packaging/nftables'"
scp "${scp_options[@]}" \
  "${binary}" \
  "${repo_root}/scripts/install.sh" \
  "${target}:${stage}/"
scp "${scp_options[@]}" \
  "${repo_root}/packaging/systemd/tenzor-webapp-relay.service" \
  "${repo_root}/packaging/systemd/tenzor-webapp-relay-egress-guard.service" \
  "${target}:${stage}/packaging/systemd/"
scp "${scp_options[@]}" \
  "${repo_root}/packaging/nftables/egress-guard.nft.in" \
  "${target}:${stage}/packaging/nftables/"

ssh "${ssh_options[@]}" "${target}" \
  "sudo -n env TENZOR_WEBAPP_RELAY_BINARY='${stage}/tenzor-webapp-relay' TENZOR_WEBAPP_RELAY_ENV_FILE='${remote_env}' bash '${stage}/install.sh'"
echo "deployment complete: ${target}"
