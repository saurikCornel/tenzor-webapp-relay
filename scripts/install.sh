#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${TENZOR_WEBAPP_RELAY_BINARY:-${repo_root}/target/release/tenzor-webapp-relay}"
config_source="${TENZOR_WEBAPP_RELAY_ENV_FILE:-${repo_root}/configs/webapp-relay.env}"
validate_only=0
service_user="tenzor-webapp-relay"
service_name="tenzor-webapp-relay.service"
guard_name="tenzor-webapp-relay-egress-guard.service"
config_dir="/etc/tenzor-webapp-relay"
installed_env="${config_dir}/relay.env"
installed_binary="/usr/local/bin/tenzor-webapp-relay"
host_marker="${TENZOR_WEBAPP_RELAY_HOST_MARKER:-${config_dir}/dedicated-host}"

usage() {
  cat <<'EOF'
Install the standalone Tenzor WebApp relay on a Linux VPS.

Required inputs:
  TENZOR_WEBAPP_RELAY_BINARY=/path/to/tenzor-webapp-relay
  TENZOR_WEBAPP_RELAY_ENV_FILE=/path/to/relay.env

The environment file is preprovisioned and is never generated from secrets.
Full installation also requires /etc/tenzor-webapp-relay/dedicated-host with
the exact root-owned value tenzor-webapp-relay:<configured-public-ip>.
Use --check for a rootless config/package validation without deployment.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

is_canonical_ipv4() {
  local host="$1" a b c d octet
  [[ "${host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"${host}"
  for octet in "${a}" "${b}" "${c}" "${d}"; do
    [[ "${octet}" == "0" || "${octet}" != 0* ]] || return 1
    ((10#${octet} <= 255)) || return 1
  done
}

is_public_ipv4() {
  local host="$1" a b c d
  is_canonical_ipv4 "${host}" || return 1
  IFS=. read -r a b c d <<<"${host}"
  a=$((10#${a})); b=$((10#${b})); c=$((10#${c}))
  ((a != 0 && a != 10 && a != 127 && a < 224)) || return 1
  ((a != 100 || b < 64 || b > 127)) || return 1
  ((a != 169 || b != 254)) || return 1
  ((a != 172 || b < 16 || b > 31)) || return 1
  ((a != 192 || b != 168)) || return 1
  ((a != 198 || (b != 18 && b != 19))) || return 1
  ((a != 192 || b != 0 || c != 0)) || return 1
  ((a != 192 || b != 88)) || return 1
  ((a != 192 || b != 0 || c != 2)) || return 1
  ((a != 198 || b != 51 || c != 100)) || return 1
  ((a != 203 || b != 0 || c != 113)) || return 1
}

is_known_key() {
  case "$1" in
    TENZOR_WEBAPP_RELAY_BIND | \
      TENZOR_WEBAPP_RELAY_LISTEN_BIND | \
      TENZOR_WEBAPP_RELAY_METRICS_BIND | \
      TENZOR_WEBAPP_RELAY_CERT_PEM | \
      TENZOR_WEBAPP_RELAY_KEY_PEM | \
      TENZOR_WEBAPP_RELAY_ID | \
      TENZOR_WEBAPP_RELAY_REGION | \
      TENZOR_WEBAPP_RELAY_DIAGNOSTICS_HOST | \
      TENZOR_WEBAPP_RELAY_DENY_HOST_SUFFIXES | \
      TENZOR_WEBAPP_RELAY_DENY_IPS | \
      TENZOR_WEBAPP_RELAY_CONTROL_ALLOW_IPV4 | \
      TENZOR_WEBAPP_RELAY_HMAC_SECRET_FILE | \
      TENZOR_WEBAPP_RELAY_HMAC_PREVIOUS_SECRET_FILE | \
      TENZOR_WEBAPP_RELAY_ALLOWED_PORTS | \
      TENZOR_WEBAPP_RELAY_TLS_HANDSHAKE_TIMEOUT_MS | \
      TENZOR_WEBAPP_RELAY_HEADER_TIMEOUT_MS | \
      TENZOR_WEBAPP_RELAY_CONNECT_TIMEOUT_MS | \
      TENZOR_WEBAPP_RELAY_IDLE_TIMEOUT_SECS | \
      TENZOR_WEBAPP_RELAY_MAX_HEADER_BYTES | \
      TENZOR_WEBAPP_RELAY_MAX_TUNNEL_BYTES | \
      TENZOR_WEBAPP_RELAY_MAX_CONCURRENT | \
      TENZOR_WEBAPP_RELAY_MAX_CONCURRENT_PER_SUB | \
      TENZOR_WEBAPP_RELAY_MAX_CONCURRENT_PER_JTI | \
      TENZOR_WEBAPP_RELAY_CLOCK_SKEW_SECS | \
      TENZOR_WEBAPP_RELAY_MAX_TOKEN_LIFETIME_SECS | \
      TENZOR_WEBAPP_RELAY_GRACEFUL_DRAIN_TIMEOUT_SECS) return 0 ;;
    *) return 1 ;;
  esac
}

env_value() {
  local key="$1"
  awk -v wanted="${key}" '
    index($0, wanted "=") == 1 {
      count += 1
      value = substr($0, length(wanted) + 2)
    }
    END {
      if (count == 1) print value
      else if (count > 1) exit 2
    }
  ' "${config_source}"
}

validate_env_file() {
  [[ -f "${config_source}" ]] || fail "environment file not found: ${config_source}"
  local line key value
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    [[ "${line}" =~ ^TENZOR_WEBAPP_RELAY_[A-Z0-9_]+=[^[:space:]]+$ ]] ||
      fail "invalid environment-file line (plain KEY=value only)"
    key="${line%%=*}"
    value="${line#*=}"
    [[ -n "${value}" ]] || fail "${key} must not be empty"
    is_known_key "${key}" || fail "unsupported environment key: ${key}"
  done <"${config_source}"

  local required
  for required in \
    TENZOR_WEBAPP_RELAY_BIND \
    TENZOR_WEBAPP_RELAY_CERT_PEM \
    TENZOR_WEBAPP_RELAY_KEY_PEM \
    TENZOR_WEBAPP_RELAY_ID \
    TENZOR_WEBAPP_RELAY_REGION \
    TENZOR_WEBAPP_RELAY_DIAGNOSTICS_HOST \
    TENZOR_WEBAPP_RELAY_DENY_HOST_SUFFIXES \
    TENZOR_WEBAPP_RELAY_DENY_IPS \
    TENZOR_WEBAPP_RELAY_HMAC_SECRET_FILE; do
    [[ -n "$(env_value "${required}")" ]] || fail "missing required ${required}"
  done
}

collect_config_env() {
  config_env=()
  local line
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    config_env+=("${line}")
  done <"${config_source}"
}

protected_ipv4_elements() {
  local raw="$1" item result="" count=0
  local -a items
  IFS=, read -ra items <<<"${raw}"
  for item in "${items[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -n "${item}" ]] || continue
    is_public_ipv4 "${item}" || fail "DENY_IPS must contain canonical public IPv4 addresses only"
    case ",${result// /}," in
      *,"${item}",*) continue ;;
    esac
    [[ -z "${result}" ]] || result+=", "
    result+="${item}"
    count=$((count + 1))
  done
  ((count >= 2)) || fail "DENY_IPS must protect the relay IP and at least one control/infrastructure IP"
  printf '%s' "${result}"
}

optional_ipv4_elements_line() {
  local raw="$1" item result="" count=0
  local -a items
  IFS=, read -ra items <<<"${raw}"
  for item in "${items[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -n "${item}" ]] || continue
    is_public_ipv4 "${item}" || fail "CONTROL_ALLOW_IPV4 must contain canonical public IPv4 addresses only"
    case ",${result// /}," in
      *,"${item}",*) continue ;;
    esac
    [[ -z "${result}" ]] || result+=", "
    result+="${item}"
    count=$((count + 1))
  done
  if ((count == 0)); then
    printf ''
  else
    printf 'elements = { %s }' "${result}"
  fi
}

run_config_check() {
  collect_config_env
  env -i PATH="${PATH}" "${config_env[@]}" "${binary}" --check-config >/dev/null
}

case "${1:-}" in
  -h | --help) usage; exit 0 ;;
  --check) validate_only=1 ;;
  "") ;;
  *) fail "unknown argument: $1" ;;
esac

[[ -x "${binary}" ]] || fail "executable relay binary not found: ${binary}"
validate_env_file

bind="$(env_value TENZOR_WEBAPP_RELAY_BIND)"
[[ "${bind}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:443$ ]] ||
  fail "BIND must be an explicit public IPv4 on port 443"
gateway_ip="${bind%:443}"
is_public_ipv4 "${gateway_ip}" || fail "BIND must use a canonical public IPv4"
listen_bind="$(env_value TENZOR_WEBAPP_RELAY_LISTEN_BIND)"
if [[ -n "${listen_bind}" ]]; then
  [[ "${listen_bind}" =~ ^127\.0\.0\.1:([0-9]{4,5})$ ]] ||
    fail "LISTEN_BIND must be loopback IPv4 with an unprivileged port"
  ((10#${BASH_REMATCH[1]} >= 1024 && 10#${BASH_REMATCH[1]} <= 65535)) ||
    fail "LISTEN_BIND port is out of range"
fi
metrics_bind="$(env_value TENZOR_WEBAPP_RELAY_METRICS_BIND)"
metrics_bind="${metrics_bind:-127.0.0.1:9800}"
[[ "${metrics_bind}" =~ ^127\.0\.0\.1:[1-9][0-9]{0,4}$ ||
  "${metrics_bind}" =~ ^\[::1\]:[1-9][0-9]{0,4}$ ]] ||
  fail "METRICS_BIND must be a loopback socket"
metrics_port="${metrics_bind##*:}"
metrics_port="${metrics_port%]}"
((10#${metrics_port} <= 65535)) || fail "METRICS_BIND port is out of range"
deny_ips="$(env_value TENZOR_WEBAPP_RELAY_DENY_IPS)"
protected_elements="$(protected_ipv4_elements "${deny_ips}")"
control_allow_elements="$(optional_ipv4_elements_line "$(env_value TENZOR_WEBAPP_RELAY_CONTROL_ALLOW_IPV4)")"
case ",${protected_elements// /}," in
  *,"${gateway_ip}",*) ;;
  *) fail "DENY_IPS must include the relay's own public IPv4 ${gateway_ip}" ;;
esac
run_config_check
echo "config validation: ok"

if ((validate_only)); then
  exit 0
fi

[[ "$(uname -s)" == "Linux" ]] || fail "deployment requires Linux"
((EUID == 0)) || fail "deployment requires root"
for command in awk curl install nft runuser sed sha256sum stat systemctl useradd; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing required command: ${command}"
done

[[ "${host_marker}" =~ ^/[A-Za-z0-9_./-]+$ ]] ||
  fail "dedicated-host marker path contains unsupported characters"
[[ -f "${host_marker}" && ! -L "${host_marker}" ]] ||
  fail "dedicated-host marker is missing or is a symlink: ${host_marker}"
marker_owner="$(stat -c %u "${host_marker}")"
marker_mode="$(stat -c %a "${host_marker}")"
[[ "${marker_owner}" == "0" ]] || fail "dedicated-host marker must be owned by root"
(( (8#${marker_mode} & 8#022) == 0 )) ||
  fail "dedicated-host marker must not be group/world writable"
marker_value="$(<"${host_marker}")"
[[ "${marker_value}" == "tenzor-webapp-relay:${gateway_ip}" ]] ||
  fail "dedicated-host marker does not authorize relay IPv4 ${gateway_ip}"

if ! id -u "${service_user}" >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin "${service_user}"
fi
service_uid="$(id -u "${service_user}")"

install -d -m 0755 "${config_dir}" "${config_dir}/tls" "${config_dir}/secrets"
install -m 0640 -o root -g "${service_user}" "${config_source}" "${installed_env}.new"
mv -f "${installed_env}.new" "${installed_env}"
config_source="${installed_env}"
collect_config_env
for file_key in \
  TENZOR_WEBAPP_RELAY_CERT_PEM \
  TENZOR_WEBAPP_RELAY_KEY_PEM \
  TENZOR_WEBAPP_RELAY_HMAC_SECRET_FILE \
  TENZOR_WEBAPP_RELAY_HMAC_PREVIOUS_SECRET_FILE; do
  file_path="$(env_value "${file_key}")"
  [[ -z "${file_path}" ]] && continue
  runuser -u "${service_user}" -- test -r "${file_path}" ||
    fail "${file_key} is not readable by ${service_user}"
done

digest="$(sha256sum "${binary}" | awk '{print $1}')"
versioned_binary="/usr/local/libexec/tenzor-webapp-relay-${digest:0:12}"
install -d -m 0755 /usr/local/libexec
[[ -e "${versioned_binary}" ]] || install -m 0755 "${binary}" "${versioned_binary}"
runuser -u "${service_user}" -- env -i PATH="${PATH}" "${config_env[@]}" \
  "${versioned_binary}" --check-config >/dev/null
if [[ -e "${installed_binary}" && ! -L "${installed_binary}" ]]; then
  fail "refusing to replace non-symlink ${installed_binary}"
fi
old_target="$(readlink -f "${installed_binary}" 2>/dev/null || true)"
ln -sfn "${versioned_binary}" "${installed_binary}"
activated=1
rollback() {
  local status="${1:-$?}"
  if ((status != 0 && activated)) && [[ -n "${old_target}" && -x "${old_target}" ]]; then
    ln -sfn "${old_target}" "${installed_binary}"
    systemctl restart "${service_name}" >/dev/null 2>&1 || true
  elif ((status != 0 && activated)); then
    systemctl stop "${service_name}" >/dev/null 2>&1 || true
    rm -f "${installed_binary}"
  fi
  exit "${status}"
}
trap 'rollback "$?"' EXIT

guard_tmp="$(mktemp)"
trap 'install_status=$?; rm -f "${guard_tmp}"; rollback "${install_status}"' EXIT
sed \
  -e "s/@SERVICE_UID@/${service_uid}/g" \
  -e "s/@GATEWAY_IPV4@/${gateway_ip}/g" \
  -e "s/@PROTECTED_IPV4@/${protected_elements}/g" \
  -e "s/@CONTROL_ALLOW_IPV4_ELEMENTS@/${control_allow_elements}/g" \
  "${repo_root}/packaging/nftables/egress-guard.nft.in" >"${guard_tmp}"
nft -c -f "${guard_tmp}"
install -m 0644 "${guard_tmp}" "${config_dir}/egress-guard.nft"
rm -f "${guard_tmp}"
install -m 0644 "${repo_root}/packaging/systemd/tenzor-webapp-relay.service" \
  "/etc/systemd/system/${service_name}"
install -m 0644 "${repo_root}/packaging/systemd/tenzor-webapp-relay-egress-guard.service" \
  "/etc/systemd/system/${guard_name}"

systemctl daemon-reload
systemctl enable "${guard_name}" "${service_name}" >/dev/null
systemctl restart "${guard_name}"
systemctl restart "${service_name}"

ready=0
for _ in $(seq 1 40); do
  if curl --noproxy '*' --fail --silent --show-error --max-time 2 \
    "http://${metrics_bind}/readyz" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.25
done
((ready)) || {
  systemctl --no-pager --full status "${service_name}" >&2 || true
  fail "relay readiness did not become healthy"
}
systemctl is-active --quiet "${guard_name}" || fail "kernel egress guard is not active"
# Do not use grep -q with pipefail here: once grep exits on a match, nft can
# receive SIGPIPE and turn a successful guard check into a false failure.
nft list set inet tenzor_webapp_relay_guard protected_ipv4 | grep -F "${gateway_ip}" >/dev/null ||
  fail "kernel egress guard does not protect the relay public IPv4"

activated=0
trap - EXIT
echo "installed ${versioned_binary}; readiness: ok; egress guard: active"
