#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${TENZOR_WEBAPP_RELAY_TEST_BINARY:-${repo_root}/target/debug/tenzor-webapp-relay}"

for script in "${repo_root}"/scripts/*.sh "${repo_root}"/tests/*.sh; do
  bash -n "${script}"
done

for required in \
  'Requires=tenzor-webapp-relay-egress-guard.service' \
  'ct direction reply ct state established,related ip daddr @protected_ipv4 counter accept' \
  'meta skuid @SERVICE_UID@ ip daddr @protected_ipv4' \
  'ip saddr @GATEWAY_IPV4@ ip daddr @protected_ipv4' \
  'tenzor-webapp-relay:${gateway_ip}' \
  'TENZOR_WEBAPP_RELAY_EXPECTED_DNS_NAME' \
  '-checkhost "${expected_dns_name}"' \
  '"${versioned_binary}" --check-config'; do
  grep -R -Fq "${required}" "${repo_root}/packaging" "${repo_root}/scripts" || {
    echo "error: missing packaging safety contract: ${required}" >&2
    exit 1
  }
done

if grep -R -E \
  'TENZOR_RELAY_(MODE|TRUSTTUNNEL|GATE_MODE|X25519)|185\.250\.46\.114|cornel\.pro' \
  "${repo_root}/src" "${repo_root}/scripts" "${repo_root}/packaging" \
  "${repo_root}/configs" "${repo_root}/docs" 2>/dev/null; then
  echo "error: ordinary VPN mode or production infrastructure leaked into standalone repo" >&2
  exit 1
fi

[[ -x "${binary}" ]] || {
  echo "error: build the debug binary before running packaging tests" >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  echo "packaging config test: SKIP (openssl unavailable)"
  exit 0
}

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "${tmp_dir}"
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=gateway.example.com' \
  -keyout "${tmp_dir}/privkey.pem" \
  -out "${tmp_dir}/fullchain.pem" >/dev/null 2>&1
printf '%s' '0123456789abcdef0123456789abcdef' >"${tmp_dir}/hmac"

env_file="${tmp_dir}/relay.env"
cat >"${env_file}" <<EOF
TENZOR_WEBAPP_RELAY_BIND=93.184.216.34:443
TENZOR_WEBAPP_RELAY_LISTEN_BIND=127.0.0.1:19443
TENZOR_WEBAPP_RELAY_METRICS_BIND=127.0.0.1:19800
TENZOR_WEBAPP_RELAY_CERT_PEM=${tmp_dir}/fullchain.pem
TENZOR_WEBAPP_RELAY_KEY_PEM=${tmp_dir}/privkey.pem
TENZOR_WEBAPP_RELAY_ID=web-eu-test-1
TENZOR_WEBAPP_RELAY_REGION=eu
TENZOR_WEBAPP_RELAY_DIAGNOSTICS_HOST=canary.example.net
TENZOR_WEBAPP_RELAY_DENY_HOST_SUFFIXES=gateway.example.com,control.example.com
TENZOR_WEBAPP_RELAY_DENY_IPS=93.184.216.34,1.1.1.1
TENZOR_WEBAPP_RELAY_HMAC_SECRET_FILE=${tmp_dir}/hmac
TENZOR_WEBAPP_RELAY_ALLOWED_PORTS=443
EOF

TENZOR_WEBAPP_RELAY_BINARY="${binary}" \
TENZOR_WEBAPP_RELAY_ENV_FILE="${env_file}" \
  bash "${repo_root}/scripts/install.sh" --check >/dev/null

sed 's/93\.184\.216\.34,1\.1\.1\.1/8.8.8.8,1.1.1.1/' \
  "${env_file}" >"${tmp_dir}/missing-own.env"
if TENZOR_WEBAPP_RELAY_BINARY="${binary}" \
  TENZOR_WEBAPP_RELAY_ENV_FILE="${tmp_dir}/missing-own.env" \
  bash "${repo_root}/scripts/install.sh" --check >/dev/null 2>&1; then
  echo "error: installer accepted DENY_IPS without the relay public IPv4" >&2
  exit 1
fi

cp "${env_file}" "${tmp_dir}/vpn-coupled.env"
printf '%s\n' 'TENZOR_RELAY_MODE=tun-auto' >>"${tmp_dir}/vpn-coupled.env"
if TENZOR_WEBAPP_RELAY_BINARY="${binary}" \
  TENZOR_WEBAPP_RELAY_ENV_FILE="${tmp_dir}/vpn-coupled.env" \
  bash "${repo_root}/scripts/install.sh" --check >/dev/null 2>&1; then
  echo "error: installer accepted an ordinary VPN relay setting" >&2
  exit 1
fi

echo "packaging and config validation: ok"
