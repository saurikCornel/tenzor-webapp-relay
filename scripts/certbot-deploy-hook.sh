#!/usr/bin/env bash
set -euo pipefail

source_dir="${RENEWED_LINEAGE:-${TENZOR_WEBAPP_RELAY_CERT_SOURCE_DIR:-}}"
target_dir="${TENZOR_WEBAPP_RELAY_CERT_TARGET_DIR:-/etc/tenzor-webapp-relay/tls}"
service="${TENZOR_WEBAPP_RELAY_SERVICE:-tenzor-webapp-relay.service}"
service_group="${TENZOR_WEBAPP_RELAY_SERVICE_GROUP:-tenzor-webapp-relay}"
metrics_bind="${TENZOR_WEBAPP_RELAY_METRICS_BIND:-127.0.0.1:9800}"
expected_dns_name="${TENZOR_WEBAPP_RELAY_EXPECTED_DNS_NAME:-}"

[[ -n "${source_dir}" ]] || {
  echo "error: RENEWED_LINEAGE or TENZOR_WEBAPP_RELAY_CERT_SOURCE_DIR is required" >&2
  exit 1
}
[[ "${expected_dns_name}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || {
  echo "error: TENZOR_WEBAPP_RELAY_EXPECTED_DNS_NAME is required" >&2
  exit 1
}
for command in curl install mktemp openssl sha256sum systemctl; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: missing required command: ${command}" >&2
    exit 1
  }
done
[[ -s "${source_dir}/fullchain.pem" && -s "${source_dir}/privkey.pem" ]] || {
  echo "error: renewed certificate or key is missing" >&2
  exit 1
}
openssl x509 -in "${source_dir}/fullchain.pem" -checkend 3600 -noout >/dev/null || {
  echo "error: renewed certificate is already expired or expires within one hour" >&2
  exit 1
}
if ! openssl x509 -in "${source_dir}/fullchain.pem" \
  -checkhost "${expected_dns_name}" -noout >/dev/null 2>&1; then
  echo "certificate rotation skipped: lineage does not cover ${expected_dns_name}"
  exit 0
fi

certificate_key_hash="$({ openssl x509 -in "${source_dir}/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER; } | sha256sum | awk '{print $1}')"
private_key_hash="$(openssl pkey -in "${source_dir}/privkey.pem" -pubout -outform DER | sha256sum | awk '{print $1}')"
[[ "${certificate_key_hash}" == "${private_key_hash}" ]] || {
  echo "error: renewed certificate and private key do not match" >&2
  exit 1
}

install -d -m 0750 -o root -g "${service_group}" "${target_dir}"
rotation_dir="$(mktemp -d "${target_dir}/.rotation.XXXXXX")"
had_previous=0
cleanup() {
  rm -rf -- "${rotation_dir}"
}
trap cleanup EXIT
if [[ -s "${target_dir}/fullchain.pem" && -s "${target_dir}/privkey.pem" ]]; then
  install -m 0600 "${target_dir}/fullchain.pem" "${rotation_dir}/fullchain.previous"
  install -m 0600 "${target_dir}/privkey.pem" "${rotation_dir}/privkey.previous"
  had_previous=1
fi
install -m 0640 -o root -g "${service_group}" \
  "${source_dir}/fullchain.pem" "${target_dir}/fullchain.pem.new"
install -m 0640 -o root -g "${service_group}" \
  "${source_dir}/privkey.pem" "${target_dir}/privkey.pem.new"
mv -f "${target_dir}/fullchain.pem.new" "${target_dir}/fullchain.pem"
mv -f "${target_dir}/privkey.pem.new" "${target_dir}/privkey.pem"

systemctl restart "${service}"
for _ in $(seq 1 40); do
  if curl --noproxy '*' --fail --silent --show-error --max-time 2 \
    "http://${metrics_bind}/readyz" >/dev/null; then
    echo "certificate rotation complete; relay readiness: ok"
    exit 0
  fi
  sleep 0.25
done
if ((had_previous)); then
  install -m 0640 -o root -g "${service_group}" \
    "${rotation_dir}/fullchain.previous" "${target_dir}/fullchain.pem.new"
  install -m 0640 -o root -g "${service_group}" \
    "${rotation_dir}/privkey.previous" "${target_dir}/privkey.pem.new"
  mv -f "${target_dir}/fullchain.pem.new" "${target_dir}/fullchain.pem"
  mv -f "${target_dir}/privkey.pem.new" "${target_dir}/privkey.pem"
  systemctl restart "${service}" >/dev/null 2>&1 || true
  echo "error: relay did not become ready; previous certificate pair restored" >&2
else
  echo "error: relay did not become ready after initial certificate install" >&2
fi
exit 1
