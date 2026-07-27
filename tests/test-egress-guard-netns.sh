#!/usr/bin/env bash
set -euo pipefail

test_name="webapp-relay-egress-guard-netns"

skip() {
  echo "${test_name}: SKIP: $*"
  exit 0
}

fail() {
  echo "${test_name}: FAIL: $*" >&2
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  skip "requires Linux network namespaces"
fi

if ((EUID != 0)); then
  skip "requires root (CAP_NET_ADMIN)"
fi

for required_command in ip nft python3 setpriv; do
  command -v "${required_command}" >/dev/null 2>&1 ||
    skip "missing required command: ${required_command}"
done

dedicated_uid="${TENZOR_WEBAPP_RELAY_GUARD_TEST_UID:-42424}"
if [[ ! "${dedicated_uid}" =~ ^[1-9][0-9]*$ ]] || ((dedicated_uid > 4294967294)); then
  fail "TENZOR_WEBAPP_RELAY_GUARD_TEST_UID must be a non-root numeric UID"
fi

# RFC 2544 benchmarking addresses cannot collide with production routes. Both
# namespaces and the nft table are deleted by cleanup, even after a failed test.
origin_ip="198.18.0.1"
gateway_source_ip="198.18.0.2"
control_source_ip="198.18.0.3"
origin_port="18443"
reply_port="18444"
suffix="${BASHPID}-${RANDOM}"
guard_ns="twg-guard-${suffix}"
origin_ns="twg-origin-${suffix}"
guard_if="twgg${RANDOM}"
origin_if="twgo${RANDOM}"
tmp_dir="$(mktemp -d)"
ready_file="${tmp_dir}/origin.ready"
server_log="${tmp_dir}/origin.log"
server_pid=""
reply_ready_file="${tmp_dir}/reply.ready"
reply_server_log="${tmp_dir}/reply.log"
reply_server_pid=""
guard_ns_created=0
origin_ns_created=0

cleanup() {
  set +e
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill "${server_pid}" 2>/dev/null
    wait "${server_pid}" 2>/dev/null
  fi
  if [[ -n "${reply_server_pid}" ]] && kill -0 "${reply_server_pid}" 2>/dev/null; then
    kill "${reply_server_pid}" 2>/dev/null
    wait "${reply_server_pid}" 2>/dev/null
  fi
  if ((guard_ns_created)); then
    ip netns delete "${guard_ns}" >/dev/null 2>&1
  fi
  if ((origin_ns_created)); then
    ip netns delete "${origin_ns}" >/dev/null 2>&1
  fi
  rm -rf -- "${tmp_dir}"
}
trap cleanup EXIT

netns_error="${tmp_dir}/netns.error"
if ! ip netns add "${guard_ns}" 2>"${netns_error}"; then
  skip "network namespaces unavailable: $(tr '\n' ' ' <"${netns_error}")"
fi
guard_ns_created=1
if ! ip netns add "${origin_ns}" 2>"${netns_error}"; then
  skip "network namespaces unavailable: $(tr '\n' ' ' <"${netns_error}")"
fi
origin_ns_created=1

# Keep every interface and address inside the two temporary namespaces. The
# control address deliberately differs from the WebApp relay source address so
# the test can prove that unrelated control-plane traffic remains reachable.
ip link add "${guard_if}" type veth peer name "${origin_if}"
ip link set "${guard_if}" netns "${guard_ns}"
ip link set "${origin_if}" netns "${origin_ns}"
ip -n "${guard_ns}" link set lo up
ip -n "${origin_ns}" link set lo up
ip -n "${guard_ns}" address add "${gateway_source_ip}/24" dev "${guard_if}"
ip -n "${guard_ns}" address add "${control_source_ip}/24" dev "${guard_if}"
ip -n "${origin_ns}" address add "${origin_ip}/24" dev "${origin_if}"
ip -n "${guard_ns}" link set "${guard_if}" up
ip -n "${origin_ns}" link set "${origin_if}" up

if ! ip netns exec "${guard_ns}" nft -f - <<NFT
table inet tenzor_webapp_relay_guard_test {
  set protected_ipv4 {
    type ipv4_addr
    flags interval
    elements = { ${origin_ip} }
  }

  chain output {
    type filter hook output priority -151; policy accept;
    ct direction reply ct state established,related ip daddr @protected_ipv4 counter accept comment "established-reply-allowed"
    meta skuid ${dedicated_uid} ip daddr @protected_ipv4 meta l4proto tcp counter reject with tcp reset comment "dedicated-uid-denied"
    ip saddr ${gateway_source_ip} ip daddr @protected_ipv4 meta l4proto tcp counter reject with tcp reset comment "gateway-source-denied"
  }
}
NFT
then
  fail "could not install the isolated nft OUTPUT guard"
fi

ip netns exec "${origin_ns}" python3 -u - \
  "${origin_ip}" "${origin_port}" "${ready_file}" >"${server_log}" 2>&1 <<'PY' &
import pathlib
import socket
import sys

host, raw_port, ready_path = sys.argv[1:]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(raw_port)))
    listener.listen(8)
    pathlib.Path(ready_path).write_text("ready\n", encoding="ascii")
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(1.0)
            try:
                connection.recv(64)
            except (TimeoutError, OSError):
                pass
            connection.sendall(b"OK\n")
PY
server_pid="$!"

for _ in $(seq 1 100); do
  [[ -f "${ready_file}" ]] && break
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    cat "${server_log}" >&2
    fail "fake origin exited before becoming ready"
  fi
  sleep 0.02
done
[[ -f "${ready_file}" ]] || fail "fake origin did not become ready"

# A protected origin is allowed to initiate an intentional inbound probe. The
# relay host's response uses the dedicated source and protected destination,
# so it proves the conntrack reply exception without opening NEW egress.
ip netns exec "${guard_ns}" python3 -u - \
  "${gateway_source_ip}" "${reply_port}" "${reply_ready_file}" >"${reply_server_log}" 2>&1 <<'PY' &
import pathlib
import socket
import sys

host, raw_port, ready_path = sys.argv[1:]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(raw_port)))
    listener.listen(1)
    pathlib.Path(ready_path).write_text("ready\n", encoding="ascii")
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(1.0)
        connection.recv(64)
        connection.sendall(b"OK\n")
PY
reply_server_pid="$!"
for _ in $(seq 1 100); do
  [[ -f "${reply_ready_file}" ]] && break
  if ! kill -0 "${reply_server_pid}" 2>/dev/null; then
    cat "${reply_server_log}" >&2
    fail "reply-direction server exited before becoming ready"
  fi
  sleep 0.02
done
[[ -f "${reply_ready_file}" ]] || fail "reply-direction server did not become ready"

client_program=$'import socket, sys\n'\
$'host, raw_port, source = sys.argv[1:]\n'\
$'with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:\n'\
$'    sock.settimeout(1.5)\n'\
$'    sock.bind((source, 0))\n'\
$'    sock.connect((host, int(raw_port)))\n'\
$'    sock.sendall(b"probe\\n")\n'\
$'    if sock.recv(3) != b"OK\\n":\n'\
$'        raise RuntimeError("unexpected fake-origin response")\n'

probe_as_root() {
  local source_ip="$1"
  ip netns exec "${guard_ns}" python3 -c "${client_program}" \
    "${origin_ip}" "${origin_port}" "${source_ip}"
}

probe_as_gateway_uid() {
  local source_ip="$1"
  ip netns exec "${guard_ns}" setpriv \
    --reuid="${dedicated_uid}" \
    --regid="${dedicated_uid}" \
    --clear-groups \
    -- python3 -c "${client_program}" \
    "${origin_ip}" "${origin_port}" "${source_ip}"
}

counter_packets() {
  local marker="$1"
  local listing line packets
  listing="$(ip netns exec "${guard_ns}" nft -nn list chain inet \
    tenzor_webapp_relay_guard_test output)"
  line="$(grep -F "comment \"${marker}\"" <<<"${listing}" || true)"
  packets="$(sed -n 's/.*counter packets \([0-9][0-9]*\) bytes.*/\1/p' <<<"${line}")"
  [[ -n "${packets}" ]] || fail "could not read nft counter ${marker}"
  printf '%s' "${packets}"
}

[[ "$(counter_packets established-reply-allowed)" == "0" ]] ||
  fail "established-reply counter was non-zero before the inbound probe"
ip netns exec "${origin_ns}" python3 -c "${client_program}" \
  "${gateway_source_ip}" "${reply_port}" "${origin_ip}" ||
  fail "protected origin could not receive an established reply"
reply_allowed_packets="$(counter_packets established-reply-allowed)"
((reply_allowed_packets > 0)) || fail "established reply matched no allow rule"

# Establish reachability before treating a failed connection as a successful
# guard test. This socket is neither owned by the dedicated UID nor bound to
# the dedicated source address.
probe_as_root "${control_source_ip}" || fail "ordinary control socket is unreachable"
[[ "$(counter_packets dedicated-uid-denied)" == "0" ]] ||
  fail "UID deny counter changed for an ordinary control socket"
[[ "$(counter_packets gateway-source-denied)" == "0" ]] ||
  fail "source deny counter changed for an ordinary control socket"

if probe_as_gateway_uid "${control_source_ip}" >"${tmp_dir}/uid-probe.log" 2>&1; then
  fail "dedicated WebApp relay UID reached the protected fake origin"
fi
uid_denied_packets="$(counter_packets dedicated-uid-denied)"
((uid_denied_packets > 0)) || fail "UID guard rejected no packets"
[[ "$(counter_packets gateway-source-denied)" == "0" ]] ||
  fail "UID probe unexpectedly matched the dedicated-source rule"

if probe_as_root "${gateway_source_ip}" >"${tmp_dir}/source-probe.log" 2>&1; then
  fail "dedicated WebApp relay source reached the protected fake origin"
fi
source_denied_packets="$(counter_packets gateway-source-denied)"
((source_denied_packets > 0)) || fail "source guard rejected no packets"

uid_before_control="$(counter_packets dedicated-uid-denied)"
source_before_control="$(counter_packets gateway-source-denied)"
probe_as_root "${control_source_ip}" ||
  fail "ordinary control socket became unreachable after denied probes"
[[ "$(counter_packets dedicated-uid-denied)" == "${uid_before_control}" ]] ||
  fail "ordinary control socket changed the UID deny counter"
[[ "$(counter_packets gateway-source-denied)" == "${source_before_control}" ]] ||
  fail "ordinary control socket changed the source deny counter"

echo "${test_name}: UID guard packets=${uid_denied_packets}"
echo "${test_name}: source guard packets=${source_denied_packets}"
echo "${test_name}: established reply packets=${reply_allowed_packets}"
echo "${test_name}: ordinary control socket remained reachable"
echo "${test_name}: ok"
