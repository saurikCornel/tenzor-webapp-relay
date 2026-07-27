# Security contract

The relay is an authenticated, destination-scoped CONNECT proxy, not an open
proxy. Its required controls are:

- explicit dedicated public IPv4 identity and source-bound outbound sockets;
- strict TLS and HTTP/1.1 parsing with bounded handshake/header timeouts;
- short HMAC token lifetime, exact audience/region, per-subject and per-token
  concurrency ceilings;
- exact/wildcard destination scope plus a destination-port allowlist;
- absolute DNS lookup, bounded answer count, whole-answer safety validation,
  and dialing the already validated socket address;
- rejection of local/private/reserved/multicast/documentation address ranges;
- byte, idle, token-expiry, task, file-descriptor and memory bounds;
- loopback-only health/metrics with label-free aggregate counters;
- mandatory nftables guard for protected infrastructure and self-recursion.

The deployment environment must include the relay's own IPv4 and every control
or product infrastructure IPv4 in `DENY_IPS`. The installer requires at least
two public entries and refuses to start without an active guard. No application
allowlist or token issuer logic belongs in this repository.
