# Architecture and isolation boundary

The WebApp relay is a dedicated data-plane service on a dedicated public
identity. It is not a reverse proxy for the product website or API.

```text
mobile client ── TLS CONNECT + short token ──> WebApp relay ── TLS bytes ──> allowed app origin
                         ^
                         └── token was issued earlier by the control plane
```

The relay has no control-plane URL or credential and performs no callback while
accepting or serving a tunnel. The only shared contract is the HMAC token format.
Current and optional previous verification keys are provisioned as local files.

Isolation is enforced twice:

1. Rust rejects protected suffixes/IPs, unsafe DNS answers, unscoped hosts and
   disallowed destination ports before dialing.
2. nftables rejects every new connection to protected infrastructure from both
   the service UID and dedicated public source IP. Established reply-direction
   packets are allowed so an intentional inbound health/policy probe can receive
   a response; that exception cannot authorize a relay-originated connection.

A data-plane failure therefore affects WebApps only. Main website, API and VPN
ingress must live outside this host/IP and must never be routed through this
service or its Nginx stream listener.
