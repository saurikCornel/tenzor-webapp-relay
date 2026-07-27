# Agent Guide: Tenzor WebApp Relay

This repository owns only the isolated WebApps HTTPS CONNECT data plane.

## Required boundaries

- Keep the binary independent from the VPN/TUN relay, gate routing, databases,
  billing, admin UI and client selection logic.
- Keep the wire token compatible with the issuer and mobile client. Coordinate
  intentional protocol changes with `tenzor-server` and `tenzor-client`.
- Never add synchronous calls from this process to the main API. Configuration,
  certificates and HMAC verification keys are preprovisioned locally.
- Keep destination validation, DNS pinning, bounded resources and the kernel
  egress guard fail-closed.
- Do not commit production domains/IPs, passwords, tokens, private keys, SSH
  material or populated `.env` files.
- Preserve health/readiness/metrics endpoints and Linux packaging tests.

## Verification

Run `cargo fmt --check`, `cargo test --locked`, `cargo clippy --all-targets
--locked -- -D warnings`, and `tests/test-packaging.sh`. The network-namespace
guard test is Linux/root-only and must skip cleanly elsewhere.
