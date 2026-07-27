# Tenzor WebApp Relay

Standalone, fail-closed data plane for Tenzor WebApps. It accepts authenticated
TLS HTTP/1.1 `CONNECT` tunnels, validates a short-lived signed destination
scope, resolves DNS on the relay, and proxies raw TCP only to an allowed public
destination.

This repository deliberately contains no VPN/TUN mode, ordinary relay/gate
logic, database, admin API, billing code, client inventory or main-service
credentials. The process never calls the control plane. A host-level nftables
guard independently blocks new connections from the relay identity to every
protected WebApp/control IP.

## Repository layout

- `src/`: the single-purpose Rust data plane and CLI;
- `configs/`: placeholder-only environment example;
- `packaging/`: systemd, nftables, and optional Nginx stream front-end assets;
- `scripts/`: build, install, deploy, and certificate-rotation helpers;
- `tests/`: rootless packaging checks and a Linux network-namespace guard test;
- `docs/`: protocol, security, architecture, deployment and migration notes.

## Local verification

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
TENZOR_WEBAPP_RELAY_TEST_BINARY=target/debug/tenzor-webapp-relay \
  ./tests/test-packaging.sh
```

Build a deployable binary with `./scripts/build-release.sh`. Deployment requires
a preprovisioned environment file and secrets on the target host; neither the
installer nor deploy script transports private material.
Full installation also requires a preprovisioned root-owned dedicated-host
marker bound to the relay IPv4, preventing accidental execution on a main host.

See [architecture](docs/ARCHITECTURE.md), [deployment](docs/DEPLOYMENT.md),
[security](docs/SECURITY.md), and [protocol](docs/PROTOCOL.md).
