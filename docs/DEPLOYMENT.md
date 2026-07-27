# Deployment

## Host boundary

Use a WebApp-only VPS/public IP. Do not place the main website, API, VPN ingress
or a generic outbound proxy on it. Permit public TCP 443 only; keep metrics on
loopback. Install `nftables`, systemd, CA certificates and curl.

## Configuration

Copy `configs/webapp-relay.example.env` outside the checkout, replace every
placeholder, and provision certificate/key/HMAC files under
`/etc/tenzor-webapp-relay`. Values are plain `KEY=value` without shell syntax.
The deploy script never uploads this file or its referenced secrets.

For a dedicated IP the Rust process may own public `:443`. If Nginx must retain
the public socket, set `LISTEN_BIND=127.0.0.1:9443` and adapt the provided
top-level `stream` configuration. Nginx must pass raw TLS and must not send
PROXY protocol.

## Install and deploy

Provision a non-secret, root-owned host marker once from the provider console.
The installer never creates this marker, and refuses to mutate systemd,
nftables or `/etc` unless its value authorizes the configured dedicated IPv4:

```bash
sudo install -d -m 0755 /etc/tenzor-webapp-relay
printf '%s\n' 'tenzor-webapp-relay:<dedicated-public-ip>' | \
  sudo tee /etc/tenzor-webapp-relay/dedicated-host >/dev/null
sudo chown root:root /etc/tenzor-webapp-relay/dedicated-host
sudo chmod 0644 /etc/tenzor-webapp-relay/dedicated-host
```

```bash
./scripts/build-release.sh
sudo TENZOR_WEBAPP_RELAY_BINARY=dist/tenzor-webapp-relay \
  TENZOR_WEBAPP_RELAY_ENV_FILE=/secure/path/relay.env \
  ./scripts/install.sh
```

Remote deployment uses an already provisioned target config:

```bash
TENZOR_WEBAPP_RELAY_SSH_TARGET=user@webapp-vps \
TENZOR_WEBAPP_RELAY_REMOTE_ENV_FILE=/etc/tenzor-webapp-relay/relay.env \
  ./scripts/deploy.sh
```

The installer validates the full Rust config, materializes the deny list into
nftables, installs a content-addressed binary, starts the guard before the
relay, and requires `/readyz` to become healthy. It refuses a non-symlink at
the managed binary path and keeps older content-addressed binaries for manual
rollback.

## Runtime checks

```bash
curl --fail http://127.0.0.1:9800/healthz
curl --fail http://127.0.0.1:9800/readyz
curl --fail http://127.0.0.1:9800/metrics
systemctl status tenzor-webapp-relay.service
systemctl status tenzor-webapp-relay-egress-guard.service
nft list table inet tenzor_webapp_relay_guard
```

Run `tests/test-egress-guard-netns.sh` as root on a disposable Linux CI host to
verify UID/source isolation. It creates and removes only temporary namespaces.
