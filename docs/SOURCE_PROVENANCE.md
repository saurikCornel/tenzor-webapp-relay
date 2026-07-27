# Extraction provenance

The initial data-plane implementation was copied, not removed, from:

- repository: `tenzor-relay`;
- source file: `crates/tenzor-relay/src/cornel_web_gateway.rs`;
- source commit: `f8c60d27bf07b9edbafc2b2ff269e567e583308b`;
- protocol: `cornel-web-gateway-connect-v1`.

The standalone changes are limited to binary/config/operational naming and
deployment packaging. `tenzor-relay` is intentionally left unchanged so the
migration can be reviewed and rolled out independently.
