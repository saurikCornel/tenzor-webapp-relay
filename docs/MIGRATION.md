# Migration from tenzor-relay

The extraction source is the former `--web-gateway-only` entrypoint. The wire
protocol, token validation, destination policy and metrics contract are kept.

Rename each `TENZOR_RELAY_WEB_GATEWAY_<NAME>` setting to
`TENZOR_WEBAPP_RELAY_<NAME>`, install the new service and verify its kernel
guard/readiness before disabling the legacy Web Gateway unit. Do not run both
listeners on the same public or loopback socket. Roll back by restoring the
legacy listener only after stopping the standalone service; never merge it
back into the ordinary relay process.
