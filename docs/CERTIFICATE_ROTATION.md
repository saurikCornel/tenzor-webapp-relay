# TLS certificate rotation

The relay reads its certificate and private key at process startup. Use the
provided Certbot deploy hook to validate the expected DNS name and renewed key
pair, atomically copy it into the service-owned TLS directory, restart only the WebApp relay, and
verify readiness. If readiness fails, the hook restores the previous certificate
pair and restarts the service again:

```bash
install -m 0755 scripts/certbot-deploy-hook.sh \
  /usr/local/libexec/tenzor-webapp-relay-certbot-hook
cat >/etc/letsencrypt/renewal-hooks/deploy/tenzor-webapp-relay <<'EOF'
#!/bin/sh
export TENZOR_WEBAPP_RELAY_EXPECTED_DNS_NAME='<gateway-dns-name>'
exec /usr/local/libexec/tenzor-webapp-relay-certbot-hook
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/tenzor-webapp-relay
```

The hook consumes Certbot's `RENEWED_LINEAGE`. A host may contain unrelated
lineages; only a certificate covering `TENZOR_WEBAPP_RELAY_EXPECTED_DNS_NAME`
is installed. For another ACME client set `TENZOR_WEBAPP_RELAY_CERT_SOURCE_DIR`.
A renewal never restarts the main API, website, VPN service or host Nginx; raw
Nginx stream pass-through does not need a certificate reload.

HMAC keys rotate independently: configure the old key as
`HMAC_PREVIOUS_SECRET_FILE`, replace the current issuer/relay key, restart,
wait longer than the maximum token lifetime, then remove the previous key and
restart again.
