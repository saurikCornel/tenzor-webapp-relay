# CONNECT protocol

Protocol identifier: `cornel-web-gateway-connect-v1`.

The client opens TLS 1.2 or TLS 1.3 and sends strict HTTP/1.1:

```text
CONNECT app.example:443 HTTP/1.1
Host: app.example:443
Proxy-Authorization: Basic <base64(cornel:token)>
```

A token is `cwg1.<canonical-base64url-payload>.<canonical-base64url-HMAC>`.
The HMAC is SHA-256 over ASCII `cwg1.<payload>`. The exact JSON claim set is:

```json
{"v":1,"aud":"<relay-id>","sub":"<pseudonym>","jti":"<16-byte-id>","iat":0,"exp":0,"region":"<region>","app":"<app-id>","dst":["exact.example","*.example"]}
```

Unknown/missing claims, noncanonical encodings, future-issued/expired/overlong
tokens, wrong audience/region, duplicate/invalid scopes and unscoped CONNECT
authorities are rejected. Credentials and destination names are never logged.
The wire format is unchanged from the extracted v1 implementation.
