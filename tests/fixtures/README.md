# TLS fixtures — tests only

`localhost-test-only.crt` and `localhost-test-only.key` are a public, self-signed
certificate and its intentionally disclosed private key for local integration
tests. Never deploy this key or add this certificate to a system trust store.
Tests trust the certificate only in their own Python SSL contexts and child
process `SSL_CERT_FILE` environment.

The certificate covers `localhost` and `127.0.0.1`, uses RSA 2048/SHA-256, and is
valid for 100 years so CI does not depend on an installed certificate generator.
It was generated using:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 \
  -subj '/CN=localhost/O=PostPlus TEST ONLY' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout localhost-test-only.key -out localhost-test-only.crt
```
