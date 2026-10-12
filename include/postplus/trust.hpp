#pragma once
// Adds native OS root certificates, including Linux distribution CA stores
// when a packaged OpenSSL build's default paths are unavailable. Distribution
// fallback paths respect explicit SSL_CERT_FILE/SSL_CERT_DIR overrides.
typedef struct x509_store_st X509_STORE;
namespace postplus { void add_platform_trust_roots(X509_STORE* store); }
