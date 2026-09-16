#pragma once
// Adds native OS root certificates to an OpenSSL store where OpenSSL cannot
// discover the platform trust store through its default paths.
typedef struct x509_store_st X509_STORE;
namespace postplus { void add_platform_trust_roots(X509_STORE* store); }
