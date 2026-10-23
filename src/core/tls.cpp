#include <postplus/tls.hpp>
#include <openssl/ssl.h>
#include <stdexcept>

namespace postplus {
std::shared_ptr<X509> load_tls_certificate_pair(const std::string& certificate,
                                                const std::string& private_key) {
    if (certificate.empty() || private_key.empty() ||
        certificate.find('\0') != std::string::npos || private_key.find('\0') != std::string::npos)
        throw std::invalid_argument("invalid TLS certificate/private key path");
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    if (!context) throw std::runtime_error("cannot create TLS certificate context");
    SSL_CTX_set_default_passwd_cb(context.get(), [](char*, int, int, void*) { return 0; });
    if (SSL_CTX_use_certificate_chain_file(context.get(), certificate.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(context.get(), private_key.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context.get()) != 1)
        throw std::runtime_error("cannot load matching TLS certificate/private key");
    auto* leaf = SSL_CTX_get0_certificate(context.get());
    if (!leaf || X509_up_ref(leaf) != 1) throw std::runtime_error("cannot retain TLS leaf certificate");
    return {leaf, X509_free};
}
}
