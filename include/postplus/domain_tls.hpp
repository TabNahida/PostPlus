#pragma once
#include <postplus/core.hpp>

namespace postplus {
// Resolve relative paths and validate the persisted hostname-to-certificate
// map. Certificate contents are checked when saved and when selected by SNI.
void normalize_domain_tls(Config& config);
// Read the latest saved configuration; only file paths are returned.
Json domain_tls_view(const Config& running,const std::string& domain);
// request: revision, domain, hostname, tls_certificate, tls_private_key.
// Empty paired paths remove an override, retaining the default certificate.
Json save_domain_tls(const Config& running,const Json& request);
}
