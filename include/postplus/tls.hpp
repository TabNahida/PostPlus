#pragma once
#include <openssl/types.h>
#include <memory>
#include <string>

namespace postplus {
// Load the server chain and unencrypted key together, check the pair, and return
// an owned reference to the leaf for hostname/expiry checks by domain settings.
std::shared_ptr<X509> load_tls_certificate_pair(const std::string& certificate,
                                                const std::string& private_key);
}
