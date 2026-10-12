#pragma once
#include <postplus/core.hpp>

namespace postplus {
struct DkimKeyPair {
    std::string private_pem;
    std::string txt_value;
};
// Fresh RSA-2048 key; TXT contains only the corresponding public key.
DkimKeyPair generate_dkim_key();
std::string dkim_public_record(std::string_view private_pem);
bool valid_dkim_domain(std::string_view domain);
bool valid_dkim_selector(std::string_view selector);
bool valid_dkim_record_name(std::string_view domain, std::string_view selector);
// Pins a regular, bounded file and refuses symbolic links. Unix keys must be
// owner-only; Windows keys must exclude access by unrelated principals.
std::string load_dkim_private_key(const std::filesystem::path& path);
// Adds a relaxed/relaxed RSA-SHA256 signature; preserves MIME content and
// headers apart from LF-to-CRLF normalization and the final SMTP line ending.
// Exactly one From mailbox in domain is required.
std::string dkim_sign(std::string_view raw, std::string_view domain,
                      std::string_view selector, std::string_view private_pem);
// Direct mode requires a key. Relay mode signs only when a key is configured.
std::string sign_dkim(const Config& config, std::string_view raw);
}
