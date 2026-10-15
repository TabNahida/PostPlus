#pragma once
#include <postplus/dns.hpp>
#include <stdexcept>

namespace postplus {
class RemoteImageError : public std::runtime_error {
public:
    explicit RemoteImageError(const std::string& message) : std::runtime_error(message) {}
};
struct RemoteImage {
    std::string content_type;
    std::string body;
};
struct RemoteImageOptions {
    DnsOptions dns;
    // Native tests only. Production connects to the already-vetted numeric
    // endpoint and verifies TLS with the original hostname. Never set from API
    // input, saved configuration, or a sender-owned mail header.
    std::function<void(Connection&, const tcp::endpoint&, const std::string&, bool)> connect;
};
// Only bounded HTTP(S) img src attributes are returned; no links or CSS URLs.
std::vector<std::string> extract_remote_image_urls(std::string_view html);
// No browser credentials, referrer or cookies are sent. Redirects are rejected.
// Connects only to vetted numeric public addresses. Raster-only, 2 MiB maximum,
// ten-second total transaction budget, at most four concurrent native fetches.
RemoteImage fetch_remote_image(const std::string& url, RemoteImageOptions options = {});
}
