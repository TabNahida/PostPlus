#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace postplus::mime {
struct Limits {
    std::size_t max_bytes = 10485760;
    std::size_t max_parts = 256;
    std::size_t max_depth = 16;
    std::size_t max_headers = 256;
};
struct Part {
    std::vector<std::pair<std::string, std::string>> headers;
    std::string content_type;
    std::string body; // Decoded bytes; character sets are preserved, never guessed.
    std::vector<Part> parts;
};
Part parse(std::string_view raw, Limits limits = {});
std::string header(const Part& part, std::string_view name);
// Decodes RFC 2047 B/Q encoded words. Bytes retain the declared character set.
std::string decode_header(std::string_view value);
std::string compose(const std::string& from, const std::vector<std::string>& to,
                    const std::string& subject, const std::string& text);
}
