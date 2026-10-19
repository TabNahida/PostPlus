#pragma once
#include "postplus/mime.hpp"
#include <optional>
#include <string>
#include <string_view>

namespace postplus {
struct VerificationCode {
    std::string code;
};
struct VerificationLink {
    std::string url, label;
};
// Conservative extraction from decoded, visible message content. Attachments,
// quoted/forwarded messages, links and ambiguous codes are not candidates.
std::optional<VerificationCode> extract_verification_code(const mime::Part& message);
std::optional<VerificationCode> extract_verification_code(std::string_view raw);
// A conservative action-link candidate, never a trust/authenticity verdict.
// Only absolute HTTP(S) URLs are returned; extraction performs no requests.
std::optional<VerificationLink> extract_verification_link(const mime::Part& message);
std::optional<VerificationLink> extract_verification_link(std::string_view raw);
}
