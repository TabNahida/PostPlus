#pragma once
#include "postplus/mime.hpp"
#include <optional>
#include <string>
#include <string_view>

namespace postplus {
struct VerificationCode {
    std::string code;
};
// Conservative extraction from decoded, visible message content. Attachments,
// quoted/forwarded messages, links and ambiguous codes are not candidates.
std::optional<VerificationCode> extract_verification_code(const mime::Part& message);
std::optional<VerificationCode> extract_verification_code(std::string_view raw);
}
