#pragma once
#include <postplus/core.hpp>
#include <array>

namespace postplus {
// Normalize a local-part glob (optionally followed by the configured domain).
// Only * and ? have wildcard meaning; brackets/escaping/regex are unsupported.
std::string forwarding_pattern(const std::string& pattern, const std::string& domain);
bool forwarding_matches(std::string_view pattern, std::string_view local_part);
std::array<unsigned, 3> forwarding_specificity(std::string_view pattern);
// Returns storage's canonical mailbox/rule report; an unknown local recipient
// returns ok:true,exists:false. Service failures throw rather than permit mail.
Json resolve_local_recipient(const Config& config, const std::string& recipient,
                             const std::string& queue_id = "");
}
