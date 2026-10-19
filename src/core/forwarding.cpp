#include <postplus/forwarding.hpp>
#include <array>
#include <algorithm>

namespace postplus {
std::string forwarding_pattern(const std::string& input, const std::string& domain) {
    auto pattern = lower(trim(input));
    const auto at = pattern.find('@');
    if (at != pattern.npos) {
        if (pattern.substr(at + 1) != lower(domain) || pattern.find('@', at + 1) != pattern.npos)
            throw std::invalid_argument("Forwarding patterns must belong to the configured local domain.");
        pattern.resize(at);
    }
    if (pattern.empty() || pattern.size() > 64 || pattern.front() == '.' || pattern.back() == '.' ||
        pattern.find("..") != pattern.npos || pattern.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789.!#$%&'*+-/=?^_`{|}~") != pattern.npos)
        throw std::invalid_argument("Forwarding pattern must be a local prefix of at most 64 characters; only * and ? are wildcards.");
    // Collapse repeated stars so equivalent patterns have one stored identity.
    std::string normalized;
    for (const auto ch : pattern) if (ch != '*' || normalized.empty() || normalized.back() != '*') normalized += ch;
    return normalized;
}
bool forwarding_matches(std::string_view pattern, std::string_view value) {
    // Bounded dynamic programming avoids exponential regex/backtracking costs.
    if (pattern.empty() || pattern.size() > 64 || value.empty() || value.size() > 64) return false;
    std::array<bool, 65> previous{}, next{}; previous[0] = true;
    for (const auto ch : pattern) {
        next.fill(false); if (ch == '*') next[0] = previous[0];
        for (std::size_t i = 1; i <= value.size(); ++i) {
            auto actual = value[i - 1]; if (actual >= 'A' && actual <= 'Z') actual += 'a' - 'A';
            auto wanted = ch; if (wanted >= 'A' && wanted <= 'Z') wanted += 'a' - 'A';
            next[i] = ch == '*' ? previous[i] || next[i - 1] : previous[i - 1] && (ch == '?' || wanted == actual);
        }
        previous = next;
    }
    return previous[value.size()];
}
std::array<unsigned, 3> forwarding_specificity(std::string_view pattern) {
    std::array<unsigned, 3> result{};
    for (const auto ch : pattern) ++result[ch == '*' ? 1 : ch == '?' ? 2 : 0];
    return result;
}
Json resolve_local_recipient(const Config& config, const std::string& input, const std::string& queue_id) {
    const auto recipient = lower(trim(input));
    if (!config.local_address(recipient))
        throw std::invalid_argument("Forwarding can resolve only recipients in the configured local domain.");
    Json request{{"op", "resolve_recipient"}, {"recipient", recipient}};
    if (!queue_id.empty()) request["queue_id"] = queue_id;
    auto response = rpc(config, "storage", request);
    if (!response.value("ok", false)) throw std::runtime_error(response.value("error", "Recipient resolution unavailable."));
    if (response.value("exists", false)) {
        const auto destination = response.at("destination").get<std::string>();
        if (!config.local_address(destination))
            throw std::runtime_error("Recipient resolver returned a nonlocal destination.");
    }
    return response;
}
}
