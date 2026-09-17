#include <postplus/password_policy.hpp>

#include <algorithm>
#include <array>
#include <cstdint>

namespace postplus {
namespace {
constexpr std::array<const char*, 4> diversity_fields = {
    "require_uppercase", "require_lowercase", "require_digit", "require_symbol"
};

std::optional<std::size_t> unicode_length(std::string_view input) {
    std::size_t count = 0;
    for (std::size_t i = 0; i < input.size(); ++count) {
        const auto first = static_cast<unsigned char>(input[i++]);
        if (first < 0x80) continue;
        std::uint32_t codepoint = 0, minimum = 0;
        unsigned remaining = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            codepoint = first & 0x1f; minimum = 0x80; remaining = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            codepoint = first & 0x0f; minimum = 0x800; remaining = 2;
        } else if (first >= 0xf0 && first <= 0xf4) {
            codepoint = first & 0x07; minimum = 0x10000; remaining = 3;
        } else return std::nullopt;
        if (input.size() - i < remaining) return std::nullopt;
        while (remaining--) {
            const auto next = static_cast<unsigned char>(input[i++]);
            if ((next & 0xc0) != 0x80) return std::nullopt;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff))
            return std::nullopt;
    }
    return count;
}
}

Json password_policy_json(const PasswordPolicy& policy) {
    return {{"min_length", policy.min_length}, {"require_uppercase", policy.require_uppercase},
            {"require_lowercase", policy.require_lowercase}, {"require_digit", policy.require_digit},
            {"require_symbol", policy.require_symbol}};
}

Json password_policy_errors(const Json& value, int max_password_bytes) {
    auto errors = Json::array();
    if (!value.is_object()) return Json::array({{{"field", "policy"}, {"code", "invalid_type"}}});
    for (const auto& item : value.items()) {
        if (item.key() != "min_length" && std::none_of(diversity_fields.begin(), diversity_fields.end(),
                [&](const char* name) { return item.key() == name; }))
            errors.push_back({{"field", item.key()}, {"code", "unknown_field"}});
    }
    const int maximum = std::min(128, max_password_bytes);
    if (!value.contains("min_length")) errors.push_back({{"field", "min_length"}, {"code", "required"}});
    else if (!value.at("min_length").is_number_integer())
        errors.push_back({{"field", "min_length"}, {"code", "invalid_type"}});
    else if ((value.at("min_length").is_number_unsigned() && value.at("min_length").get<std::uint64_t>() > static_cast<std::uint64_t>(maximum)) ||
             value.at("min_length").get<std::int64_t>() < 8 || value.at("min_length").get<std::int64_t>() > maximum)
        errors.push_back({{"field", "min_length"}, {"code", "out_of_range"}, {"min", 8}, {"max", maximum}});
    for (const auto* name : diversity_fields) {
        if (!value.contains(name)) errors.push_back({{"field", name}, {"code", "required"}});
        else if (!value.at(name).is_boolean()) errors.push_back({{"field", name}, {"code", "invalid_type"}});
    }
    return errors;
}

PasswordPolicy parse_password_policy(const Json& value) {
    return {value.at("min_length").get<int>(), value.at("require_uppercase").get<bool>(),
            value.at("require_lowercase").get<bool>(), value.at("require_digit").get<bool>(),
            value.at("require_symbol").get<bool>()};
}

Json password_violations(std::string_view password, const PasswordPolicy& policy, std::size_t max_password_bytes) {
    auto result = Json::array();
    const auto length = unicode_length(password);
    if (!length) result.push_back("invalid_utf8");
    else if (*length < static_cast<std::size_t>(policy.min_length)) result.push_back("min_length");
    if (password.size() > max_password_bytes) result.push_back("max_password_bytes");
    bool uppercase = false, lowercase = false, digit = false, symbol = false;
    for (unsigned char ch : password) {
        uppercase = uppercase || (ch >= 'A' && ch <= 'Z');
        lowercase = lowercase || (ch >= 'a' && ch <= 'z');
        digit = digit || (ch >= '0' && ch <= '9');
        symbol = symbol || (ch >= 0x21 && ch <= 0x2f) || (ch >= 0x3a && ch <= 0x40) ||
                            (ch >= 0x5b && ch <= 0x60) || (ch >= 0x7b && ch <= 0x7e);
    }
    if (policy.require_uppercase && !uppercase) result.push_back("require_uppercase");
    if (policy.require_lowercase && !lowercase) result.push_back("require_lowercase");
    if (policy.require_digit && !digit) result.push_back("require_digit");
    if (policy.require_symbol && !symbol) result.push_back("require_symbol");
    return result;
}
}
