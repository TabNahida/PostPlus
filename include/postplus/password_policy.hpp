#pragma once
#include <postplus/core.hpp>

namespace postplus {
struct PasswordPolicy {
    int min_length = 8;
    bool require_uppercase = false;
    bool require_lowercase = false;
    bool require_digit = false;
    bool require_symbol = false;
};

Json password_policy_json(const PasswordPolicy& policy);
// Full policy objects only. Returns stable field errors without coercing values.
Json password_policy_errors(const Json& value, int max_password_bytes);
PasswordPolicy parse_password_policy(const Json& value);
// Counts Unicode scalar values; ASCII punctuation satisfies require_symbol.
// Passwords are never trimmed or normalized.
Json password_violations(std::string_view password, const PasswordPolicy& policy,
                         std::size_t max_password_bytes);
}
