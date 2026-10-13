#pragma once
#include <postplus/core.hpp>
#include <optional>

namespace postplus {
// Stable permission identifiers; presentation labels belong to the client.
Json api_permission_catalog();
std::vector<std::string> api_key_permission_ids(std::string_view audience);
bool api_permissions_valid(const Json& permissions, std::string_view audience);
// Unknown routes and credential-management routes deny Bearer access.
std::optional<std::string> required_api_permission(std::string_view method, std::string_view path);
}
