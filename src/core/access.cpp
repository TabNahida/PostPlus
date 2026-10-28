#include <postplus/access.hpp>
#include <algorithm>
#include <set>

namespace postplus {
std::vector<std::string> api_key_permission_ids(std::string_view audience) {
    if (audience == "admin") return {"users:read", "users:write", "mail:read", "quota:read", "quota:write",
        "policy:read", "policy:write", "stats:read", "queue:read", "logs:read", "config:read", "config:write",
        "backup:read", "backup:write", "services:write", "updates:read", "updates:write", "invites:read", "invites:write",
        "forwarding:read", "forwarding:write", "security:read", "security:write"};
    if (audience == "mailbox") return {"mailbox:read", "mailbox:write", "mailbox:send", "codes:read"};
    return {};
}
Json api_permission_catalog() {
    auto result = Json::array();
    for (const auto audience : {"admin", "mailbox"})
        for (const auto& id : api_key_permission_ids(audience)) result.push_back({{"id", id}, {"audience", audience}});
    return result;
}
bool api_permissions_valid(const Json& permissions, std::string_view audience) {
    const auto allowed = api_key_permission_ids(audience);
    if (allowed.empty() || !permissions.is_array() || permissions.size() > allowed.size()) return false;
    std::set<std::string> seen;
    for (const auto& item : permissions) {
        if (!item.is_string()) return false;
        const auto id = item.get<std::string>();
        if (std::find(allowed.begin(), allowed.end(), id) == allowed.end() || !seen.insert(id).second) return false;
    }
    return true;
}
std::optional<std::string> required_api_permission(std::string_view method, std::string_view path) {
    path = path.substr(0, path.find('?'));
    const bool read = method == "GET";
    const bool write = method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE";
    if (!read && !write) return {};
    if (path == "/api/admin/users") return read ? "users:read" : "users:write";
    if (path == "/api/admin/password") return write ? std::optional<std::string>("users:write") : std::nullopt;
    if (path == "/api/admin/folders" || path == "/api/admin/messages" || path.starts_with("/api/admin/messages/")) return read ? std::optional<std::string>("mail:read") : std::nullopt;
    if (path == "/api/admin/quota") return read ? "quota:read" : "quota:write";
    if (path == "/api/admin/password-policy") return read ? "policy:read" : "policy:write";
    if (path == "/api/admin/security" && read) return "security:read";
    if (path == "/api/admin/security/events" && read) return "security:read";
    if (path == "/api/admin/abuseipdb" && read) return "security:read";
    if (path == "/api/admin/abuseipdb/settings" && method == "PUT") return "security:write";
    if (path == "/api/admin/abuseipdb/quotas/refresh" && method == "POST") return "security:write";
    if (method == "POST" && (path == "/api/admin/abuseipdb/check" || path == "/api/admin/abuseipdb/reports" ||
        path == "/api/admin/abuseipdb/blacklist" || path == "/api/admin/abuseipdb/check-block" || path == "/api/admin/abuseipdb/bulk-check")) return "security:read";
    if (method == "POST" && (path == "/api/admin/abuseipdb/report" || path == "/api/admin/abuseipdb/bulk-report" || path == "/api/admin/abuseipdb/clear-address")) return "security:write";
    if ((path == "/api/admin/security/policy" && method == "PUT") ||
        ((path == "/api/admin/security/ban" || path == "/api/admin/security/unban") && method == "POST")) return "security:write";
    if (path == "/api/admin/stats") return read ? std::optional<std::string>("stats:read") : std::nullopt;
    if (path == "/api/admin/queue") return read ? std::optional<std::string>("queue:read") : std::nullopt;
    if (path == "/api/admin/logs") return read ? std::optional<std::string>("logs:read") : std::nullopt;
    if (path == "/api/admin/config") return read ? "config:read" : "config:write";
    if (path == "/api/admin/domains" || path.starts_with("/api/admin/domains/"))
        return read || path == "/api/admin/domains/preview" ? "config:read" : "config:write";
    if ((path == "/api/admin/dns" && read) || (path == "/api/admin/dns/check" && method == "POST")) return "config:read";
    if (path == "/api/admin/dkim") return write ? std::optional<std::string>("config:write") : std::nullopt;
    if (path.starts_with("/api/admin/acme/")) return read ? "config:read" : "config:write";
    if (path == "/api/admin/backup" || path == "/api/admin/backup/download") return read ? "backup:read" : "backup:write";
    if (path == "/api/admin/restart" || path == "/api/admin/shutdown") return "services:write";
    if (path == "/api/admin/update" || path.starts_with("/api/admin/update/"))
        return read || path == "/api/admin/update/check" ? "updates:read" : "updates:write";
    if (path == "/api/admin/invitations" || path.starts_with("/api/admin/invitations/")) return read ? "invites:read" : "invites:write";
    if (path == "/api/admin/forwarding" || path.starts_with("/api/admin/forwarding/")) return read ? "forwarding:read" : "forwarding:write";
    if (path == "/api/verification-code") return read ? std::optional<std::string>("codes:read") : std::nullopt;
    if (path == "/api/folders" || path == "/api/messages" || path.starts_with("/api/messages/")) return read ? "mailbox:read" : "mailbox:write";
    if (path == "/api/drafts") return write ? std::optional<std::string>("mailbox:write") : std::nullopt;
    if (path == "/api/send") return write ? std::optional<std::string>("mailbox:send") : std::nullopt;
    return {};
}
}
