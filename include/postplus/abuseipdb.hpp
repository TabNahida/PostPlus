#pragma once
#include <postplus/core.hpp>
#include <stdexcept>

namespace postplus {
struct AbuseHttpResponse {
    int status = 200;
    std::map<std::string, std::string> headers;
    std::string body;
};
struct AbuseHttpRequest {
    std::string method, target, body, content_type = "application/x-www-form-urlencoded";
};
using AbuseTransport = std::function<AbuseHttpResponse(const AbuseHttpRequest&, const std::string&,
    std::chrono::steady_clock::time_point)>;
class AbuseError : public std::runtime_error {
public:
    std::string field;
    explicit AbuseError(std::string field_, std::string message) : std::runtime_error(std::move(message)), field(std::move(field_)) {}
};
Json abuseipdb_defaults();
Json validate_abuseipdb_settings(const Json& current, const Json& patch);
AbuseHttpRequest abuseipdb_request(const std::string& endpoint, const Json& input);
class AbuseIpDb {
public:
    explicit AbuseIpDb(AbuseTransport transport = {}, const std::filesystem::path& database = {});
    ~AbuseIpDb();
    void configure(const Json& settings);
    Json settings() const;
    Json view() const;
    void set_event_sink(std::function<void(Json)> sink);
    // Cache-only membership in the unexpired confidence-100 provider list.
    bool blacklisted(const std::string& ip) const;
    // Fixed read-only probes discover observed endpoint limits, even while
    // protection is disabled. Never submits or removes an abuse report.
    Json refresh_quotas(std::chrono::milliseconds budget = std::chrono::seconds(18));
    Json perform(const std::string& endpoint, const Json& input);
    // Public addresses only. Cached checks and unavailable upstreams fail open.
    std::optional<Json> reputation(const std::string& ip, bool cached_only = false);
    void observe_failures(const std::string& ip, const std::string& protocol, int failures);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
