#pragma once
#include <postplus/core.hpp>
#include <stdexcept>

namespace postplus {
class AcmeError : public std::runtime_error {
public:
    std::string code;
    int status;
    AcmeError(std::string name, std::string message, int http = 400)
        : std::runtime_error(std::move(message)), code(std::move(name)), status(http) {}
};

struct AcmeHttpResponse {
    int status = 0;
    // Lowercase header names, as returned by the native transport.
    std::map<std::string, std::string> headers;
    std::string body;
};
using AcmeTransport = std::function<AcmeHttpResponse(
    const std::string& method, const std::string& url,
    const std::map<std::string, std::string>& headers, const std::string& body,
    std::chrono::steady_clock::time_point deadline)>;

struct AcmeOptions {
    std::filesystem::path storage_directory;
    // HTTP-01 always reaches public TCP port 80. This listener can sit behind
    // port forwarding; otherwise use port 80 and a publicly reachable address.
    std::string challenge_bind = "0.0.0.0";
    int challenge_port = 80;
    bool manage_http_listener = true;
    std::chrono::seconds request_timeout{15};
    std::chrono::seconds job_timeout{300};
    // Dependency injection for deterministic, offline protocol tests. Neither
    // field is accepted from browser request JSON. An override requires BOTH.
    AcmeTransport transport;
    std::string test_directory_url;
    std::filesystem::path test_ca_file;
};

class AcmeManager {
public:
    explicit AcmeManager(AcmeOptions options);
    ~AcmeManager();
    AcmeManager(const AcmeManager&) = delete;
    AcmeManager& operator=(const AcmeManager&) = delete;
    // Read-only CA metadata; does not create an account or accept any terms.
    Json terms(const std::string& directory = "staging") const;
    // Required request keys: domain, email, directory (staging|production),
    // agree_terms:true, terms_of_service (the URL returned by terms()).
    Json start(const Json& request);
    // Empty job_id returns the latest job, or {ok:true,state:"idle"}.
    Json status(const std::string& job_id = "") const;
    Json cancel(const std::string& job_id);
    // Integrate with a reverse proxy's HTTP listener when the manager does not
    // own port 80. Root must expose this PUBLIC route without login/HTTPS/CSRF.
    // Other routes return nullopt; unknown challenge tokens return HTTP 404.
    std::optional<HttpResponse> challenge(const HttpRequest& request) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
