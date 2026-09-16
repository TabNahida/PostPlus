#include "postplus/core.hpp"
#include "postplus/mime.hpp"
#include "postplus/settings.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>

namespace postplus {
namespace {
#ifdef POSTPLUS_ADMIN
constexpr bool admin_only = true;
const std::string service_name = "admin", cookie_name = "pp_admin_session";
#else
constexpr bool admin_only = false;
const std::string service_name = "web", cookie_name = "pp_session";
#endif
using Clock = std::chrono::steady_clock;
struct ApiError : std::runtime_error {
    int status;
    ApiError(int code, const std::string& message) : std::runtime_error(message), status(code) {}
};

std::string header(const HttpRequest& request, const std::string& name) {
    auto found = request.headers.find(name);
    return found == request.headers.end() ? "" : found->second;
}

std::string session_cookie(const HttpRequest& request) {
    std::istringstream stream(header(request, "cookie"));
    std::string part;
    while (std::getline(stream, part, ';')) {
        part = trim(part);
        if (part.starts_with(cookie_name + "=")) return part.substr(cookie_name.size() + 1);
    }
    return "";
}

Json request_json(const HttpRequest& request) {
    auto type = lower(header(request, "content-type"));
    if (trim(type.substr(0, type.find(';'))) != "application/json")
        throw ApiError(415, "Use application/json for this request.");
    auto result = Json::parse(request.body, nullptr, false);
    if (result.is_discarded() || !result.is_object()) throw ApiError(400, "A JSON object is required.");
    return result;
}

std::string field(const Json& value, const std::string& key, std::size_t limit) {
    if (!value.contains(key) || !value[key].is_string()) throw ApiError(400, "Missing text field: " + key);
    auto result = value[key].get<std::string>();
    if (result.size() > limit) throw ApiError(400, "Field is too long: " + key);
    return result;
}

std::string username_field(const Json& value) {
    auto username = lower(trim(field(value, "username", 254)));
    if (!valid_address(username)) throw ApiError(400, "Enter a full email address.");
    return username;
}

std::string password_field(const Json& value) {
    auto password = field(value, "password", 1024);
    if (password.size() < 12) throw ApiError(400, "Passwords must contain at least 12 characters.");
    return password;
}

void require_ok(const Json& value, const std::string& message, int status = 503) {
    if (!value.value("ok", false)) throw ApiError(status, message);
}

Json log_query(const Config& config, const std::string& path) {
    std::string service, level;
    std::size_t limit = 100;
    const auto question = path.find('?');
    std::set<std::string> seen;
    if (question != std::string::npos) {
        std::istringstream query(path.substr(question + 1));
        std::string item;
        while (std::getline(query,item,'&')) {
            const auto equals = item.find('=');
            if (equals == std::string::npos) throw ApiError(400,"Invalid log filters.");
            const auto key = item.substr(0,equals), value = item.substr(equals + 1);
            if (!seen.insert(key).second) throw ApiError(400,"Invalid log filters.");
            if (key == "service") service = value;
            else if (key == "level") level = value;
            else if (key == "limit") {
                const auto [end,error] = std::from_chars(value.data(),value.data()+value.size(),limit);
                if (error != std::errc{} || end != value.data()+value.size()) throw ApiError(400,"Invalid log limit.");
            } else throw ApiError(400,"Invalid log filters.");
        }
    }
    try { return read_logs(config,service,level,limit); }
    catch (const std::invalid_argument&) { throw ApiError(400,"Invalid log filters or limit."); }
}

std::optional<std::string> plain_text(const mime::Part& part) {
    if (lower(mime::header(part, "content-disposition")).starts_with("attachment")) return std::nullopt;
    if (part.content_type == "text/plain") return part.body;
    for (const auto& child : part.parts) {
        if (auto text = plain_text(child)) return text;
    }
    return std::nullopt;
}

Json message_view(const std::string& raw) {
    try {
        auto part = mime::parse(raw);
        auto text = plain_text(part);
        return {{"subject", mime::decode_header(mime::header(part, "subject"))},
                {"from", mime::decode_header(mime::header(part, "from"))},
                {"to", mime::decode_header(mime::header(part, "to"))},
                {"date", mime::header(part, "date")},
                {"text", text.value_or("This message has no readable plain-text part. View the original message below.")}};
    } catch (const std::exception&) {
        return {{"subject", ""}, {"from", ""}, {"to", ""}, {"date", ""},
                {"text", "The message could not be decoded. View the original message below."}};
    }
}

struct WebSession {
    std::string username, csrf, credential_version;
    bool admin = false;
    Clock::time_point expires;
};

class Web {
public:
    explicit Web(const Config& config) : config_(config) {
        session_seconds_ = std::clamp(config_.number("web_session_seconds", 3600), 60, 86400);
        session_limit_ = static_cast<std::size_t>(std::clamp(config_.number("max_web_sessions", 1024), 1, 10000));
        const auto root = std::filesystem::path(config_.text("web_root", "web"));
        load_static(root, "/", admin_only ? "admin.html" : "index.html", "text/html; charset=utf-8");
        if (admin_only) {
            load_static(root, "/admin.js", "admin.js", "application/javascript; charset=utf-8");
            load_static(root, "/settings.js", "settings.js", "application/javascript; charset=utf-8");
        } else load_static(root, "/app.js", "app.js", "application/javascript; charset=utf-8");
        load_static(root, "/favicon.svg", "favicon.svg", "image/svg+xml");
        load_static(root, "/i18n.js", "i18n.js", "application/javascript; charset=utf-8");
        load_static(root, "/style.css", "style.css", "text/css; charset=utf-8");
    }

    HttpResponse handle(const HttpRequest& request) {
        HttpResponse response;
        try { response = route(request); }
        catch (const ApiError& error) {
            response = json_response({{"ok", false}, {"error", error.what()}}, error.status);
            if (error.status == 429) response.headers["Retry-After"] = "60";
        }
        catch (const SettingsError& error) {
            response = json_response({{"ok", false}, {"code", "invalid_configuration"},
                                      {"field", error.field}, {"error", error.what()}}, error.status);
        }
        catch (const Json::exception&) { response = json_response({{"ok", false}, {"error", "Invalid request data."}}, 400); }
        catch (const std::exception&) { response = json_response({{"ok", false}, {"error", "A required service is unavailable. Please retry."}}, 503); }
        response.headers["Cache-Control"] = "no-store";
        response.headers["X-Content-Type-Options"] = "nosniff";
        response.headers["X-Frame-Options"] = "DENY";
        response.headers["Referrer-Policy"] = "no-referrer";
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
        return response;
    }

    std::optional<HttpResponse> preflight(const HttpRequest& request) {
        if ((!admin_only && request.path.starts_with("/api/admin/")) ||
            (admin_only && (request.path.starts_with("/api/messages") || request.path == "/api/send")))
            return json_response({{"ok",false},{"error","API route not found."}},404);
        // Verify session and CSRF before core allocates a potentially large compose body.
        if (!request.path.starts_with("/api/") || request.path == "/api/login") return std::nullopt;
        try {
            const auto session = authenticate(request);
            if (request.method != "GET") require_csrf(request,session);
            return std::nullopt;
        } catch (const ApiError& error) {
            return json_response({{"ok",false},{"error",error.what()}},error.status);
        } catch (const std::exception&) {
            return json_response({{"ok",false},{"error","A required service is unavailable. Please retry."}},503);
        }
    }

private:
    Config config_;
    std::mutex mutex_;
    std::map<std::string, WebSession> sessions_;
    struct Rate { Clock::time_point expires; unsigned count = 0; };
    std::map<std::string, Rate> attempts_;
    Rate global_attempts_{};
    std::map<std::string, HttpResponse> assets_;
    int session_seconds_ = 3600;
    std::size_t session_limit_ = 1024;

    void load_static(const std::filesystem::path& root, const std::string& route,
                     const std::string& filename, const std::string& type) {
        std::ifstream file(root / filename, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot read web asset: " + (root / filename).string());
        file.seekg(0, std::ios::end);
        const auto size = file.tellg();
        if (size < 0 || size > 512 * 1024) throw std::runtime_error("Invalid web asset size.");
        file.seekg(0);
        std::string body(static_cast<std::size_t>(size), '\0');
        if (!body.empty() && !file.read(body.data(), static_cast<std::streamsize>(body.size())))
            throw std::runtime_error("Cannot read web asset.");
        assets_.emplace(route, HttpResponse{200, type, std::move(body), {}});
    }

    void prune(Clock::time_point now) {
        std::erase_if(sessions_, [now](const auto& item) { return item.second.expires <= now; });
        std::erase_if(attempts_, [now](const auto& item) { return item.second.expires <= now; });
    }

    void allow_login(const HttpRequest& request) {
        std::lock_guard lock(mutex_);
        const auto now = Clock::now();
        prune(now);
        if (global_attempts_.expires <= now) global_attempts_ = {now + std::chrono::minutes(1), 0};
        if (global_attempts_.count >= 120) throw ApiError(429, "Too many sign-in attempts. Try again in one minute.");
        ++global_attempts_.count;
        if (!attempts_.contains(request.peer_address) && attempts_.size() >= 4096)
            throw ApiError(429, "Too many sign-in attempts. Try again in one minute.");
        auto& rate = attempts_[request.peer_address];
        if (rate.expires <= now) rate = {now + std::chrono::minutes(1), 0};
        if (rate.count >= 20) throw ApiError(429, "Too many sign-in attempts. Try again in one minute.");
        ++rate.count;
    }

    void require_transport(const HttpRequest& request) const {
        if (!request.encrypted && !(request.peer_loopback && config_.flag("allow_insecure_auth")))
            throw ApiError(403, "HTTPS is required to access your account.");
    }

    WebSession authenticate(const HttpRequest& request) {
        require_transport(request);
        auto token = session_cookie(request);
        if (token.size() != 64) throw ApiError(401, "Sign in to continue.");
        WebSession session;
        {
            std::lock_guard lock(mutex_);
            prune(Clock::now());
            auto found = sessions_.find(token);
            if (found == sessions_.end()) throw ApiError(401, "Your session has expired. Please sign in again.");
            session = found->second;
        }
        const auto account = rpc(config_, "auth", {{"op","session_check"},{"username",session.username},
                                                  {"credential_version",session.credential_version}});
        require_ok(account,"A required service is unavailable. Please retry.");
        if (!account.value("valid",false) || account.value("admin",false) != session.admin) {
            std::lock_guard lock(mutex_);
            sessions_.erase(token);
            throw ApiError(401,"Your session has expired. Please sign in again.");
        }
        return session;
    }

    void require_csrf(const HttpRequest& request, const WebSession& session) const {
        if (!secure_equal(header(request, "x-csrf-token"), session.csrf))
            throw ApiError(403, "Security token is missing or expired. Refresh this page.");
    }

    HttpResponse login(const HttpRequest& request) {
        require_transport(request);
        allow_login(request);
        auto input = request_json(request);
        auto username = username_field(input);
        auto password = field(input, "password", 1024);
        auto user = rpc(config_, "auth", {{"op", "verify"}, {"username", username}, {"password", password}, {"session", true}});
        if (!user.value("ok",false)) log(service_name,"sign-in failed for " + username + " from " + request.peer_address,"warn");
        require_ok(user, "The email address or password is incorrect.", 401);
        if (admin_only && !user.value("admin",false)) throw ApiError(403,"Administrator access is required.");
        auto token = random_hex(32);
        WebSession session{user.at("username").get<std::string>(), random_hex(32), user.at("credential_version").get<std::string>(), user.value("admin", false),
                           Clock::now() + std::chrono::seconds(session_seconds_)};
        {
            std::lock_guard lock(mutex_);
            prune(Clock::now());
            sessions_.erase(session_cookie(request));
            if (sessions_.size() >= session_limit_) throw ApiError(503, "Session capacity reached. Please try again later.");
            sessions_.emplace(token, session);
        }
        auto response = json_response({{"ok", true}, {"username", session.username}, {"admin", session.admin},
                                       {"csrf", session.csrf}, {"expires_in", session_seconds_}});
        response.headers["Set-Cookie"] = cookie_name + "=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                                         std::to_string(session_seconds_) + (request.encrypted ? "; Secure" : "");
        log(service_name,"signed in " + session.username + " from " + request.peer_address);
        return response;
    }

    HttpResponse send_mail(const HttpRequest& request, const WebSession& session);

    HttpResponse route(const HttpRequest& request) {
        if ((!admin_only && request.path.starts_with("/api/admin/")) ||
            (admin_only && (request.path.starts_with("/api/messages") || request.path == "/api/send")))
            throw ApiError(404, "API route not found.");
        if (request.method == "GET" && request.path == "/health")
            return json_response({{"ok", true}, {"service", service_name}});
        if (request.method == "GET") {
            auto path = request.path == (admin_only ? "/admin.html" : "/index.html") ||
                        (admin_only && request.path == "/admin") ? "/" : request.path;
            auto asset = assets_.find(path);
            if (asset != assets_.end()) return asset->second;
        }
        if (!request.path.starts_with("/api/")) throw ApiError(404, "Page not found.");
        if (request.method == "POST" && request.path == "/api/login") return login(request);
        const auto session = authenticate(request);
        if (request.method != "GET") require_csrf(request, session);
        if (request.method == "GET" && request.path == "/api/session")
            return json_response({{"ok", true}, {"username", session.username}, {"admin", session.admin}, {"csrf", session.csrf}});
        if (request.method == "POST" && request.path == "/api/logout") {
            std::lock_guard lock(mutex_);
            sessions_.erase(session_cookie(request));
            auto response = json_response({{"ok", true}});
            response.headers["Set-Cookie"] = cookie_name + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" +
                                             std::string(request.encrypted ? "; Secure" : "");
            return response;
        }
        if (request.method == "GET" && request.path == "/api/messages") {
            auto result = rpc(config_, "storage", {{"op", "list"}, {"username", session.username}, {"include_envelope", true}});
            require_ok(result, "Unable to load messages.");
            return json_response(result);
        }
        if (request.path.starts_with("/api/messages/")) {
            auto id = request.path.substr(std::string("/api/messages/").size());
            if (id.empty() || id.size() > 128 || !std::all_of(id.begin(), id.end(), [](unsigned char ch) {
                    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
                })) throw ApiError(400, "Invalid message ID.");
            if (request.method == "GET") {
                auto result = rpc(config_, "storage", {{"op", "get"}, {"username", session.username}, {"id", id}});
                require_ok(result, "Message not found.", 404);
                auto marked = rpc(config_, "storage", {{"op", "flags"}, {"username", session.username}, {"id", id}, {"seen", true}});
                require_ok(marked, "Unable to update message flags.");
                result["message"] = message_view(result.at("raw").get<std::string>());
                return json_response(result);
            }
            if (request.method == "DELETE") {
                auto result = rpc(config_, "storage", {{"op", "delete"}, {"username", session.username}, {"ids", Json::array({id})}});
                require_ok(result, "Unable to delete message.");
                log(service_name,"message deleted by " + session.username + ": " + id);
                return json_response(result);
            }
        }
        if (request.method == "POST" && request.path == "/api/send") return send_mail(request, session);
        if (request.path.starts_with("/api/admin/")) {
            if (!admin_only) throw ApiError(404,"API route not found.");
            if (!session.admin) throw ApiError(403, "Administrator access is required.");
            if (request.path == "/api/admin/config") {
                if (request.method == "GET") return json_response(settings_view(config_));
                if (request.method == "POST") return json_response(save_settings(config_, request_json(request)));
            }
            if (request.method == "GET" && (request.path == "/api/admin/logs" || request.path.starts_with("/api/admin/logs?")))
                return json_response(log_query(config_,request.path));
            if (request.method == "GET" && request.path == "/api/admin/users") {
                auto result = rpc(config_, "auth", {{"op", "list"}});
                require_ok(result, "Unable to load accounts.");
                return json_response(result);
            }
            if (request.method == "GET" && request.path == "/api/admin/stats") {
                auto result = rpc(config_, "storage", {{"op", "stats"}});
                require_ok(result, "Unable to load server statistics.");
                return json_response(result);
            }
            if (request.method == "GET" && request.path == "/api/admin/queue") {
                auto result = rpc(config_, "storage", {{"op", "queue_inspect"}, {"limit", 100}});
                require_ok(result, "Unable to inspect the delivery queue.");
                return json_response(result);
            }
            if (request.method == "POST" && request.path == "/api/admin/users") {
                const auto input = request_json(request);
                const auto username = username_field(input);
                if (username.substr(username.find('@') + 1) != lower(config_.text("domain", "localhost")))
                    throw ApiError(400, "Account addresses must use the configured server domain.");
                const auto password = password_field(input);
                auto result = rpc(config_, "auth", {{"op", "create"}, {"username", username}, {"password", password}, {"admin", input.value("admin", false)}});
                require_ok(result, "Unable to create account. This address may already exist.", 409);
                log(service_name,"administrator " + session.username + " created account " + username);
                return json_response(result, 201);
            }
            if (request.method == "POST" && request.path == "/api/admin/password") {
                const auto input = request_json(request);
                const auto username = username_field(input);
                const auto password = password_field(input);
                auto result = rpc(config_, "auth", {{"op", "change_password"}, {"username", username}, {"password", password}});
                require_ok(result, "Unable to change password.", 400);
                log(service_name,"administrator " + session.username + " changed password for " + username);
                std::lock_guard lock(mutex_);
                std::erase_if(sessions_, [&username](const auto& item) { return item.second.username == username; });
                return json_response(result);
            }
        }
        throw ApiError(404, "API route not found.");
    }
};

HttpResponse Web::send_mail(const HttpRequest& request, const WebSession& session) {
    const auto input = request_json(request);
    const auto max_bytes = static_cast<std::size_t>(std::clamp(config_.number("max_message_bytes", 10485760), 1024, 104857600));
    const auto subject = field(input, "subject", 512);
    const auto text = field(input, "text", max_bytes);
    if (!input.contains("to") || !input["to"].is_array() || input["to"].empty() || input["to"].size() > 100)
        throw ApiError(400, "Provide between 1 and 100 recipient addresses.");
    std::set<std::string> unique;
    std::vector<std::string> recipients;
    const auto domain = lower(config_.text("domain", "localhost"));
    for (const auto& address : input["to"]) {
        if (!address.is_string()) throw ApiError(400, "Recipient addresses must be strings.");
        auto recipient = lower(trim(address.get<std::string>()));
        if (!valid_address(recipient)) throw ApiError(400, "Invalid recipient address.");
        if (!unique.insert(recipient).second) continue;
        if (recipient.substr(recipient.find('@') + 1) == domain) {
            const auto exists = rpc(config_, "auth", {{"op", "exists"}, {"username", recipient}});
            require_ok(exists, "Unable to validate recipients.");
            if (!exists.value("exists", false)) throw ApiError(400, "A local recipient account does not exist: " + recipient);
        } else if (config_.text("smarthost_host").empty()) {
            throw ApiError(400, "External delivery is unavailable until an administrator configures a smarthost.");
        }
        recipients.push_back(std::move(recipient));
    }
    std::string raw;
    try { raw = mime::compose(session.username, recipients, subject, text); }
    catch (const std::exception&) { throw ApiError(400, "The message contains invalid headers or content."); }
    if (raw.size() > max_bytes) throw ApiError(413, "The encoded message exceeds the server size limit.");
    const auto scanned = rpc(config_, "filter", {{"op", "scan"}, {"raw", raw}});
    require_ok(scanned, "The message scanning service is unavailable.");
    if (scanned.value("action", "reject") != "accept") throw ApiError(422, "The message was rejected by the server mail filter.");
    const auto result = rpc(config_, "storage", {{"op", "enqueue"}, {"sender", session.username}, {"recipients", recipients}, {"raw", raw}});
    require_ok(result, "Unable to queue your message.");
    log(service_name,"message queued by " + session.username + " for " + std::to_string(recipients.size()) + " recipients");
    return json_response(result, 202);
}
} // namespace
} // namespace postplus

int main(int argc, char** argv) {
    return postplus::service_main(postplus::service_name, argc, argv, [](const postplus::Config& config) {
        postplus::Web web(config);
        postplus::serve_http(config, postplus::service_name, [&web](const auto& request) { return web.handle(request); }, false,
                            [&web](const auto& request) { return web.preflight(request); });
    });
}
