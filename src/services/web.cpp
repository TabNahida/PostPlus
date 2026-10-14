#include "postplus/core.hpp"
#include "postplus/mime.hpp"
#include "postplus/settings.hpp"
#include "postplus/acme.hpp"
#include "postplus/maintenance.hpp"
#include "postplus/restart.hpp"
#include "postplus/mail_clients.hpp"
#include "postplus/dns.hpp"
#include "postplus/access.hpp"
#include "postplus/forwarding.hpp"
#include "postplus/verification_code.hpp"

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
    // The auth service applies the live policy to every creation/reset path.
    return field(value, "password", 4096);
}

void require_ok(const Json& value, const std::string& message, int status = 503) {
    if (!value.value("ok", false)) throw ApiError(status, message);
}

std::map<std::string,std::string> query_fields(const std::string& path) {
    auto decode = [](std::string_view input) {
        std::string out;
        auto hex = [](char ch) { if(ch >= '0' && ch <= '9') return ch-'0'; if(ch >= 'a' && ch <= 'f') return ch-'a'+10; if(ch >= 'A' && ch <= 'F') return ch-'A'+10; return -1; };
        for(std::size_t i=0;i<input.size();++i) {
            unsigned char ch=input[i];
            if(ch=='%') {
                if(i+2>=input.size() || hex(input[i+1])<0 || hex(input[i+2])<0) throw ApiError(400,"Invalid query string.");
                ch=static_cast<unsigned char>(hex(input[i+1])*16+hex(input[i+2])); i+=2;
            } else if(ch=='+') ch=' ';
            if(ch<32 || ch==127) throw ApiError(400,"Invalid query string.");
            out+=static_cast<char>(ch);
        }
        return out;
    };
    std::map<std::string,std::string> result;
    const auto question=path.find('?');
    if(question==std::string::npos) return result;
    std::istringstream input(path.substr(question+1)); std::string item;
    while(std::getline(input,item,'&')) {
        auto equal=item.find('=');
        if(equal==std::string::npos || !result.emplace(decode(std::string_view(item).substr(0,equal)),decode(std::string_view(item).substr(equal+1))).second)
            throw ApiError(400,"Invalid query string.");
    }
    return result;
}

std::string message_id(const std::string& id) {
    if(id.empty() || id.size()>128 || !std::all_of(id.begin(),id.end(),[](unsigned char c) {
        return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-' || c=='_';
    })) throw ApiError(400,"Invalid message ID.");
    return id;
}

std::string folder_name(const std::string& name) {
    static const std::set<std::string> names{"INBOX","Sent","Trash","Drafts","Junk","Archive"};
    if(!names.contains(name)) throw ApiError(400,"Unknown mail folder.");
    return name;
}

bool forbidden_portal_route(const HttpRequest& request) {
    const auto path=request.path.substr(0,request.path.find('?'));
    return (!admin_only && path.starts_with("/api/admin/")) ||
        (admin_only && (path.starts_with("/api/messages") || path=="/api/folders" || path=="/api/drafts" || path=="/api/send" || path=="/api/verification-code" || path.starts_with("/api/api-keys") || path.starts_with("/api/public/invitations/")));
}

bool api_key_management_route(const std::string& path) {
    return path == "/api/admin/api-keys" || path.starts_with("/api/admin/api-keys/") ||
           path == "/api/api-keys" || path.starts_with("/api/api-keys/");
}

Json log_query(const Config& config, const std::string& path) {
    std::string service, level, search, cursor;
    std::size_t limit = 100;
    for (const auto& [key,value] : query_fields(path)) {
            if (key == "service") service = value;
            else if (key == "level") level = value;
            else if (key == "q") search = value;
            else if (key == "cursor") cursor = value;
            else if (key == "limit") {
                const auto [end,error] = std::from_chars(value.data(),value.data()+value.size(),limit);
                if (error != std::errc{} || end != value.data()+value.size()) throw ApiError(400,"Invalid log limit.");
            } else throw ApiError(400,"Invalid log filters.");
    }
    try { return read_logs(config,service,level,limit,search,cursor); }
    catch (const std::invalid_argument&) { throw ApiError(400,"Invalid log filters or limit."); }
}

struct ViewBudget {
    std::size_t forwarded = 0, images = 0, image_bytes = 0;
};
struct ViewBody {
    std::string text, html;
    Json forwarded = Json::array(), inline_images = Json::array();
};

std::string content_id(const mime::Part& part) {
    auto id = trim(mime::header(part, "content-id"));
    if (id.size() >= 2 && id.front() == '<' && id.back() == '>') id = id.substr(1, id.size() - 2);
    return id;
}

bool attachment(const mime::Part& part) {
    const auto disposition = mime::header(part, "content-disposition");
    return lower(trim(disposition.substr(0, disposition.find(';')))) == "attachment" ||
        !mime::parameter(disposition, "filename").empty() ||
        !mime::parameter(mime::header(part, "content-type"), "name").empty();
}

void inline_images(const mime::Part& part, ViewBody& out, ViewBudget& budget) {
    // Never send active formats such as SVG, or images from an attached message.
    if (part.content_type == "message/rfc822") return;
    const auto disposition = lower(trim(mime::header(part, "content-disposition")));
    if (disposition.starts_with("attachment")) return;
    const auto id = content_id(part);
    const bool raster = part.content_type == "image/png" || part.content_type == "image/jpeg" ||
        part.content_type == "image/gif" || part.content_type == "image/webp";
    constexpr std::size_t max_image_bytes = 5 * 1024 * 1024;
    if (raster && !id.empty() && id.size() <= 998 && budget.images < 64 &&
        part.body.size() <= max_image_bytes - budget.image_bytes) {
        out.inline_images.push_back({{"cid", id}, {"content_type", part.content_type}, {"data", base64_encode(part.body)}});
        ++budget.images; budget.image_bytes += part.body.size();
    }
    for (const auto& child : part.parts) inline_images(child, out, budget);
}

Json part_view(const mime::Part& part, ViewBudget& budget, std::size_t depth);

ViewBody view_body(const mime::Part& part, ViewBudget& budget, std::size_t depth) {
    ViewBody out;
    if (part.content_type == "message/rfc822") {
        if (!part.parts.empty() && budget.forwarded < 32 && depth < 8) {
            ++budget.forwarded;
            out.forwarded.push_back(part_view(part.parts.front(), budget, depth + 1));
        }
        return out;
    }
    if (part.content_type.starts_with("image/")) {
        inline_images(part, out, budget);
        return out;
    }
    if (attachment(part)) return out;
    if (part.content_type == "text/plain") out.text = mime::decode_text(part);
    else if (part.content_type == "text/html") out.html = mime::decode_text(part);
    else if (part.content_type == "multipart/related" && !part.parts.empty()) {
        auto start = mime::parameter(mime::header(part, "content-type"), "start");
        if (start.size() >= 2 && start.front() == '<' && start.back() == '>') start = start.substr(1, start.size() - 2);
        const mime::Part* root = &part.parts.front();
        if (!start.empty()) {
            for (const auto& child : part.parts) if (content_id(child) == start) { root = &child; break; }
        }
        out = view_body(*root, budget, depth);
        for (const auto& child : part.parts) if (&child != root) inline_images(child, out, budget);
    } else if (part.content_type.starts_with("multipart/")) {
        const bool alternative = part.content_type == "multipart/alternative";
        for (const auto& child : part.parts) {
            auto body = view_body(child, budget, depth);
            auto merge = [alternative](std::string& target, std::string& value) {
                if (value.empty()) return;
                if (alternative || target.empty()) target = std::move(value);
                else target += "\n" + value;
            };
            merge(out.text, body.text); merge(out.html, body.html);
            for (auto& forward : body.forwarded) out.forwarded.push_back(std::move(forward));
            for (auto& image : body.inline_images) out.inline_images.push_back(std::move(image));
        }
    }
    return out;
}

Json part_view(const mime::Part& part, ViewBudget& budget, std::size_t depth) {
    auto body = view_body(part, budget, depth);
    return {{"subject", mime::decode_header(mime::header(part, "subject"))},
            {"from", mime::decode_header(mime::header(part, "from"))},
            {"to", mime::decode_header(mime::header(part, "to"))},
            {"date", mime::header(part, "date")},
            {"text", std::move(body.text)}, {"html", std::move(body.html)},
            {"forwarded", std::move(body.forwarded)}, {"inline_images", std::move(body.inline_images)}};
}

Json message_view(const std::string& raw) {
    try {
        auto part = mime::parse(raw);
        ViewBudget budget;
        return part_view(part, budget, 0);
    } catch (const std::exception&) {
        return {{"subject", ""}, {"from", ""}, {"to", ""}, {"date", ""},
                {"text", "The message could not be decoded. View the original message below."},
                {"html", ""}, {"forwarded", Json::array()}, {"inline_images", Json::array()}};
    }
}

struct WebSession {
    std::string username, csrf, credential_version;
    bool admin = false;
    Clock::time_point expires;
    std::string api_key_id;
};

class Web {
public:
    explicit Web(const Config& config) : config_(config) {
        session_seconds_ = std::clamp(config_.number("web_session_seconds", 3600), 60, 86400);
        session_limit_ = static_cast<std::size_t>(std::clamp(config_.number("max_web_sessions", 1024), 1, 10000));
        const auto root = std::filesystem::path(config_.text("web_root", "web"));
        load_static(root, "/", admin_only ? "admin.html" : "index.html", "text/html; charset=utf-8");
        if (admin_only) {
            acme_ = std::make_unique<AcmeManager>(AcmeOptions{config_.source.parent_path()/"certificates"});
            backups_ = std::make_unique<BackupManager>(config_);
            load_static(root, "/admin.js", "admin.js", "application/javascript; charset=utf-8");
            load_static(root, "/settings.js", "settings.js", "application/javascript; charset=utf-8");
            load_static(root, "/acme.js", "acme.js", "application/javascript; charset=utf-8");
            load_static(root, "/mail-clients.js", "mail-clients.js", "application/javascript; charset=utf-8");
            load_static(root, "/admin-dns.js", "admin-dns.js", "application/javascript; charset=utf-8");
            load_static(root, "/update.js", "update.js", "application/javascript; charset=utf-8");
            load_static(root, "/admin-access.js", "admin-access.js", "application/javascript; charset=utf-8");
        } else {
            load_static(root, "/app.js", "app.js", "application/javascript; charset=utf-8");
            load_static(root, "/verification-code.js", "verification-code.js", "application/javascript; charset=utf-8");
            load_static(root, "/verification-code.css", "verification-code.css", "text/css; charset=utf-8");
            load_static(root, "/register", "register.html", "text/html; charset=utf-8");
            load_static(root, "/register.js", "register.js", "application/javascript; charset=utf-8");
        }
        load_static(root, "/key-permissions.js", "key-permissions.js", "application/javascript; charset=utf-8");
        load_static(root, "/size.js", "size.js", "application/javascript; charset=utf-8");
        load_static(root, "/address.js", "address.js", "application/javascript; charset=utf-8");
        load_static(root, "/preferences.js", "preferences.js", "application/javascript; charset=utf-8");
        load_static(root, "/preferences.css", "preferences.css", "text/css; charset=utf-8");
        load_static(root, "/icons.svg", "icons.svg", "image/svg+xml");
        load_static(root, "/favicon.svg", "favicon.svg", "image/svg+xml");
        load_static(root, "/i18n.js", "i18n.js", "application/javascript; charset=utf-8");
        load_static(root, "/style.css", "style.css", "text/css; charset=utf-8");
        load_static(root, "/mail-reader.js", "mail-reader.js", "application/javascript; charset=utf-8");
        load_static(root, "/mail-reader.css", "mail-reader.css", "text/css; charset=utf-8");
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
        catch (const AcmeError& error) { response = json_response({{"ok",false},{"code",error.code},{"error",error.what()}},error.status); }
        catch (const UpdateError& error) { response = json_response({{"ok",false},{"code",error.code},{"error",error.what()}},error.status); }
        catch (const MaintenanceError& error) { response = json_response({{"ok",false},{"error",error.what()}},error.status); }
        catch (const Json::exception&) { response = json_response({{"ok", false}, {"error", "Invalid request data."}}, 400); }
        catch (const std::exception&) { response = json_response({{"ok", false}, {"error", "A required service is unavailable. Please retry."}}, 503); }
        response.headers["Cache-Control"] = "no-store";
        response.headers["X-Content-Type-Options"] = "nosniff";
        response.headers["X-Frame-Options"] = "DENY";
        response.headers["Referrer-Policy"] = "no-referrer";
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: https: http:; frame-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
        return response;
    }

    std::optional<HttpResponse> preflight(const HttpRequest& request) {
        if (forbidden_portal_route(request))
            return json_response({{"ok",false},{"error","API route not found."}},404);
        // Verify session and CSRF before core allocates a potentially large compose body.
        if (!request.path.starts_with("/api/") || request.path == "/api/login" || public_invitation_route(request) ||
            (request.method == "GET" && request.path == "/api/public/config")) return std::nullopt;
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
    static bool public_invitation_route(const HttpRequest& request) {
        return !admin_only && request.method == "POST" &&
            (request.path == "/api/public/invitations/inspect" || request.path == "/api/public/invitations/redeem");
    }
    Config config_;
    std::unique_ptr<AcmeManager> acme_;
    std::unique_ptr<BackupManager> backups_;
    std::mutex maintenance_mutex_;
    bool shutting_down_ = false;
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
        // An explicitly supplied credential is authoritative. Never fall back
        // to a browser cookie when a Bearer credential is invalid or misplaced.
        if (request.headers.contains("authorization")) {
            if (!request.encrypted && !request.peer_loopback)
                throw ApiError(403, "HTTPS is required to use an API key remotely.");
            const auto path = request.path.substr(0, request.path.find('?'));
            if (api_key_management_route(path))
                throw ApiError(403, "Use a browser session to manage API keys.");
            const auto authorization = header(request, "authorization");
            if (authorization.size() != 74 || lower(authorization.substr(0, 7)) != "bearer ")
                throw ApiError(401, "Invalid or expired API key.");
            const auto account = rpc(config_, "auth", {{"op", "api_key_verify"}, {"key", authorization.substr(7)}});
            require_ok(account, "A required service is unavailable. Please retry.");
            if (!account.value("valid", false)) throw ApiError(401, "Invalid or expired API key.");
            if (account.value("audience", std::string{}) != (admin_only ? "admin" : "mailbox"))
                throw ApiError(403, "This API key belongs to a different API.");
            const auto permission = required_api_permission(request.method, path);
            if (!permission || !account.contains("permissions") ||
                std::find(account["permissions"].begin(), account["permissions"].end(), *permission) == account["permissions"].end())
                throw ApiError(403, "This API key does not have permission for this operation.");
            WebSession session;
            session.username = account.at("username").get<std::string>();
            session.admin = account.value("admin", false);
            session.api_key_id = account.at("id").get<std::string>();
            return session;
        }
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
        if (!session.api_key_id.empty()) return;
        if (!secure_equal(header(request, "x-csrf-token"), session.csrf))
            throw ApiError(403, "Security token is missing or expired. Refresh this page.");
    }

    HttpResponse login(const HttpRequest& request) {
        require_transport(request);
        allow_login(request);
        auto input = request_json(request);
        auto username = username_field(input);
        auto password = field(input, "password", 4096);
        auto user = rpc(config_, "auth", {{"op", "verify"}, {"username", username}, {"password", password}, {"session", true}});
        if (!user.value("ok",false)) log(service_name,"sign-in failed for " + username + " from " + request.peer_address,"warn");
        require_ok(user, "The email address or password is incorrect.", 401);
        if (admin_only && !user.value("admin",false)) throw ApiError(403,"Administrator access is required.");
        auto token = random_hex(32);
        WebSession session{user.at("username").get<std::string>(), random_hex(32), user.at("credential_version").get<std::string>(), user.value("admin", false),
                           Clock::now() + std::chrono::seconds(session_seconds_), {}};
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
    HttpResponse save_draft(const HttpRequest& request, const WebSession& session);

    HttpResponse manage_api_keys(const HttpRequest& request, const WebSession& session, const std::string& path) {
        if (!session.api_key_id.empty()) throw ApiError(403, "Use a browser session to manage API keys.");
        require_csrf(request, session);
        const std::string base = admin_only ? "/api/admin/api-keys" : "/api/api-keys";
        Json command{{"username",session.username},{"audience",admin_only ? "admin" : "mailbox"}};
        if (path == base) {
            if (request.method == "GET") command["op"] = "api_key_list";
            else if (request.method == "POST") {
                const auto input = request_json(request);
                for (const auto& item : input.items()) {
                    if (item.key() != "name" && item.key() != "expires_in_days" && item.key() != "permissions")
                        throw ApiError(400, "Unexpected API key field: " + item.key());
                    command[item.key()] = item.value();
                }
                command["op"] = "api_key_create";
            } else throw ApiError(405, "Use GET or POST.");
        } else {
            const auto id = path.substr(base.size()+1);
            if (id.size()!=32 || !std::all_of(id.begin(),id.end(),[](unsigned char ch){return (ch>='0'&&ch<='9')||(ch>='a'&&ch<='f');}))
                throw ApiError(400,"Invalid API key ID.");
            command["id"]=id;
            if (request.method == "DELETE") command["op"]="api_key_revoke";
            else if (request.method == "PATCH") {
                const auto input=request_json(request);
                if (input.size()!=1 || !input.contains("permissions")) throw ApiError(400,"Provide only API key permissions.");
                command["op"]="api_key_update";command["permissions"]=input.at("permissions");
            } else throw ApiError(405,"Use PATCH or DELETE.");
        }
        auto result=rpc(config_,"auth",command);
        if (!result.value("ok",false)) {
            const auto code=result.value("code",std::string{});
            if (code=="invalid_api_key") return json_response(result,400);
            if (code=="api_key_not_found") return json_response(result,404);
            if (code=="api_key_limit") return json_response(result,409);
            if (code=="administrator_required") return json_response(result,403);
            require_ok(result,"Unable to manage API keys.");
        }
        return json_response(result,request.method=="POST"?201:200);
    }

    HttpResponse route(const HttpRequest& request) {
        if (forbidden_portal_route(request))
            throw ApiError(404, "API route not found.");
        if (request.method == "GET" && request.path == "/health")
            return json_response({{"ok", true}, {"service", service_name}});
        if (request.method == "GET" && request.path == "/api/public/config")
            return json_response({{"ok", true}, {"domain", config_.text("domain", "localhost")}});
        if (!admin_only)
            if (auto discovered = mail_client_discovery(config_, request)) return *discovered;
        if (request.method == "GET") {
            auto path = request.path == (admin_only ? "/admin.html" : "/index.html") ||
                        (admin_only && request.path == "/admin") ? "/" : request.path;
            auto asset = assets_.find(path);
            if (asset != assets_.end()) return asset->second;
        }
        if (!request.path.starts_with("/api/")) throw ApiError(404, "Page not found.");
        if (request.method == "POST" && request.path == "/api/login") return login(request);
        if (public_invitation_route(request)) {
            require_transport(request);
            allow_login(request);
            auto input = request_json(request);
            const bool redeem = request.path.ends_with("/redeem");
            for (const auto& item : input.items())
                if (item.key() != "token" && !(redeem && (item.key() == "localpart" || item.key() == "password")))
                    throw ApiError(400, "Unexpected registration field.");
            input["token"] = field(input, "token", 71);
            input["op"] = redeem ? "invite_redeem" : "invite_inspect";
            auto result = rpc(config_, "auth", input);
            if (!result.value("ok", false)) {
                const auto code = result.value("code", std::string{});
                if (code == "user_exists") return json_response(result, 409);
                if (code == "invitation_unavailable") return json_response(result, 410);
                if (code == "rate_limit") return json_response(result, 429);
                if (code == "invalid_invitation" || code == "password_policy_violation") return json_response(result, 400);
                require_ok(result, "Unable to register this mailbox.");
            }
            if (redeem) log(service_name, "mailbox registered by invitation: " + result.value("username", std::string{}));
            return json_response(result, redeem ? 201 : 200);
        }
        const auto session = authenticate(request);
        if (request.method != "GET") require_csrf(request, session);
        const auto path = request.path.substr(0,request.path.find('?'));
        const auto query = query_fields(request.path);
        auto parameter = [&](const std::string& key, const std::string& fallback = "") { auto found=query.find(key); return found==query.end()?fallback:found->second; };
        if (api_key_management_route(path)) return manage_api_keys(request, session, path);
        if (request.method == "GET" && path == "/api/verification-code") {
            if (!query.empty()) throw ApiError(400, "Verification code lookup does not accept account or message filters.");
            const auto candidates = rpc(config_, "storage", {{"op","verification_candidates"},{"username",session.username},{"max_age_seconds",900},{"limit",30}});
            require_ok(candidates, "Unable to load verification codes.");
            const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            for (const auto& candidate : candidates.at("messages")) {
                const auto received = candidate.at("internal_date").get<std::int64_t>();
                if (received > now + 60 || received + 900 <= now) continue;
                mime::Part part;
                try { part=mime::parse(candidate.at("raw").get<std::string>()); }
                catch(const std::exception&) { continue; }
                const auto code = extract_verification_code(part);
                if (!code) continue;
                return json_response({{"ok",true},{"found",true},{"code",code->code},{"message_id",candidate.at("id")},
                    {"from",mime::decode_header(mime::header(part,"from"))},{"subject",mime::decode_header(mime::header(part,"subject"))},
                    {"received_at",received},{"expires_at",received+900}});
            }
            return json_response({{"ok",true},{"found",false}});
        }
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
        if (request.method == "GET" && path == "/api/folders") {
            auto result = rpc(config_, "storage", {{"op", "folders"}, {"username", session.username}});
            require_ok(result,"Unable to load messages.");
            for(auto& folder:result["folders"]) { folder["total"]=folder["messages"]; folder["unread"]=folder["unseen"]; }
            return json_response(result);
        }
        if (request.method == "POST" && path == "/api/drafts") return save_draft(request,session);
        if (request.method == "GET" && path == "/api/messages") {
            auto result = rpc(config_, "storage", {{"op", "list"}, {"username", session.username}, {"folder",folder_name(parameter("folder","INBOX"))}, {"include_envelope", true}});
            require_ok(result, "Unable to load messages.");
            return json_response(result);
        }
        if (path.starts_with("/api/messages/")) {
            const bool moving=path.ends_with("/move");
            auto id = message_id(path.substr(14,path.size()-14-(moving?5:0)));
            if(moving && request.method=="POST") {
                auto input=request_json(request);
                auto result=rpc(config_,"storage",{{"op","move"},{"username",session.username},{"ids",Json::array({id})},{"folder",folder_name(field(input,"folder",32))}});
                require_ok(result,"Unable to move message.",400);
                return json_response(result);
            }
            if(moving) throw ApiError(404,"API route not found.");
            if (request.method == "GET") {
                auto result = rpc(config_, "storage", {{"op", "get"}, {"username", session.username}, {"id", id}});
                require_ok(result, "Message not found.", 404);
                auto marked = rpc(config_, "storage", {{"op", "flags"}, {"username", session.username}, {"id", id}, {"seen", true},{"uid",result.at("uid")}});
                require_ok(marked, "Unable to update message flags.");
                result["message"] = message_view(result.at("raw").get<std::string>());
                return json_response(result);
            }
            if (request.method == "DELETE") {
                const auto message=rpc(config_,"storage",{{"op","get"},{"username",session.username},{"id",id}});
                require_ok(message,"Message not found.",404);
                if(query.contains("permanent") && parameter("permanent")!="true" && parameter("permanent")!="false") throw ApiError(400,"Invalid deletion mode.");
                const bool permanent=parameter("permanent")=="true";
                if(permanent && message.value("folder",std::string{})!="Trash") throw ApiError(409,"Move the message to Trash before permanently deleting it.");
                auto result = rpc(config_, "storage", {{"op", "delete"}, {"username", session.username}, {"ids", Json::array({id})},{"permanent",permanent},
                    {"folder",message.at("folder")},{"expected_uids",{{id,message.at("uid")}}}});
                require_ok(result, "Unable to delete message.");
                log(service_name,"message deleted by " + session.username + ": " + id);
                return json_response(result);
            }
        }
        if (request.method == "POST" && request.path == "/api/send") return send_mail(request, session);
        if (request.path.starts_with("/api/admin/")) {
            if (!admin_only) throw ApiError(404,"API route not found.");
            if (!session.admin) throw ApiError(403, "Administrator access is required.");
            if (!session.api_key_id.empty() && request.method != "GET")
                log(service_name, "API key " + session.api_key_id + " owned by administrator " + session.username +
                    " requested " + request.method + " " + path);
            if (path == "/api/admin/invitations" || path.starts_with("/api/admin/invitations/")) {
                Json command{{"username",session.username}};
                if (path == "/api/admin/invitations") {
                    if (request.method == "GET") command["op"]="invite_list";
                    else if (request.method == "POST") {
                        const auto input=request_json(request);
                        for (const auto& item:input.items()) {
                            if (item.key()!="name" && item.key()!="localpart" && item.key()!="expires_in_days" && item.key()!="max_uses")
                                throw ApiError(400,"Unexpected invitation field.");
                            command[item.key()]=item.value();
                        }
                        command["op"]="invite_create";
                    } else throw ApiError(405,"Use GET or POST.");
                } else {
                    if (request.method!="DELETE") throw ApiError(405,"Use DELETE to revoke an invitation.");
                    command["op"]="invite_revoke";
                    command["id"]=path.substr(std::string("/api/admin/invitations/").size());
                }
                auto result=rpc(config_,"auth",command);
                if (!result.value("ok",false)) {
                    const auto code=result.value("code",std::string{});
                    if (code=="invalid_invitation") return json_response(result,400);
                    if (code=="invitation_not_found") return json_response(result,404);
                    if (code=="user_exists" || code=="invitation_limit") return json_response(result,409);
                    require_ok(result,"Unable to manage invitations.");
                }
                if (result.contains("token")) {
                    const auto settings=settings_view(config_);
                    result["registration_url"]=settings.at("web_url").get<std::string>()+"register#"+result.at("token").get<std::string>();
                    result.erase("token");
                }
                return json_response(result,request.method=="POST"?201:200);
            }
            if (path == "/api/admin/forwarding" || path.starts_with("/api/admin/forwarding/")) {
                Json command;
                if (path == "/api/admin/forwarding") {
                    if (request.method=="GET") command={{"op","forwarding_list"}};
                    else if (request.method=="POST") {
                        const auto input=request_json(request);
                        if (input.size()!=2 || !input.contains("pattern") || !input.contains("destination"))
                            throw ApiError(400,"Provide a pattern and destination mailbox.");
                        command={{"op","forwarding_create"},{"pattern",field(input,"pattern",254)},{"destination",field(input,"destination",254)}};
                    } else throw ApiError(405,"Use GET or POST.");
                } else {
                    if (request.method!="DELETE") throw ApiError(405,"Use DELETE to remove a forwarding rule.");
                    const auto text=path.substr(std::string("/api/admin/forwarding/").size());
                    std::int64_t id=0;const auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),id);
                    if(error!=std::errc{} || end!=text.data()+text.size() || id<=0) throw ApiError(400,"Invalid forwarding rule ID.");
                    command={{"op","forwarding_delete"},{"id",id}};
                }
                auto result=rpc(config_,"storage",command);
                if (!result.value("ok",false)) return json_response(result, result.value("code",std::string{})=="forwarding_not_found"?404:400);
                if (request.method!="GET") log(service_name,"administrator "+session.username+" changed a forwarding rule");
                return json_response(result,request.method=="POST"?201:200);
            }
            if (request.method == "POST" && path == "/api/admin/backup") {
                (void)request_json(request);
                std::lock_guard lock(maintenance_mutex_);
                if (shutting_down_) throw ApiError(409, "The server is shutting down.");
                if(supervisor_restart_busy(config_)) throw ApiError(409,"Wait for the service restart to finish before starting a backup.");
                const auto result = backups_->start();
                log(service_name, "administrator " + session.username + " requested a data backup");
                return json_response(result, 202);
            }
            if (request.method == "GET" && (path == "/api/admin/backup" || path == "/api/admin/backup/download")) {
                if (path == "/api/admin/backup/download") {
                    auto response = backups_->download(parameter("job_id"));
                    log(service_name, "administrator " + session.username + " downloaded a data backup");
                    return response;
                }
                return json_response(backups_->status(parameter("job_id")));
            }
            if (request.method == "POST" && path == "/api/admin/shutdown") {
                (void)request_json(request);
                std::lock_guard lock(maintenance_mutex_);
                if (shutting_down_) throw ApiError(409, "The server is already shutting down.");
                if (backups_->busy()) throw ApiError(409, "Wait for the data backup to finish before shutting down.");
                if(supervisor_restart_busy(config_)) throw ApiError(409,"Wait for the service restart to finish before shutting down.");
                request_supervisor_shutdown(config_);
                shutting_down_ = true;
                log(service_name, "administrator " + session.username + " requested server shutdown");
                return json_response({{"ok", true}, {"state", "shutting_down"}}, 202);
            }
            if (path == "/api/admin/password-policy") {
                Json command = {{"op", "password_policy_get"}};
                if (request.method == "POST") {
                    command = request_json(request);
                    if (command.contains("op")) throw ApiError(400, "Unexpected password policy field: op");
                    command["op"] = "password_policy_set";
                } else if (request.method != "GET") throw ApiError(405, "Use GET or POST.");
                auto result = rpc(config_, "auth", command);
                if (!result.value("ok", false)) {
                    const auto code = result.value("code", std::string{});
                    if (code == "invalid_password_policy") return json_response(result, 400);
                    if (code == "password_policy_conflict") return json_response(result, 409);
                    require_ok(result, "Unable to load or save the account password policy.");
                }
                if (request.method == "POST") log(service_name, "administrator " + session.username +
                    " saved account password policy revision " + std::to_string(result.at("revision").get<std::int64_t>()));
                return json_response(result);
            }
            if(path.starts_with("/api/admin/acme/")) {
                if(request.method=="GET" && path=="/api/admin/acme/terms") return json_response(acme_->terms(parameter("directory","staging")));
                if(request.method=="GET" && path=="/api/admin/acme/status") return json_response(acme_->status(parameter("job_id")));
                if(request.method=="POST" && path=="/api/admin/acme/start") {
                    auto result=acme_->start(request_json(request));
                    log(service_name,"administrator " + session.username + " requested a TLS certificate");
                    return json_response(result,202);
                }
                if(request.method=="POST" && path=="/api/admin/acme/cancel") return json_response(acme_->cancel(field(request_json(request),"job_id",128)));
                throw ApiError(404,"API route not found.");
            }
            if(path=="/api/admin/messages" || path.starts_with("/api/admin/messages/") || path=="/api/admin/quota") {
                if(path!="/api/admin/quota" && request.method!="GET") throw ApiError(405,"Administrator mail inspection is read-only.");
                auto input=request.method=="GET" ? Json{{"username",parameter("username")}} : request_json(request);
                const auto username=username_field(input);
                auto exists=rpc(config_,"auth",{{"op","exists"},{"username",username}});
                require_ok(exists,"Unable to load accounts.");
                if(!exists.value("exists",false)) throw ApiError(404,"Account not found.");
                if(path=="/api/admin/quota") {
                    Json command{{"op",request.method=="GET"?"quota_get":"quota_set"},{"username",username}};
                    if(request.method=="POST") {
                        if(!input.contains("quota_bytes")) throw ApiError(400,"A quota is required.");
                        const auto& quota=input["quota_bytes"];
                        if(!quota.is_null() && (!quota.is_number_integer() ||
                            (quota.is_number_unsigned() && quota.get<std::uint64_t>()>UINT64_C(1125899906842624)) ||
                            quota.get<std::int64_t>()<1 || quota.get<std::int64_t>()>INT64_C(1125899906842624)))
                            throw ApiError(400,"Invalid account quota.");
                        command["max_bytes"]=input["quota_bytes"];
                    } else if(request.method!="GET") throw ApiError(405,"Use GET or POST.");
                    auto result=rpc(config_,"storage",command);
                    require_ok(result,"Invalid account quota.",400);
                    if(request.method=="POST") log(service_name,"administrator " + session.username + " changed quota for " + username);
                    return json_response(result);
                }
                if(request.method!="GET") throw ApiError(405,"Administrator mail inspection is read-only.");
                if(path=="/api/admin/messages") {
                    auto result=rpc(config_,"storage",{{"op","list"},{"username",username},{"folder",folder_name(parameter("folder","INBOX"))},{"include_envelope",true}});
                    require_ok(result,"Unable to load messages.");
                    log(service_name,"administrator " + session.username + " inspected mailbox " + username);
                    return json_response(result);
                }
                const auto id=message_id(path.substr(std::string("/api/admin/messages/").size()));
                auto result=rpc(config_,"storage",{{"op","get"},{"username",username},{"id",id}});
                require_ok(result,"Message not found.",404);
                result["message"]=message_view(result.at("raw").get<std::string>());
                log(service_name,"administrator " + session.username + " inspected message " + id + " in mailbox " + username);
                return json_response(result);
            }
            if ((request.method == "GET" && path == "/api/admin/dns") ||
                (request.method == "POST" && path == "/api/admin/dns/check")) {
                const auto saved=Config::from_file(config_.source);
                try {
                    if(request.method=="GET") return json_response(dns_recommendations(saved));
                    return json_response(DnsChecker().check_server(saved,request_json(request)));
                } catch(const DnsError& error) {
                    return json_response({{"ok",false},{"code",error.code},{"error",error.what()}},400);
                }
            }
            if (request.path == "/api/admin/config") {
                if (request.method == "GET") return json_response(settings_view(config_));
                if (request.method == "POST") {
                    std::lock_guard lock(maintenance_mutex_);
                    if (shutting_down_ || backups_->busy()) throw ApiError(409, "Wait for the backup or shutdown operation to finish before saving configuration.");
                    if(supervisor_restart_busy(config_)) throw ApiError(409,"Wait for the service restart to finish before saving configuration.");
                    auto input=request_json(request);
                    bool apply=true;
                    if(input.contains("apply")) {
                        if(!input.at("apply").is_boolean()) throw ApiError(400,"The apply field must be a boolean.");
                        apply=input.at("apply").get<bool>();
                        input.erase("apply");
                    }
                    auto result=save_settings(config_,input);
                    result["restart_available"]=supervisor_restart_available(config_);
                    if(apply && result.at("restart_available").get<bool>()) {
                        try {
                            result["restart"]=request_supervisor_restart(config_,Config::from_file(config_.source));
                            result["restart_required"]=false;
                        } catch(const MaintenanceError& error) {
                            result["restart_error"]=error.what();
                        }
                    }
                    return json_response(result);
                }
            }
            if(path=="/api/admin/restart") {
                if(request.method=="GET") return json_response(supervisor_restart_status(config_,parameter("job_id")));
                if(request.method=="POST") {
                    std::lock_guard lock(maintenance_mutex_);
                    if(shutting_down_ || backups_->busy()) throw ApiError(409,"Wait for the backup or shutdown operation to finish before restarting services.");
                    const auto input=request_json(request);
                    if(!input.is_object() || input.size()!=1 || !input.contains("mode") || !input.at("mode").is_string())
                        throw ApiError(400,"Choose a restart mode: changed or all.");
                    const auto mode=input.at("mode").get<std::string>();
                    if(mode!="changed" && mode!="all") throw ApiError(400,"Choose a restart mode: changed or all.");
                    return json_response(request_supervisor_restart(config_,Config::from_file(config_.source),mode),202);
                }
                throw ApiError(405,"Use GET or POST.");
            }
            if(path=="/api/admin/update" && request.method=="GET")
                return json_response(supervisor_update_status(config_,parameter("job_id")));
            if(path.starts_with("/api/admin/update/")) {
                if(request.method!="POST") throw ApiError(405,"Use POST for update actions.");
                const auto input=request_json(request);
                if(path=="/api/admin/update/check") {
                    if(!input.empty()) throw ApiError(400,"Update check accepts an empty object.");
                    auto result=check_update(supervisor_update_options(config_));
                    result["update_available"]=result.value("available",false);
                    result["available"]=supervisor_restart_available(config_);
                    result["state"]="idle";
                    return json_response(result);
                }
                std::lock_guard lock(maintenance_mutex_);
                if(shutting_down_ || backups_->busy()) throw ApiError(409,"Wait for the backup or shutdown operation to finish before updating.");
                const auto action=path.substr(std::string("/api/admin/update/").size());
                if(action!="stage" && action!="apply") throw ApiError(404,"API route not found.");
                const std::string key=action=="stage"?"version":"job_id";
                if(input.size()!=1 || !input.contains(key) || !input.at(key).is_string())
                    throw ApiError(400,"Provide the reviewed update version or downloaded job ID.");
                auto result=request_supervisor_update(config_,action,input.at(key).get<std::string>());
                log(service_name,"administrator "+session.username+" requested update "+action);
                return json_response(result,202);
            }
            if(request.path=="/api/admin/dkim" && request.method=="POST") {
                std::lock_guard lock(maintenance_mutex_);
                if(shutting_down_ || backups_->busy()) throw ApiError(409,"Wait for the backup or shutdown operation to finish before saving configuration.");
                if(supervisor_restart_busy(config_)) throw ApiError(409,"Wait for the service restart to finish before saving configuration.");
                return json_response(prepare_dkim(Config::from_file(config_.source),request_json(request)));
            }
            if (request.method == "GET" && (request.path == "/api/admin/logs" || request.path.starts_with("/api/admin/logs?")))
                return json_response(log_query(config_,request.path));
            if (request.method == "GET" && request.path == "/api/admin/users") {
                auto result = rpc(config_, "auth", {{"op", "list"}});
                require_ok(result, "Unable to load accounts.");
                return json_response(result);
            }
            if (request.method == "DELETE" && request.path == "/api/admin/users") {
                const auto input = request_json(request);
                const auto username = username_field(input);
                if (input.size() != 2 || !input.contains("confirm_username") || !input.at("confirm_username").is_string() ||
                        lower(trim(input.at("confirm_username").get<std::string>())) != username)
                    throw ApiError(400, "Type the complete email address to confirm account deletion.");
                auto prepared = rpc(config_, "auth", {{"op", "user_delete"}, {"username", username}, {"actor", session.username}});
                if (!prepared.value("ok", false)) return json_response(prepared, prepared.value("code", std::string{}) == "account_not_found" ? 404 : 409);
                try {
                    auto cleaned = rpc(config_, "storage", {{"op", "mailbox_delete"}, {"username", username}});
                    require_ok(cleaned, "The account is disabled. Retry deletion to finish removing its mailbox.", 503);
                    auto result = rpc(config_, "auth", {{"op", "user_delete_finish"}, {"username", username}, {"actor", session.username}, {"cleanup_id", prepared.at("cleanup_id")}});
                    require_ok(result, "The account is disabled. Retry deletion to finish removing its mailbox.", 503);
                } catch (const std::exception&) {
                    return json_response({{"ok", false}, {"code", "account_cleanup_pending"}, {"error", "The account is disabled. Retry deletion to finish removing its mailbox."}}, 503);
                }
                { std::lock_guard lock(mutex_); std::erase_if(sessions_, [&username](const auto& item) { return item.second.username == username; }); }
                log(service_name, "administrator " + session.username + " deleted account " + username);
                return json_response({{"ok", true}, {"username", username}});
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
                if (result.value("code", std::string{}) == "password_policy_violation") return json_response(result, 400);
                require_ok(result, "Unable to create account. This address may already exist.", 409);
                log(service_name,"administrator " + session.username + " created account " + username);
                return json_response(result, 201);
            }
            if (request.method == "POST" && request.path == "/api/admin/password") {
                const auto input = request_json(request);
                const auto username = username_field(input);
                const auto password = password_field(input);
                auto result = rpc(config_, "auth", {{"op", "change_password"}, {"username", username}, {"password", password}});
                if (result.value("code", std::string{}) == "password_policy_violation") return json_response(result, 400);
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
    Json routes=Json::object();
    const auto domain = lower(config_.text("domain", "localhost"));
    for (const auto& address : input["to"]) {
        if (!address.is_string()) throw ApiError(400, "Recipient addresses must be strings.");
        auto recipient = lower(trim(address.get<std::string>()));
        if (!valid_address(recipient)) throw ApiError(400, "Invalid recipient address.");
        if (!unique.insert(recipient).second) continue;
        if (recipient.substr(recipient.find('@') + 1) == domain) {
            const auto route=resolve_local_recipient(config_,recipient);
            require_ok(route,"Unable to validate recipients.");
            if (!route.value("exists",false)) throw ApiError(400,"A local recipient account does not exist: "+recipient);
            routes[recipient]={{"destination",route.at("destination")},{"rule",route.at("rule")}};
        } else if (config_.outbound_mode()=="disabled") {
            throw ApiError(400, "External delivery is disabled. Ask an administrator to enable direct delivery or an SMTP relay.");
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
    Json submission={{"op", "enqueue"}, {"sender", session.username}, {"recipients", recipients}, {"raw", raw},{"sent_username",session.username},{"recipient_routes",routes}};
    if(input.contains("draft_id")) submission["draft_id"]=message_id(field(input,"draft_id",128));
    const auto result = rpc(config_, "storage", submission);
    require_ok(result, "Unable to queue your message.");
    log(service_name,"message queued by " + session.username + " for " + std::to_string(recipients.size()) + " recipients");
    return json_response(result, 202);
}
HttpResponse Web::save_draft(const HttpRequest& request, const WebSession& session) {
    const auto input=request_json(request);
    const auto maximum=static_cast<std::size_t>(config_.number("max_message_bytes",10485760));
    const auto subject=field(input,"subject",512), text=field(input,"text",maximum);
    if(!input.contains("to") || !input["to"].is_array() || input["to"].size()>100) throw ApiError(400,"Invalid recipient address.");
    std::vector<std::string> recipients;
    for(const auto& address:input["to"]) {
        if(!address.is_string() || !valid_address(address.get<std::string>())) throw ApiError(400,"Invalid recipient address.");
        recipients.push_back(address.get<std::string>());
    }
    std::string raw;
    try {raw=mime::compose(session.username,recipients,subject,text,true);}
    catch(const std::exception&) {throw ApiError(400,"The message contains invalid headers or content.");}
    if(raw.size()>maximum) throw ApiError(413,"The encoded message exceeds the server size limit.");
    Json command={{"op","draft_save"},{"username",session.username},{"raw",raw}};
    if(input.contains("id")) command["id"]=message_id(field(input,"id",128));
    const auto result=rpc(config_,"storage",command);
    require_ok(result,"Unable to save draft. Check your mailbox capacity.",409);
    return json_response(result);
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
