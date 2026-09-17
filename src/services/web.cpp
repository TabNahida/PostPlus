#include "postplus/core.hpp"
#include "postplus/mime.hpp"
#include "postplus/settings.hpp"
#include "postplus/acme.hpp"
#include "postplus/maintenance.hpp"

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
        (admin_only && (path.starts_with("/api/messages") || path=="/api/folders" || path=="/api/drafts" || path=="/api/send"));
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
            acme_ = std::make_unique<AcmeManager>(AcmeOptions{config_.source.parent_path()/"certificates"});
            backups_ = std::make_unique<BackupManager>(config_);
            load_static(root, "/admin.js", "admin.js", "application/javascript; charset=utf-8");
            load_static(root, "/settings.js", "settings.js", "application/javascript; charset=utf-8");
            load_static(root, "/acme.js", "acme.js", "application/javascript; charset=utf-8");
        } else load_static(root, "/app.js", "app.js", "application/javascript; charset=utf-8");
        load_static(root, "/size.js", "size.js", "application/javascript; charset=utf-8");
        load_static(root, "/address.js", "address.js", "application/javascript; charset=utf-8");
        load_static(root, "/preferences.js", "preferences.js", "application/javascript; charset=utf-8");
        load_static(root, "/preferences.css", "preferences.css", "text/css; charset=utf-8");
        load_static(root, "/icons.svg", "icons.svg", "image/svg+xml");
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
        catch (const AcmeError& error) { response = json_response({{"ok",false},{"code",error.code},{"error",error.what()}},error.status); }
        catch (const MaintenanceError& error) { response = json_response({{"ok",false},{"error",error.what()}},error.status); }
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
        if (forbidden_portal_route(request))
            return json_response({{"ok",false},{"error","API route not found."}},404);
        // Verify session and CSRF before core allocates a potentially large compose body.
        if (!request.path.starts_with("/api/") || request.path == "/api/login" ||
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
        auto password = field(input, "password", 4096);
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
    HttpResponse save_draft(const HttpRequest& request, const WebSession& session);

    HttpResponse route(const HttpRequest& request) {
        if (forbidden_portal_route(request))
            throw ApiError(404, "API route not found.");
        if (request.method == "GET" && request.path == "/health")
            return json_response({{"ok", true}, {"service", service_name}});
        if (request.method == "GET" && request.path == "/api/public/config")
            return json_response({{"ok", true}, {"domain", config_.text("domain", "localhost")}});
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
        const auto path = request.path.substr(0,request.path.find('?'));
        const auto query = query_fields(request.path);
        auto parameter = [&](const std::string& key, const std::string& fallback = "") { auto found=query.find(key); return found==query.end()?fallback:found->second; };
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
            if (request.method == "POST" && path == "/api/admin/backup") {
                (void)request_json(request);
                std::lock_guard lock(maintenance_mutex_);
                if (shutting_down_) throw ApiError(409, "The server is shutting down.");
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
            if (request.path == "/api/admin/config") {
                if (request.method == "GET") return json_response(settings_view(config_));
                if (request.method == "POST") {
                    std::lock_guard lock(maintenance_mutex_);
                    if (shutting_down_ || backups_->busy()) throw ApiError(409, "Wait for the backup or shutdown operation to finish before saving configuration.");
                    return json_response(save_settings(config_, request_json(request)));
                }
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
    Json submission={{"op", "enqueue"}, {"sender", session.username}, {"recipients", recipients}, {"raw", raw},{"sent_username",session.username}};
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
