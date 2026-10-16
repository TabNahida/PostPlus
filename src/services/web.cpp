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
#include "postplus/remote_image.hpp"
#include "postplus/folders.hpp"

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
    std::int64_t retry_after;
    std::string code;
    ApiError(int status, const std::string& message, std::int64_t retry_after = 0, std::string code = {})
        : std::runtime_error(message), status(status), retry_after(retry_after), code(std::move(code)) {}
};
HttpResponse api_error_response(const ApiError& error) {
    Json body{{"ok",false},{"error",error.what()}};
    if (!error.code.empty()) body["code"]=error.code;
    if (error.retry_after>0) body["retry_after"]=error.retry_after;
    auto response=json_response(body,error.status);
    if (error.status==429) response.headers["Retry-After"]=std::to_string(error.retry_after>0?error.retry_after:60);
    return response;
}

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

std::string folder_name(const Config& config, const std::string& username, const std::string& name) {
    std::string normalized;
    try { normalized = normalize_mail_folder(name); }
    catch (const std::invalid_argument&) { throw ApiError(400,"Invalid mail folder."); }
    if (!is_system_mail_folder(normalized)) {
        const auto catalog = rpc(config,"storage",{{"op","folder_catalog"},{"username",username}});
        require_ok(catalog,"Unable to load mail folders.");
        const auto& folders = catalog.at("folders");
        if (std::none_of(folders.begin(),folders.end(),[&](const Json& item) {
                return item.at("name")==normalized && item.value("selectable",true);
            })) throw ApiError(400,"Unknown mail folder.");
    }
    return normalized;
}

Json search_query(const Config& config,const std::string& username,const std::map<std::string,std::string>& query,bool admin=false) {
    Json command{{"op","search"},{"username",username}};
    auto integer=[](const std::string& input,std::int64_t minimum,std::int64_t maximum) {
        std::int64_t number=0; const auto [end,error]=std::from_chars(input.data(),input.data()+input.size(),number);
        if(error!=std::errc{} || end!=input.data()+input.size() || number<minimum || number>maximum) throw ApiError(400,"Invalid search number.");
        return number;
    };
    for(const auto& [key,value]:query) {
        if(key=="username" && admin) continue;
        if(key=="q" || key=="from" || key=="to" || key=="subject") {
            if(value.size()>256) throw ApiError(400,"Search text is too long."); command[key]=value;
        } else if(key=="folder") command[key]=value=="all"?value:folder_name(config,username,value);
        else if(key=="seen" || key=="has_attachment") {
            if(value!="true" && value!="false") throw ApiError(400,"Search flags must be true or false."); command[key]=value=="true";
        } else if(key=="limit") command[key]=integer(value,1,100);
        else if(key=="offset") command[key]=integer(value,0,100000);
        else if(key=="after" || key=="before") {
            if(value.size()==10 && value[4]=='-' && value[7]=='-') {
                const auto year=integer(value.substr(0,4),1900,9999),month=integer(value.substr(5,2),1,12),day=integer(value.substr(8,2),1,31);
                const std::chrono::year_month_day date{std::chrono::year(static_cast<int>(year)),std::chrono::month(static_cast<unsigned>(month)),std::chrono::day(static_cast<unsigned>(day))};
                if(!date.ok()) throw ApiError(400,"Invalid search date.");
                command[key]=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::sys_days(date).time_since_epoch()).count();
            } else command[key]=integer(value,-2208988800LL,253402300799LL);
        } else throw ApiError(400,"Unknown search parameter.");
    }
    if(command.value("after",INT64_C(-2208988800))>=command.value("before",INT64_C(253402300799))) throw ApiError(400,"Search after must precede before.");
    return command;
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
        !mime::attachment_filename(part).empty();
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
            {"cc", mime::decode_header(mime::header(part, "cc"))},
            {"bcc", mime::decode_header(mime::header(part, "bcc"))},
            {"reply_to", mime::decode_header(mime::header(part, "reply-to"))},
            {"in_reply_to", mime::header(part,"in-reply-to")}, {"references",mime::header(part,"references")},
            {"date", mime::header(part, "date")},
            {"text", std::move(body.text)}, {"html", std::move(body.html)},
            {"forwarded", std::move(body.forwarded)}, {"inline_images", std::move(body.inline_images)}};
}

Json message_view(const std::string& raw) {
    try {
        auto part = mime::parse(raw, {.max_bytes=raw.size()});
        ViewBudget budget;
        auto view=part_view(part, budget, 0);
        std::map<std::string,std::size_t> indexes;
        std::function<void(Json&)> collect=[&](Json& message) {
            message["remote_images"]=Json::array();
            for(const auto& url:extract_remote_image_urls(message.value("html",std::string{}))) {
                if(!indexes.contains(url) && indexes.size()>=64) continue;
                const auto [position,added]=indexes.emplace(url,indexes.size());
                (void)added;
                message["remote_images"].push_back({{"url",url},{"index",position->second}});
            }
            for(auto& forwarded:message["forwarded"])collect(forwarded);
        };
        collect(view);
        view["attachments"]=Json::array();
        const auto files=mime::attachments(part);
        for(std::size_t index=0;index<files.size();++index)
            view["attachments"].push_back({{"index",index},{"filename",files[index].filename},{"content_type",files[index].content_type},{"size",files[index].data.size()}});
        return view;
    } catch (const std::exception&) {
        return {{"subject", ""}, {"from", ""}, {"to", ""}, {"date", ""},
                {"text", "The message could not be decoded. View the original message below."},
                {"html", ""}, {"forwarded", Json::array()}, {"inline_images", Json::array()}, {"attachments",Json::array()}};
    }
}

HttpResponse message_attachment(const std::string& raw,const std::string& value) {
    std::size_t index=256;
    const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),index);
    if(value.empty() || error!=std::errc{} || end!=value.data()+value.size() || index>=256) throw ApiError(400,"Invalid attachment index.");
    std::vector<mime::Attachment> files;
    try { files=mime::attachments(mime::parse(raw,{.max_bytes=raw.size()})); }
    catch(const std::exception&) {throw ApiError(422,"The message attachments could not be decoded.");}
    if(index>=files.size())throw ApiError(404,"Attachment not found in this message.");
    auto& file=files[index];
    std::string fallback,encoded; constexpr char digits[]="0123456789ABCDEF";
    for(unsigned char ch:file.filename) {
        fallback+=ch>=32 && ch<127 && ch!='"' && ch!='\\'?static_cast<char>(ch):'_';
        if((ch>='a'&&ch<='z') || (ch>='A'&&ch<='Z') || (ch>='0'&&ch<='9') || ch=='-' || ch=='_' || ch=='.')encoded+=static_cast<char>(ch);
        else {encoded+='%';encoded+=digits[ch>>4];encoded+=digits[ch&15];}
    }
    HttpResponse response; response.content_type="application/octet-stream";response.body=std::move(file.data);
    response.headers["Content-Disposition"]="attachment; filename=\""+fallback+"\"; filename*=UTF-8''"+encoded;
    return response;
}

HttpResponse message_image(const Json& view,const std::string& value) {
    std::size_t index=64;
    const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),index);
    if(value.empty() || error!=std::errc{} || end!=value.data()+value.size() || index>=64)
        throw ApiError(400,"Invalid remote image index.");
    std::string source;
    std::function<void(const Json&)> find=[&](const Json& message) {
        if(message.contains("remote_images"))for(const auto& image:message.at("remote_images"))
            if(image.at("index").get<std::size_t>()==index)source=image.at("url").get<std::string>();
        for(const auto& forwarded:message.at("forwarded"))find(forwarded);
    };
    find(view);
    if(source.empty())throw ApiError(404,"Remote image not found in this message.");
    try {
        const auto image=fetch_remote_image(source);
        return json_response({{"ok",true},{"content_type",image.content_type},{"data",base64_encode(image.body)}});
    } catch(const std::exception&) {throw ApiError(502,"Remote image is unavailable or unsafe.");}
}

struct WebSession {
    std::string username, csrf, credential_version;
    bool admin = false;
    Clock::time_point expires;
    std::string api_key_id;
    std::vector<std::string> api_permissions;
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
            load_static(root, "/admin-access.css", "admin-access.css", "text/css; charset=utf-8");
            load_static(root, "/admin-security.js", "admin-security.js", "application/javascript; charset=utf-8");
            load_static(root, "/admin-security.css", "admin-security.css", "text/css; charset=utf-8");
            load_static(root, "/admin-settings.css", "admin-settings.css", "text/css; charset=utf-8");
        } else {
            load_static(root, "/app.js", "app.js", "application/javascript; charset=utf-8");
            load_static(root, "/verification-code.js", "verification-code.js", "application/javascript; charset=utf-8");
            load_static(root, "/verification-code.css", "verification-code.css", "text/css; charset=utf-8");
            load_static(root, "/webmail.css", "webmail.css", "text/css; charset=utf-8");
            load_static(root, "/mail-tools.js", "mail-tools.js", "application/javascript; charset=utf-8");
            load_static(root, "/mail-tools.css", "mail-tools.css", "text/css; charset=utf-8");
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
            response = api_error_response(error);
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
            return api_error_response(error);
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
            if (authorization.size() != 74 || lower(authorization.substr(0, 7)) != "bearer ") {
                const auto failure = rpc(config_, "auth", {{"op", "security_failure"}, {"peer_ip", request.peer_address}, {"protocol", "api"}});
                reject_auth_throttled(failure);
                throw ApiError(401, "Invalid or expired API key.");
            }
            const auto account = rpc(config_, "auth", {{"op", "api_key_verify"}, {"key", authorization.substr(7)},
                {"peer_ip", request.peer_address}, {"protocol", "api"}});
            reject_auth_throttled(account);
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
            session.api_permissions = account.at("permissions").get<std::vector<std::string>>();
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

    static void reject_auth_throttled(const Json& result) {
        if (result.value("code", std::string{}) == "ip_banned")
            throw ApiError(429, "Too many authentication attempts. This IP address is temporarily blocked. Try again later.",
                result.value("retry_after",INT64_C(60)), "ip_banned");
        if (result.value("code", std::string{}) == "rate_limit")
            throw ApiError(429, "Too many authentication attempts. Try again later.",
                result.value("retry_after",INT64_C(60)), "rate_limit");
    }

    HttpResponse login(const HttpRequest& request) {
        require_transport(request);
        allow_login(request);
        Json input;
        std::string username, password;
        try {
            input = request_json(request);
            username = username_field(input);
            password = field(input, "password", 4096);
        }
        catch (const ApiError&) {
            std::string attempted;
            if (input.is_object() && input.contains("username") && input.at("username").is_string())
                attempted = input.at("username").get_ref<const std::string&>().substr(0,254);
            const auto failure = rpc(config_, "auth", {{"op", "security_failure"}, {"username", attempted},
                {"peer_ip", request.peer_address}, {"protocol", admin_only ? "admin" : "webmail"}});
            reject_auth_throttled(failure);
            throw;
        }
        auto user = rpc(config_, "auth", {{"op", "verify"}, {"username", username}, {"password", password}, {"session", true},
            {"peer_ip", request.peer_address}, {"protocol", admin_only ? "admin" : "webmail"}});
        reject_auth_throttled(user);
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
            return json_response({{"ok", true}, {"domain", config_.text("domain", "localhost")},{"max_message_bytes",config_.number("max_message_bytes",10485760)}});
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
            const auto folder = parameter("folder", "INBOX");
            if (query.size() > 1 || (!query.empty() && !query.contains("folder")) || (folder != "INBOX" && folder != "Trash"))
                throw ApiError(400, "Verification code lookup accepts only an Inbox or Trash folder.");
            const auto candidates = rpc(config_, "storage", {{"op","verification_candidates"},{"username",session.username},{"folder",folder},{"max_age_seconds",900},{"limit",30}});
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
        if (request.method == "GET" && path == "/api/messages/search") {
            auto result=rpc(config_,"storage",search_query(config_,session.username,query));
            require_ok(result,"Unable to search messages."); return json_response(result);
        }
        if (request.method == "GET" && path.starts_with("/api/messages/") && path.ends_with("/delivery-status")) {
            if(!query.empty()) throw ApiError(400,"Delivery status does not accept query parameters.");
            const auto id=message_id(path.substr(14,path.size()-14-16));
            auto result=rpc(config_,"storage",{{"op","delivery_status"},{"username",session.username},{"id",id}});
            require_ok(result,"No delivery history is available for this message.",404); return json_response(result);
        }
        if (request.method == "GET" && path == "/api/messages") {
            auto result = rpc(config_, "storage", {{"op", "list"}, {"username", session.username}, {"folder",folder_name(config_,session.username,parameter("folder","INBOX"))}, {"include_envelope", true}});
            require_ok(result, "Unable to load messages.");
            return json_response(result);
        }
        if (path.starts_with("/api/messages/")) {
            const bool moving=path.ends_with("/move");
            auto id = message_id(path.substr(14,path.size()-14-(moving?5:0)));
            if(moving && request.method=="POST") {
                auto input=request_json(request);
                auto result=rpc(config_,"storage",{{"op","move"},{"username",session.username},{"ids",Json::array({id})},{"folder",folder_name(config_,session.username,field(input,"folder",255))}});
                require_ok(result,"Unable to move message.",400);
                return json_response(result);
            }
            if(moving) throw ApiError(404,"API route not found.");
            if (request.method == "GET") {
                auto result = rpc(config_, "storage", {{"op", "get"}, {"username", session.username}, {"id", id}});
                require_ok(result, "Message not found.", 404);
                if(query.contains("attachment")) {
                    if(query.size()!=1)throw ApiError(400,"Invalid attachment query.");
                    return message_attachment(result.at("raw").get<std::string>(),parameter("attachment"));
                }
                if(query.contains("image")) {
                    if(query.size()!=1)throw ApiError(400,"Invalid remote image query.");
                    return message_image(message_view(result.at("raw").get<std::string>()),parameter("image"));
                }
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
            if (path == "/api/admin/security" || path.starts_with("/api/admin/security/")) {
                Json command{{"actor",session.username}};
                if (path == "/api/admin/security" && request.method == "GET") command["op"] = "security_get";
                else {
                    const auto input = request_json(request);
                    std::set<std::string> allowed;
                    if (path == "/api/admin/security/policy" && request.method == "PUT") {
                        command["op"]="security_policy_set"; allowed={"policy","revision"};
                    } else if (path == "/api/admin/security/unban" && request.method == "POST") {
                        command["op"]="security_unban"; allowed={"ip"};
                    } else if (path == "/api/admin/security/ban" && request.method == "POST") {
                        command["op"]="security_ban"; allowed={"ip","seconds","reason"};
                    } else throw ApiError(405,"Unsupported security operation.");
                    for (const auto& [name,value] : input.items()) {
                        if (!allowed.contains(name)) throw ApiError(400,"Unexpected security field.");
                        command[name]=value;
                    }
                }
                const auto result=rpc(config_,"auth",command);
                if (!result.value("ok",false)) {
                    const auto code=result.value("code",std::string{});
                    if (code=="administrator_required") return json_response(result,403);
                    if (code=="security_policy_conflict") return json_response(result,409);
                    if (code=="security_capacity") return json_response(result,409);
                    return json_response(result,400);
                }
                return json_response(result);
            }
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
            if(path=="/api/admin/folders" || path=="/api/admin/messages" || path.starts_with("/api/admin/messages/") || path=="/api/admin/quota") {
                if(path!="/api/admin/quota" && request.method!="GET") throw ApiError(405,"Administrator mail inspection is read-only.");
                auto input=request.method=="GET" ? Json{{"username",parameter("username")}} : request_json(request);
                const auto username=username_field(input);
                auto exists=rpc(config_,"auth",{{"op","exists"},{"username",username}});
                require_ok(exists,"Unable to load accounts.");
                if(!exists.value("exists",false)) throw ApiError(404,"Account not found.");
                if(path=="/api/admin/folders") {
                    auto result=rpc(config_,"storage",{{"op","folders"},{"username",username}});
                    require_ok(result,"Unable to load mail folders.");
                    return json_response(result);
                }
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
                if(path=="/api/admin/messages/search") {
                    auto result=rpc(config_,"storage",search_query(config_,username,query,true));
                    require_ok(result,"Unable to search messages.");
                    log(service_name,"administrator " + session.username + " searched mailbox " + username); return json_response(result);
                }
                if(path.starts_with("/api/admin/messages/") && path.ends_with("/delivery-status")) {
                    if(query.size()!=1 || !query.contains("username")) throw ApiError(400,"An account is required for delivery status.");
                    const auto prefix=std::string("/api/admin/messages/"); const auto id=message_id(path.substr(prefix.size(),path.size()-prefix.size()-16));
                    auto result=rpc(config_,"storage",{{"op","delivery_status"},{"username",username},{"id",id}});
                    require_ok(result,"No delivery history is available for this message.",404);
                    log(service_name,"administrator " + session.username + " inspected delivery status " + id + " in mailbox " + username); return json_response(result);
                }
                if(path=="/api/admin/messages") {
                    auto result=rpc(config_,"storage",{{"op","list"},{"username",username},{"folder",folder_name(config_,username,parameter("folder","INBOX"))},{"include_envelope",true}});
                    require_ok(result,"Unable to load messages.");
                    log(service_name,"administrator " + session.username + " inspected mailbox " + username);
                    return json_response(result);
                }
                const auto id=message_id(path.substr(std::string("/api/admin/messages/").size()));
                auto result=rpc(config_,"storage",{{"op","get"},{"username",username},{"id",id}});
                require_ok(result,"Message not found.",404);
                if(query.contains("attachment")) {
                    if(query.size()!=2)throw ApiError(400,"Invalid attachment query.");
                    log(service_name,"administrator " + session.username + " downloaded attachment from message " + id + " in mailbox " + username);
                    return message_attachment(result.at("raw").get<std::string>(),parameter("attachment"));
                }
                result["message"]=message_view(result.at("raw").get<std::string>());
                if(query.contains("image")) {
                    if(query.size()!=2)throw ApiError(400,"Invalid remote image query.");
                    return message_image(result["message"],parameter("image"));
                }
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

mime::Composition composition_input(const Config& config,const WebSession& session,const Json& input,std::size_t maximum) {
    const auto require_read=[&] {
        if(!session.api_key_id.empty() && std::find(session.api_permissions.begin(),session.api_permissions.end(),"mailbox:read")==session.api_permissions.end())
            throw ApiError(403,"This API key does not have permission for this operation.");
    };
    mime::Composition message;message.from=session.username;message.subject=field(input,"subject",512);message.text=field(input,"text",maximum);
    if(input.contains("html"))message.html=field(input,"html",maximum);
    if(input.contains("in_reply_to"))message.in_reply_to=field(input,"in_reply_to",998);
    if(input.contains("references"))message.references=field(input,"references",998);
    std::size_t address_count=0;
    auto addresses=[&](const char* name,std::vector<std::string>& target,bool required=false) {
        if(!input.contains(name)) {if(required)throw ApiError(400,"Invalid recipient address.");return;}
        if(!input[name].is_array() || input[name].size()>100-address_count)throw ApiError(400,"Provide at most 100 recipient addresses.");
        address_count+=input[name].size();
        for(const auto& value:input[name]) {
            if(!value.is_string())throw ApiError(400,"Recipient addresses must be strings.");
            auto address=lower(trim(value.get<std::string>()));
            if(!valid_address(address))throw ApiError(400,"Invalid recipient address.");
            target.push_back(std::move(address));
        }
    };
    addresses("to",message.to,true);addresses("cc",message.cc);addresses("bcc",message.bcc);
    if(input.contains("reply_to_id")) {
        require_read();
        auto source=rpc(config,"storage",{{"op","get"},{"username",session.username},{"id",message_id(field(input,"reply_to_id",128))}});
        require_ok(source,"Original message not found.",404);
        try {
            auto part=mime::parse(source.at("raw").get<std::string>(),{.max_bytes=maximum});
            const auto id=mime::header(part,"message-id");
            if(!id.empty() && id.size()<=512 && id.front()=='<' && id.back()=='>') {
                message.in_reply_to=id; const auto refs=mime::header(part,"references");
                message.references=refs.empty() || refs.size()+id.size()+1>998?id:refs+" "+id;
            }
        } catch(const std::invalid_argument&) { /* An undecodable source can still be answered. */ }
    }
    std::size_t bytes=message.text.size()+message.html.size();
    if(bytes>maximum)throw ApiError(413,"The message exceeds the server size limit.");
    if(input.contains("attachments")) {
        if(!input["attachments"].is_array() || input["attachments"].size()>64)throw ApiError(400,"Provide at most 64 attachments.");
        // Keep at most one decoded source in memory; a request cannot retain
        // 64 maximum-sized source messages while selecting only tiny files.
        std::string source_id;std::vector<mime::Attachment> source_files;
        for(const auto& item:input["attachments"]) {
            if(!item.is_object())throw ApiError(400,"Invalid attachment.");
            mime::Attachment file;
            if(item.contains("message_id")) {
                require_read();
                if(item.contains("data_base64") || !item.contains("index") || !item["index"].is_number_unsigned())throw ApiError(400,"Invalid attachment reference.");
                const auto id=message_id(field(item,"message_id",128));
                if(source_id!=id) {
                    const auto source=rpc(config,"storage",{{"op","get"},{"username",session.username},{"id",id}});
                    require_ok(source,"Attachment source message not found.",404);
                    try {source_files=mime::attachments(mime::parse(source.at("raw").get<std::string>(),{.max_bytes=maximum}));source_id=id;}
                    catch(const std::exception&) {throw ApiError(422,"The message attachments could not be decoded.");}
                }
                const auto index=item["index"].get<std::size_t>();
                if(index>=source_files.size())throw ApiError(404,"Attachment not found in this message.");
                file=source_files[index];
            } else {
                file.filename=mime::safe_filename(field(item,"filename",512));file.content_type=field(item,"content_type",100);
                const auto data=field(item,"data_base64",(maximum+2)/3*4);
                try {file.data=base64_decode(data);}
                catch(const std::exception&) {throw ApiError(400,"Invalid attachment base64 data.");}
            }
            if(file.data.size()>maximum-bytes)throw ApiError(413,"The attachments exceed the server size limit.");
            bytes+=file.data.size();message.attachments.push_back(std::move(file));
        }
    }
    return message;
}

HttpResponse Web::send_mail(const HttpRequest& request, const WebSession& session) {
    const auto input = request_json(request);
    const auto max_bytes = static_cast<std::size_t>(std::clamp(config_.number("max_message_bytes", 10485760), 1024, 104857600));
    const auto message=composition_input(config_,session,input,max_bytes);
    if(message.to.empty() && message.cc.empty() && message.bcc.empty())throw ApiError(400,"Provide between 1 and 100 recipient addresses.");
    std::set<std::string> unique;
    std::vector<std::string> recipients;
    Json routes=Json::object();
    const auto domain = lower(config_.text("domain", "localhost"));
    auto envelope=message.to;envelope.insert(envelope.end(),message.cc.begin(),message.cc.end());envelope.insert(envelope.end(),message.bcc.begin(),message.bcc.end());
    for (const auto& address : envelope) {
        auto recipient = address;
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
    try { raw = mime::compose(message); }
    catch (const std::exception&) { throw ApiError(400, "The message contains invalid headers or content."); }
    if (raw.size() > max_bytes) throw ApiError(413, "The encoded message exceeds the server size limit.");
    const auto scanned = rpc(config_, "filter", {{"op", "scan"}, {"raw", raw},
        {"inbound", false}, {"sender", session.username}});
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
    const auto message=composition_input(config_,session,input,maximum);
    std::string raw;
    try {raw=mime::compose(message,true);}
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
