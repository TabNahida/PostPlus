#include <postplus/setup.hpp>
#include <postplus/settings.hpp>
#include <postplus/password_policy.hpp>
#include <postplus/acme.hpp>
#include <asio/ssl.hpp>
#include <openssl/ssl.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace postplus {
namespace {
namespace fs = std::filesystem;

struct SetupError : std::runtime_error {
    std::string code;
    int status;
    SetupError(std::string name, std::string message, int http = 400)
        : std::runtime_error(std::move(message)), code(std::move(name)), status(http) {}
};

HttpResponse protected_response(HttpResponse response) {
    response.headers["Cache-Control"] = "no-store";
    response.headers["X-Frame-Options"] = "DENY";
    response.headers["Referrer-Policy"] = "no-referrer";
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
    return response;
}

HttpResponse error_response(const std::string& code, const std::string& message, int status) {
    return protected_response(json_response({{"ok", false}, {"code", code}, {"error", message}}, status));
}

std::string header(const HttpRequest& request, const std::string& name) {
    auto it = request.headers.find(name);
    return it == request.headers.end() ? "" : it->second;
}

std::string text_field(const Json& input, const std::string& name, const std::string& fallback = "", std::size_t maximum = 2048) {
    if (!input.contains(name)) return fallback;
    if (!input.at(name).is_string()) throw SetupError("invalid_field", "Expected text for " + name + ".");
    const auto value = input.at(name).get<std::string>();
    if (value.size() > maximum || value.find('\0') != std::string::npos || value.find_first_of("\r\n") != std::string::npos)
        throw SetupError("invalid_field", "Invalid text for " + name + ".");
    return value;
}

int port_field(const Json& input, const std::string& name, int fallback) {
    if (!input.contains(name)) return fallback;
    if (!input.at(name).is_number_integer()) throw SetupError("invalid_port", "Ports must be whole numbers from 1 to 65535.");
    const auto value = input.at(name).get<std::int64_t>();
    if (value < 1 || value > 65535) throw SetupError("invalid_port", "Ports must be whole numbers from 1 to 65535.");
    return static_cast<int>(value);
}

// All temporary files have unpredictable names and are created exclusively with
// restrictive permissions before any bytes are written, including on Windows.
void private_write(const fs::path& path, std::string_view contents) {
#ifdef _WIN32
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("cannot read process identity");
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> user(size);
    const bool identified = GetTokenInformation(token, TokenUser, user.data(), size, &size) != 0;
    CloseHandle(token);
    if (!identified) throw std::runtime_error("cannot read process identity");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid))
        throw std::runtime_error("cannot read process identity");
    const std::wstring acl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        throw std::runtime_error("cannot create private file permissions");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot create private file");
    DWORD written = 0;
    const bool saved = WriteFile(file, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) != 0 &&
        written == contents.size() && FlushFileBuffers(file) != 0;
    CloseHandle(file);
    if (!saved) { DeleteFileW(path.c_str()); throw std::runtime_error("cannot save private file"); }
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int file = ::open(path.c_str(), flags, S_IRUSR | S_IWUSR);
    if (file < 0) throw std::runtime_error("cannot create private file");
    std::size_t offset = 0;
    bool saved = true;
    while (offset < contents.size()) {
        const auto size = ::write(file, contents.data() + offset, contents.size() - offset);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) { saved = false; break; }
        offset += static_cast<std::size_t>(size);
    }
    if (::fsync(file) != 0) saved = false;
    if (::close(file) != 0) saved = false;
    if (!saved) { ::unlink(path.c_str()); throw std::runtime_error("cannot save private file"); }
#endif
}

// Destination is created atomically, with no replacement even if another
// supervisor/config editor wins the race after provisioning the administrator.
void commit_without_replacing(const fs::path& staged, const fs::path& destination) {
#ifdef _WIN32
    if (!MoveFileExW(staged.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH))
        throw SetupError("config_commit_failed", "Configuration could not be committed. Check permissions and ensure no configuration already exists.", 409);
#else
    if (::link(staged.c_str(), destination.c_str()) != 0)
        throw SetupError("config_commit_failed", "Configuration could not be committed. Check permissions and ensure no configuration already exists.", 409);
    ::unlink(staged.c_str());
    const int directory = ::open(destination.parent_path().c_str(), O_RDONLY);
    if (directory >= 0) { (void)::fsync(directory); ::close(directory); }
#endif
}

bool path_present(const fs::path& path) {
    std::error_code error;
    const auto status = fs::symlink_status(path, error);
    if (error && error != std::errc::no_such_file_or_directory) throw std::runtime_error("cannot inspect configuration path");
    return status.type() != fs::file_type::not_found && status.type() != fs::file_type::none;
}

struct OwnedFiles {
    std::vector<fs::path> paths;
    ~OwnedFiles() {
        for (const auto& path : paths) { std::error_code ignored; fs::remove(path, ignored); }
    }
};

fs::path absolute_field(const std::string& value, const fs::path& parent) {
    auto path = fs::path(value);
    return (path.is_relative() ? parent / path : path).lexically_normal();
}

Json setup_defaults(const SetupOptions& options) {
    const auto parent = fs::absolute(options.config_path).parent_path();
    Json result = {{"domain", "localhost"}, {"bind", "127.0.0.1"}, {"admin_bind", "127.0.0.1"},
        {"data_dir", (parent / "../data").lexically_normal().string()},
        {"allow_insecure_auth", true}, {"admin_username", "admin@localhost"},
        {"tls_certificate", ""}, {"tls_private_key", ""},
        {"ports", {{"auth", 18081}, {"storage", 18082}, {"filter", 18083}, {"transfer", 18084},
            {"smtp", 2525}, {"pop3", 1110}, {"imap", 1143}, {"web", 8080}, {"admin", options.port==8080?8081:options.port}, {"delivery_lock", 18085}}},
        {"smarthost_host", ""}, {"smarthost_port", 587}, {"smarthost_tls", "starttls"},
        {"smarthost_username", ""}, {"smarthost_password_env", "POSTPLUS_SMARTHOST_PASSWORD"},
        {"clamav_host", ""}, {"clamav_port", 3310}};
    Config base;
    base.values = Json::object();
    if (options.existing_config) base.values = Json::parse(*options.existing_config);
    for (const auto& entry : settings_schema(base)) {
        const auto key=entry.at("key").get<std::string>();
        if (key.find('.')!=std::string::npos || key=="data_dir" || entry.value("readonly",false) || entry.at("type")=="password") continue;
        if (base.values.contains(key)) result[key]=base.values.at(key);
        else if (!result.contains(key)) result[key]=entry.at("default");
    }
    if (base.values.contains("ports") && base.values.at("ports").is_object())
        for (const auto& entry : base.values.at("ports").items())
            if (result["ports"].contains(entry.key())) result["ports"][entry.key()]=entry.value();
    if (base.values.contains("delivery_lock_port")) result["ports"]["delivery_lock"]=base.values.at("delivery_lock_port");
    if (!base.text("data_dir").empty()) result["data_dir"]=absolute_field(base.text("data_dir"),parent).string();
    for (const auto* key : {"tls_certificate","tls_private_key"})
        if (!result.at(key).get<std::string>().empty()) result[key]=absolute_field(result.at(key).get<std::string>(),parent).string();
    result["admin_username"]="admin@"+result.at("domain").get<std::string>();
    return result;
}

Config validate_input(const Json& input, const Json& defaults, const SetupOptions& options,
                      std::string& username, std::string& password) {
    const auto parent = fs::absolute(options.config_path).parent_path();
    Config config;
    config.source=fs::absolute(options.config_path).lexically_normal();
    if (options.existing_config) config.values=Json::parse(*options.existing_config);
    auto& values = config.values;
    const auto domain = lower(trim(text_field(input, "domain", "", 253)));
    if (!valid_address("postmaster@" + domain)) throw SetupError("invalid_domain", "Enter a valid ASCII mail domain, such as example.com.");
    values["domain"] = domain;
    username = lower(trim(text_field(input, "admin_username", "", 254)));
    if (!valid_address(username) || username.substr(username.find('@') + 1) != domain)
        throw SetupError("invalid_admin", "The administrator email address must belong to the configured domain.");
    password = text_field(input, "admin_password", "", 1024);
    if (!password_violations(password, PasswordPolicy{}, 1024).empty())
        throw SetupError("weak_password", "The administrator password must contain at least 8 Unicode characters.");
    const auto bind = trim(text_field(input, "bind", "127.0.0.1", 128));
    std::error_code address_error;
    const auto address = asio::ip::make_address(bind, address_error);
    if (address_error) throw SetupError("invalid_bind", "The listening address must be an IPv4 or IPv6 address.");
    values["bind"] = bind;
    values["admin_bind"] = trim(text_field(input,"admin_bind",defaults.value("admin_bind",std::string("127.0.0.1")),128));
    if (!input.contains("allow_insecure_auth") || !input.at("allow_insecure_auth").is_boolean())
        throw SetupError("transport_selection_required", "Choose TLS or explicitly enable local development mode.");
    const auto insecure = input.at("allow_insecure_auth").get<bool>();
    values["allow_insecure_auth"] = insecure;
    const auto certificate = trim(text_field(input, "tls_certificate"));
    const auto key = trim(text_field(input, "tls_private_key"));
    if (certificate.empty() != key.empty()) throw SetupError("tls_required", "Provide both a TLS certificate and private key.");
    if (!address.is_loopback() && (certificate.empty() || insecure))
        throw SetupError("tls_required", "Public listening addresses require TLS and disabled insecure authentication.");
    if (certificate.empty() && !insecure)
        throw SetupError("tls_required", "Provide TLS credentials or explicitly enable local development mode.");
    if (!certificate.empty()) {
        values["tls_certificate"] = absolute_field(certificate, parent).string();
        values["tls_private_key"] = absolute_field(key, parent).string();
        try {
            asio::ssl::context tls(asio::ssl::context::tls_server);
            tls.set_password_callback([](std::size_t, asio::ssl::context::password_purpose) { return std::string{}; });
            tls.use_certificate_chain_file(config.text("tls_certificate"));
            tls.use_private_key_file(config.text("tls_private_key"), asio::ssl::context::pem);
            if (SSL_CTX_check_private_key(tls.native_handle()) != 1) throw std::runtime_error("TLS key mismatch");
        } catch (const std::exception&) { throw SetupError("invalid_tls", "TLS files must be readable PEM files with a matching, unencrypted private key."); }
    }
    const auto data = trim(text_field(input, "data_dir", defaults.at("data_dir").get<std::string>()));
    if (data.empty()) throw SetupError("invalid_data_dir", "Choose a mail data directory.");
    if (options.existing_config && absolute_field(data,parent)!=absolute_field(defaults.at("data_dir").get<std::string>(),parent))
        throw SetupError("invalid_data_dir","Keep the existing data directory when completing an existing configuration.");
    values["data_dir"] = absolute_field(data, parent).string();
    values["web_root"] = fs::absolute(options.web_root).lexically_normal().string();
    if (config.text("log_dir").empty()) values["log_dir"] = (fs::path(config.text("data_dir")) / "logs").string();
    else values["log_dir"] = absolute_field(config.text("log_dir"),parent).string();
    const auto ports = input.value("ports", Json::object());
    if (!ports.is_object()) throw SetupError("invalid_port", "Service ports must be a JSON object.");
    std::set<int> assigned;
    for (const auto& entry : defaults.at("ports").items()) {
        const int port = port_field(ports, entry.key(), entry.value().get<int>());
        if (!assigned.insert(port).second) throw SetupError("duplicate_port", "Every PostPlus service must use a different port.");
        if (entry.key() == "delivery_lock") values["delivery_lock_port"] = port;
        else values["ports"][entry.key()] = port;
    }
    // Keep the running wizard separate from temporary auth used by provision().
    if (values["ports"]["auth"].get<int>() == options.port)
        throw SetupError("setup_port_conflict", "The authentication service cannot use the active setup page port.");
    // Catch occupied or privileged ports while the user can still correct the
    // form. The supervisor checks again immediately before starting services.
    asio::io_context probe_io;
    for (const auto& entry : defaults.at("ports").items()) {
        const auto& service = entry.key();
        const int port = service == "delivery_lock" ? values.at("delivery_lock_port").get<int>() : config.port(service);
        if (port == options.port) continue; // Released when setup completes.
        const bool internal = service == "auth" || service == "storage" || service == "filter" || service == "transfer" || service == "delivery_lock";
        std::error_code port_error;
        tcp::acceptor probe(probe_io);
        auto listen_address=address;
        if (service=="admin") {
            listen_address=asio::ip::make_address(config.text("admin_bind"),port_error);
            if (port_error) throw SetupError("invalid_bind","The administration listening address must be an IPv4 or IPv6 address.");
        }
        const tcp::endpoint endpoint(internal ? asio::ip::address(asio::ip::address_v4::loopback()) : listen_address,
            static_cast<unsigned short>(port));
        probe.open(endpoint.protocol(), port_error);
#ifndef _WIN32
        if (!port_error) probe.set_option(tcp::acceptor::reuse_address(true), port_error);
#endif
        if (!port_error) probe.bind(endpoint, port_error);
        if (!port_error) probe.listen(asio::socket_base::max_listen_connections, port_error);
        if (port_error) throw SetupError("port_unavailable", "The " + service + " port is unavailable. Choose another port or check listening permissions.");
    }
    for (const auto* field : {"smarthost_host", "smarthost_username", "smarthost_password_env", "clamav_host"})
        values[field] = trim(text_field(input, field, defaults.at(field).get<std::string>(), 254));
    const auto environment = config.text("smarthost_password_env");
    if (environment.empty() || !((environment.front() >= 'A' && environment.front() <= 'Z') ||
        (environment.front() >= 'a' && environment.front() <= 'z') || environment.front() == '_') ||
        environment.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos)
        throw SetupError("invalid_environment_name", "Use a valid environment variable name for the relay password.");
    values["smarthost_port"] = port_field(input, "smarthost_port", 587);
    values["clamav_port"] = port_field(input, "clamav_port", 3310);
    const auto relay_tls = text_field(input, "smarthost_tls", "starttls", 16);
    if (relay_tls != "starttls" && relay_tls != "implicit" && relay_tls != "none")
        throw SetupError("invalid_smarthost_tls", "Relay TLS must be starttls, implicit, or none.");
    if (relay_tls == "none" && !config.text("smarthost_username").empty())
        throw SetupError("invalid_smarthost_tls", "An authenticated relay requires TLS.");
    values["smarthost_tls"] = relay_tls;
    values["service_token_env"] = "POSTPLUS_SERVICE_TOKEN";
    auto settings=input;
    for (const auto* field : {"admin_username","admin_password","data_dir"}) settings.erase(field);
    if (settings.contains("ports") && settings["ports"].contains("delivery_lock")) {
        settings["delivery_lock_port"]=settings["ports"]["delivery_lock"];
        settings["ports"].erase("delivery_lock");
    }
    return validate_settings(config,settings);
}

std::int64_t monotonic_milliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
}

bool run_setup(const SetupOptions& options, SetupProvision provision) {
    if (!provision) throw std::invalid_argument("setup requires an administrator provisioning callback");
    if (options.port < 1 || options.port > 65535) throw std::invalid_argument("invalid setup port");
    const auto destination = fs::absolute(options.config_path).lexically_normal();
    if (path_present(destination) && !options.existing_config) throw std::runtime_error("setup refuses to replace an existing configuration");
    if (options.existing_config) {
        if (!fs::is_regular_file(fs::symlink_status(destination))) throw std::runtime_error("setup requires a regular existing configuration file");
        std::ifstream file(destination,std::ios::binary);
        const std::string contents{std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
        if (!file || contents!=*options.existing_config) throw std::runtime_error("existing configuration changed before setup");
    }
    const auto defaults = setup_defaults(options);
    const auto token = random_hex(32);
    const auto address = asio::ip::make_address(options.bind);
    const bool local=address.is_loopback(), https=!options.tls_certificate.empty();
    if(https!=!options.tls_private_key.empty()) throw std::invalid_argument("provide both setup TLS certificate and private key");
    if(!local && !https) throw std::invalid_argument("remote setup requires --setup-tls-certificate and --setup-tls-private-key; use a loopback SSH tunnel for first-time certificate setup");
    if(address.is_unspecified() && options.host.empty()) throw std::invalid_argument("--setup-host is required with a wildcard --setup-bind");
    std::string host=options.host.empty()?address.to_string():lower(options.host);
    std::error_code host_error;
    const auto host_address=asio::ip::make_address(host,host_error);
    if(host_error && (host.size()>253 || !valid_address("postmaster@"+host))) throw std::invalid_argument("invalid --setup-host; provide a hostname without a scheme, port, or path");
    if(!host_error && host_address.is_unspecified()) throw std::invalid_argument("--setup-host must identify a reachable address");
    if(!host_error && host_address.is_v6()) host="["+host+"]";
    const std::string scheme=https?"https://":"http://";
    const auto authority=host+":"+std::to_string(options.port);
    std::set<std::string> hosts{authority};
    if(options.port==(https?443:80)) hosts.insert(host);
    if(local && options.host.empty()) {
        hosts.insert("localhost:"+std::to_string(options.port));
        if(options.port==(https?443:80)) hosts.insert("localhost");
    }
    AcmeManager acme(AcmeOptions{destination.parent_path()/"certificates"});
    std::map<std::string, HttpResponse> assets;
    for (const auto& [filename, type] : std::map<std::string, std::string>{
        {"setup.html", "text/html; charset=utf-8"}, {"setup.js", "application/javascript; charset=utf-8"},
        {"i18n.js", "application/javascript; charset=utf-8"}, {"settings.js", "application/javascript; charset=utf-8"},
        {"size.js", "application/javascript; charset=utf-8"}, {"acme.js", "application/javascript; charset=utf-8"},
        {"preferences.js", "application/javascript; charset=utf-8"}, {"preferences.css", "text/css; charset=utf-8"},
        {"icons.svg", "image/svg+xml"},
        {"favicon.svg", "image/svg+xml"}, {"style.css", "text/css; charset=utf-8"}}) {
        std::ifstream file(fs::absolute(options.web_root) / filename, std::ios::binary);
        if (!file) throw std::runtime_error("setup web asset is missing: " + filename);
        std::ostringstream contents; contents << file.rdbuf();
        assets.emplace("/" + filename, protected_response({200, type, contents.str(), {}}));
    }
    assets.emplace("/setup", assets.at("/setup.html"));
    assets.emplace("/", assets.at("/setup.html"));
    std::mutex provisioning;
    std::atomic<bool> completed = false;
    std::atomic<std::int64_t> stop_after = 0;
    Config listener;
    listener.values = {{"bind", options.bind}, {"ports", {{"web", options.port}}},
        {"max_connections", 8}, {"timeout_seconds", 15}};
    if(https) {
        listener.values["tls_certificate"]=options.tls_certificate.string();
        listener.values["tls_private_key"]=options.tls_private_key.string();
        asio::ssl::context tls(asio::ssl::context::tls_server);
        tls.use_certificate_chain_file(options.tls_certificate.string());
        tls.use_private_key_file(options.tls_private_key.string(),asio::ssl::context::pem);
        if(SSL_CTX_check_private_key(tls.native_handle())!=1) throw std::invalid_argument("setup TLS private key does not match the certificate");
    }
    auto preflight = [&](const HttpRequest& request) -> std::optional<HttpResponse> {
        const auto host = lower(header(request, "host"));
        if ((local && !request.peer_loopback) || !hosts.contains(host))
            return error_response("local_access_required", "Setup is available only through its local URL.", 403);
        const auto origin = header(request, "origin");
        if (!origin.empty() && (!origin.starts_with(scheme) || !hosts.contains(origin.substr(scheme.size()))))
            return error_response("invalid_origin", "Open the setup URL printed by the server.", 403);
        if ((request.path == "/api/setup" || request.path.starts_with("/api/setup/acme/")) && !secure_equal(header(request, "x-setup-token"), token))
            return error_response("invalid_setup_token", "Enter the one-time setup password printed in the PostPlus terminal.", 403);
        return std::nullopt;
    };
    auto handler = [&](const HttpRequest& request) -> HttpResponse {
        try {
            if(request.path.starts_with("/api/setup/acme/")) {
                std::lock_guard lock(provisioning);
                if(completed) return error_response("already_configured","A configuration already exists. Restart PostPlus to use it.",409);
                const auto question=request.path.find('?');
                const auto path=request.path.substr(0,question);
                const auto query=question==std::string::npos?std::string{}:request.path.substr(question+1);
                if(request.method=="GET" && path=="/api/setup/acme/terms") {
                    if(query!="directory=staging" && query!="directory=production" && !query.empty()) throw SetupError("invalid_field","Invalid certificate directory.");
                    return protected_response(json_response(acme.terms(query=="directory=production"?"production":"staging")));
                }
                if(request.method=="GET" && path=="/api/setup/acme/status") {
                    if(!query.empty() && (!query.starts_with("job_id=") || query.size()>135 || query.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=.")!=std::string::npos)) throw SetupError("invalid_field","Invalid certificate job.");
                    return protected_response(json_response(acme.status(query.empty()?"":query.substr(7))));
                }
                if(request.method=="POST") {
                    if(!lower(header(request,"content-type")).starts_with("application/json")) return error_response("invalid_content_type","Use application/json for setup.",415);
                    auto input=Json::parse(request.body);
                    if(path=="/api/setup/acme/start") return protected_response(json_response(acme.start(input),202));
                    if(path=="/api/setup/acme/cancel") return protected_response(json_response(acme.cancel(text_field(input,"job_id","",128))));
                }
                return error_response("not_found","Not found.",404);
            }
            if (request.path != "/api/setup") {
                const auto asset = assets.find(request.path);
                if (request.method == "GET" && asset != assets.end()) return asset->second;
                return error_response("not_found", "Not found.", 404);
            }
            if (request.method == "GET") return protected_response(json_response({{"ok", true}, {"defaults", defaults},
                {"schema",settings_schema(Config{})},{"completing_existing",options.existing_config.has_value()}}));
            if (request.method != "POST") return error_response("method_not_allowed", "Use GET or POST.", 405);
            if (trim(lower(header(request, "content-type")).substr(0, header(request, "content-type").find(';'))) != "application/json")
                return error_response("invalid_content_type", "Use application/json for setup.", 415);
            std::unique_lock lock(provisioning, std::try_to_lock);
            if (!lock.owns_lock()) return error_response("setup_busy", "Setup is already running. Wait before retrying.", 409);
            if (completed.load() || (path_present(destination) && !options.existing_config))
                return error_response("already_configured", "A configuration already exists. Restart PostPlus to use it.", 409);
            auto input = Json::parse(request.body, nullptr, false);
            if (input.is_discarded() || !input.is_object()) throw SetupError("invalid_json", "A JSON object is required.");
            std::string username, password;
            auto config = validate_input(input, defaults, options, username, password);
            // The password only reaches the in-memory provisioning callback.
            input.erase("admin_password");
            if (fs::create_directories(destination.parent_path())) {
#ifndef _WIN32
                fs::permissions(destination.parent_path(), fs::perms::owner_all);
#endif
            }
            const auto suffix = random_hex(16);
            const auto staged = destination.parent_path() / (destination.filename().string() + ".setup-" + suffix + ".tmp");
            const auto secret = destination.parent_path() / (destination.filename().string() + ".service-token-" + suffix);
            OwnedFiles owned;
            private_write(secret, random_hex(32) + "\n");
            owned.paths.push_back(secret);
            config.values["service_token_file"] = secret.string();
            config.values["setup_complete"] = true;
            config.values.erase("setup_required");
            if (input.contains("smarthost_password") && !input.at("smarthost_password").get<std::string>().empty()) {
                const auto relay=destination.parent_path()/(destination.filename().string()+".relay-password-"+suffix);
                private_write(relay,input.at("smarthost_password").get<std::string>());
                owned.paths.push_back(relay);
                config.values["smarthost_password_file"]=relay.string();
            }
            input.erase("smarthost_password");
            private_write(staged, config.values.dump(2) + "\n");
            owned.paths.push_back(staged);
            config = Config::from_file(staged);
            configure_logging(config,"setup");
            try { provision(config, username, password); }
            catch (const std::exception&) { throw SetupError("provision_failed", "Administrator provisioning failed. Check the server console, data directory, and authentication service port, then retry with the same account and password.", 503); }
            std::fill(password.begin(), password.end(), '\0');
            if (options.existing_config) replace_config_file(destination,*options.existing_config,config.values.dump(2)+"\n");
            else commit_without_replacing(staged, destination);
            owned.paths={staged}; // Keep committed secrets, clean any staging residue.
            completed = true;
            // Let the successful response finish before stopping the listener.
            stop_after = monotonic_milliseconds() + 500;
            log("setup", "initial configuration and administrator created");
            return protected_response(json_response({{"ok", true}, {"web_url", settings_url(config,"web")},
                {"admin_url",settings_url(config,"admin")}}));
        } catch (const AcmeError& error) {
            return error_response(error.code,error.what(),error.status);
        } catch (const SettingsError& error) {
            auto response=json_response({{"ok",false},{"code","invalid_configuration"},{"field",error.field},{"error",error.what()}},error.status);
            return protected_response(std::move(response));
        } catch (const SetupError& error) {
            if (error.status >= 500) log("setup", "initial setup failed: " + error.code, "error");
            return error_response(error.code, error.what(), error.status);
        } catch (const Json::exception&) {
            return error_response("invalid_field", "One or more setup fields have an invalid value.", 400);
        } catch (const std::exception&) {
            log("setup", "cannot create or validate initial configuration files", "error");
            return error_response("setup_failed", "Setup could not save its files. Check filesystem permissions and the server console, then retry.", 503);
        }
    };
    // Never send this credential to the persistent logger or an HTTP query.
    std::cout << "\nPostPlus setup is required before mail services can start.\n"
              << "Open this configuration page: " << scheme << authority << "/setup\n"
              << "One-time setup password: " << token << "\n"
              << "Use this password to unlock setup, then choose your administrator account and password.\n"
              << (local ? "Setup is available only on this computer. " : "Remote HTTPS setup is enabled. ")
              << "This password expires after setup or server shutdown.\n" << std::endl;
    serve_http(listener, "web", handler, false, preflight, [&] {
        const auto deadline = stop_after.load();
        return deadline != 0 && monotonic_milliseconds() >= deadline;
    });
    return completed.load();
}
}
