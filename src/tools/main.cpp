#include <postplus/core.hpp>
#include <postplus/process.hpp>
#include <postplus/setup.hpp>
#include <postplus/settings.hpp>

#include <algorithm>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#endif

namespace postplus {
namespace {
volatile std::sig_atomic_t stopping = 0;
void stop_signal(int) { stopping = 1; }
#ifdef _WIN32
volatile LONG console_stopping = 0;
BOOL WINAPI console_stop(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT ||
        event == CTRL_LOGOFF_EVENT || event == CTRL_SHUTDOWN_EVENT) {
        InterlockedExchange(&console_stopping, 1);
        return TRUE;
    }
    return FALSE;
}
#endif

bool stop_requested() {
#ifdef _WIN32
    if (InterlockedCompareExchange(&console_stopping, 0, 0) != 0) return true;
#endif
    return stopping != 0 || process_stop_requested();
}

std::string path_argument(const std::filesystem::path& value) {
    const auto utf8 = value.u8string();
    return {reinterpret_cast<const char*>(utf8.data()), utf8.size()};
}

std::filesystem::path service_executable(const std::filesystem::path& directory, const std::string& service) {
#ifdef _WIN32
    return directory / ("postplus-" + service + ".exe");
#else
    return directory / ("postplus-" + service);
#endif
}

struct Options {
    std::filesystem::path config = "config/postplus.json";
    std::filesystem::path web_root;
    int setup_port = 8081;
    bool help = false;
};

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (argument == "--help" || argument == "-h") { options.help = true; continue; }
        if (argument != "--config" && argument != "--web-root" && argument != "--setup-port")
            throw std::invalid_argument("unknown option: " + std::string(argument) + "; use --help");
        if (++i >= argc) throw std::invalid_argument(std::string(argument) + " requires a value");
        if (argument == "--config") options.config = std::filesystem::path(argv[i]);
        else if (argument == "--web-root") options.web_root = std::filesystem::path(argv[i]);
        else {
            const std::string_view input(argv[i]);
            const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), options.setup_port);
            if (error != std::errc{} || end != input.data() + input.size() || options.setup_port < 1 || options.setup_port > 65535)
                throw std::invalid_argument("--setup-port must be 1..65535");
        }
    }
    return options;
}

void ensure_alive(ProcessGroup& children) {
    if (const auto exited = children.exited())
        throw std::runtime_error(exited->first + " exited with code " + std::to_string(exited->second) +
                                 "; stopping the service group");
}

std::string public_probe_host(const Config& config, const std::string& service) {
    const auto address = asio::ip::make_address(config.text(service == "admin" ? "admin_bind" : "bind", "127.0.0.1"));
    if (address.is_unspecified()) return address.is_v6() ? "::1" : "127.0.0.1";
    return address.to_string();
}

int service_port(const Config& config, const std::string& service) {
    return service == "delivery" ? config.number("delivery_lock_port", 18085) : config.port(service);
}

bool internal_service(const std::string& service) {
    return service == "auth" || service == "storage" || service == "filter" ||
           service == "transfer" || service == "delivery";
}

void port_available(const Config& config, const std::string& service) {
    const int port = service_port(config, service);
    if (port < 1 || port > 65535) throw std::invalid_argument("invalid " + service + " port");
    const auto address = asio::ip::make_address(internal_service(service) ? "127.0.0.1" : config.text(service == "admin" ? "admin_bind" : "bind", "127.0.0.1"));
    asio::io_context context;
    tcp::acceptor test(context);
    std::error_code error;
    test.open(address.is_v6() ? tcp::v6() : tcp::v4(), error);
    if (!error) test.bind({address, static_cast<unsigned short>(port)}, error);
    if (error) throw std::runtime_error(service + " cannot bind " + address.to_string() + ":" + std::to_string(port));
}

Json readiness_rpc(const Config& config, const std::string& service, const Json& request,
                   std::chrono::steady_clock::time_point deadline) {
    Connection connection(std::chrono::seconds(1));
    connection.set_deadline(std::min(deadline, std::chrono::steady_clock::now() + std::chrono::seconds(1)));
    connection.connect("127.0.0.1", config.port(service));
    const auto body = request.dump();
    connection.write("POST /rpc HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + config.token() +
                     "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
                     "\r\nConnection: close\r\n\r\n" + body);
    if (!connection.line().starts_with("HTTP/1.1 200 ")) throw std::runtime_error("readiness RPC failed");
    std::optional<std::size_t> length;
    bool headers_complete = false;
    for (int count = 0; count < 100; ++count) {
        const auto line = connection.line(8192);
        if (line.empty()) { headers_complete = true; break; }
        const auto colon = line.find(':');
        if (colon == std::string::npos) throw std::runtime_error("invalid readiness response header");
        const auto name = lower(line.substr(0, colon));
        if (name == "transfer-encoding") throw std::runtime_error("invalid readiness transfer encoding");
        if (name == "content-length") {
            if (length) throw std::runtime_error("duplicate readiness content length");
            const auto value = trim(line.substr(colon + 1));
            std::size_t size = 0;
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), size);
            if (error != std::errc{} || end != value.data() + value.size() || size > 65536)
                throw std::runtime_error("invalid readiness response length");
            length = size;
        }
    }
    if (!headers_complete || !length) throw std::runtime_error("incomplete readiness response");
    auto response = Json::parse(connection.read(*length));
    if (!response.is_object() || !response.contains("ok") || !response.at("ok").is_boolean())
        throw std::runtime_error("invalid readiness RPC response");
    return response;
}

void wait_ready(ProcessGroup& children, const Config& config, const std::string& service) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (!stop_requested()) {
        ensure_alive(children);
        try {
            if (service == "auth") {
                const auto answer = readiness_rpc(config, service, {{"op", "exists"}, {"username", "postmaster@" + config.text("domain", "localhost")}}, deadline);
                if (!answer.value("ok", false)) throw std::runtime_error("authentication readiness probe failed");
            } else if (service == "storage") {
                if (!readiness_rpc(config, service, {{"op", "stats"}}, deadline).value("ok", false))
                    throw std::runtime_error("storage readiness probe failed");
            } else if (service == "filter" || service == "transfer") {
                // An authenticated, correctly formed RPC response proves readiness
                // without scanning mail or transmitting a message.
                (void)readiness_rpc(config, service, {{"op", "health"}}, deadline);
            } else {
                Connection connection(std::chrono::seconds(1));
                connection.set_deadline(std::min(deadline, std::chrono::steady_clock::now() + std::chrono::seconds(1)));
                connection.connect(internal_service(service) ? "127.0.0.1" : public_probe_host(config,service), service_port(config, service));
                if (service == "smtp" && !connection.line().starts_with("220 "))
                    throw std::runtime_error("SMTP readiness probe failed");
                if (service == "pop3" && !connection.line().starts_with("+OK"))
                    throw std::runtime_error("POP3 readiness probe failed");
                if (service == "imap" && !connection.line().starts_with("* OK"))
                    throw std::runtime_error("IMAP readiness probe failed");
                // HTTPS may use a private certificate whose hostname differs
                // from this local probe. Listener readiness plus child liveness
                // is sufficient in that case; client trust policy stays strict.
                if ((service == "web" || service == "admin") && config.text("tls_certificate").empty()) {
                    connection.write("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
                    if (!connection.line().starts_with("HTTP/1.1 200 "))
                        throw std::runtime_error("web readiness probe failed");
                }
            }
            // A competing listener cannot hide an early bind/startup failure.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            ensure_alive(children);
            return;
        } catch (const std::exception&) {
            ensure_alive(children);
            if (std::chrono::steady_clock::now() >= deadline)
                throw std::runtime_error(service + " did not become ready within 20 seconds");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    throw std::runtime_error("startup interrupted");
}

void provision_admin(const std::filesystem::path& binaries, const Config& staged,
                     const std::string& username, const std::string& password) {
    port_available(staged, "auth");
    ProcessGroup temporary;
    temporary.start("auth", service_executable(binaries, "auth"), {"--config", path_argument(staged.source)});
    wait_ready(temporary, staged, "auth");
    auto request_config = staged;
    request_config.values["timeout_seconds"] = 10;
    const auto created = rpc(request_config, "auth", {{"op", "create"}, {"username", username}, {"password", password}, {"admin", true}});
    if (!created.value("ok", false)) {
        if (created.value("error", "") != "user already exists")
            throw std::runtime_error("administrator provisioning failed");
        const auto verified = rpc(request_config, "auth", {{"op", "verify"}, {"username", username}, {"password", password}});
        if (!verified.value("ok", false) || !verified.value("admin", false))
            throw std::runtime_error("administrator account already exists with different credentials or permissions");
    }
    ensure_alive(temporary);
    // Stop and reap auth before the setup server commits the configuration or
    // the normal service group starts. Destruction also covers every failure.
    temporary.stop();
}

std::string configuration_bytes(const std::filesystem::path& path) {
    std::ifstream file(path,std::ios::binary);
    if (!file) throw std::runtime_error("cannot read configuration");
    file.seekg(0,std::ios::end);
    const auto size = file.tellg();
    if (size < 0 || size > 1024 * 1024) throw std::runtime_error("invalid configuration size");
    file.seekg(0);
    std::string bytes(static_cast<std::size_t>(size),'\0');
    if (!bytes.empty() && !file.read(bytes.data(),static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("cannot read configuration");
    return bytes;
}

int run(int argc, char** argv) {
    auto options = parse_options(argc, argv);
    if (options.help) {
        std::cout << "PostPlus mail server\n"
                     "Usage: postplus [--config PATH] [--web-root PATH] [--setup-port PORT]\n\n"
                     "  --config PATH       Configuration file (default: config/postplus.json)\n"
                     "  --web-root PATH     Web assets for first-run setup (default: executable/web, then ./web)\n"
                     "  --setup-port PORT   Loopback-only setup page port (default: 8081)\n"
                     "  --help              Show this help\n\n"
                     "A missing or uninitialized configuration opens browser setup and prints\n"
                     "its URL and one-time password. An initialized configuration starts all\n"
                     "services. Restart manually to apply saved settings. Ctrl+C stops them.\n";
        return 0;
    }
    std::signal(SIGINT, stop_signal);
    std::signal(SIGTERM, stop_signal);
#ifdef _WIN32
    SetConsoleCtrlHandler(console_stop, TRUE);
#else
    std::signal(SIGPIPE, SIG_IGN);
#endif
    const auto binaries = executable_path(argv[0]).parent_path();
    options.config = std::filesystem::absolute(options.config).lexically_normal();
    if (options.web_root.empty()) {
        options.web_root = std::filesystem::is_directory(binaries / "web") ? binaries / "web" : std::filesystem::current_path() / "web";
    }
    options.web_root = std::filesystem::absolute(options.web_root).lexically_normal();
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(options.config, status_error);
    // Malformed, unreadable, symlink, and directory configs fail normally.
    // A valid, uninitialized example can be completed with a private backup.
    bool needs_setup = status.type() == std::filesystem::file_type::not_found &&
        (!status_error || status_error == std::errc::no_such_file_or_directory);
    std::optional<std::string> incomplete_configuration;
    if (!needs_setup && !status_error && std::filesystem::is_regular_file(status)) {
        auto bytes = configuration_bytes(options.config);
        const auto value = Json::parse(bytes);
        if (!value.is_object()) throw std::invalid_argument("config must be a JSON object");
        const auto environment = value.value("service_token_env",std::string("POSTPLUS_SERVICE_TOKEN"));
        const auto* token = std::getenv(environment.c_str());
        if ((!token || !*token) && value.value("service_token_file",std::string{}).empty() && !value.value("setup_complete",false)) {
            needs_setup = true;
            incomplete_configuration = std::move(bytes);
        }
    }
    if (needs_setup) {
        if (!run_setup({options.config, options.web_root, options.setup_port, incomplete_configuration},
                       [&](const Config& staged, const std::string& username, const std::string& password) {
                           provision_admin(binaries, staged, username, password);
                       })) return 0;
    } else if (status_error) {
        throw std::runtime_error("cannot inspect configuration file: " + options.config.string());
    }
    if (stop_requested()) return 0;
    auto config = Config::from_file(options.config);
    configure_logging(config, "postplus");
    const std::vector<std::string> services{"auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web", "admin"};
    // Validate the complete installation before creating any child process.
    std::set<int> ports;
    for (const auto& service : services) {
        if (!std::filesystem::is_regular_file(service_executable(binaries, service)))
            throw std::runtime_error("missing executable for " + service + "; install all PostPlus services together");
        if (!ports.insert(service_port(config, service)).second)
            throw std::invalid_argument("service ports must be distinct");
        port_available(config, service);
    }
    ProcessGroup children;
    log("postplus", "starting service group");
    for (const auto& service : services) {
        if (stop_requested()) break;
        children.start(service, service_executable(binaries, service), {"--config", path_argument(config.source)});
        wait_ready(children, config, service);
        log("postplus", service + " is ready");
    }
    if (!stop_requested()) log("postplus", "all services are ready");
    std::cout << "Administration: " << settings_url(config,"admin") << '\n'
              << "Webmail:        " << settings_url(config,"web") << '\n' << std::flush;
    while (!stop_requested()) {
        ensure_alive(children);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    log("postplus", "stopping service group");
    children.stop();
    log("postplus", "service group stopped");
    return 0;
}
}
}

int main(int argc, char** argv) {
    try { return postplus::run(argc, argv); }
    catch (const std::exception& error) {
        if (postplus::stop_requested()) return 0;
        postplus::log("postplus", error.what(), "error");
        return 1;
    }
}
