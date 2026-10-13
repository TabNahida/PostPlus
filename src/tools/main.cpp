#include <postplus/core.hpp>
#include <postplus/process.hpp>
#include <postplus/setup.hpp>
#include <postplus/settings.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/maintenance.hpp>
#include <asio/ssl.hpp>
#include <openssl/pem.h>

#include <algorithm>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <set>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
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
    std::string setup_bind = "127.0.0.1", setup_host;
    std::filesystem::path setup_certificate, setup_key;
    bool setup_bind_explicit = false;
    bool help = false;
};

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (argument == "--help" || argument == "-h") { options.help = true; continue; }
        if (argument != "--config" && argument != "--web-root" && argument != "--setup-port" && argument != "--setup-bind" && argument != "--setup-host" && argument != "--setup-tls-certificate" && argument != "--setup-tls-private-key")
            throw std::invalid_argument("unknown option: " + std::string(argument) + "; use --help");
        if (++i >= argc) throw std::invalid_argument(std::string(argument) + " requires a value");
        if (argument == "--config") options.config = std::filesystem::path(argv[i]);
        else if (argument == "--web-root") options.web_root = std::filesystem::path(argv[i]);
        else if (argument == "--setup-bind") { options.setup_bind = argv[i]; options.setup_bind_explicit = true; }
        else if (argument == "--setup-host") options.setup_host = argv[i];
        else if (argument == "--setup-tls-certificate") options.setup_certificate = std::filesystem::absolute(argv[i]);
        else if (argument == "--setup-tls-private-key") options.setup_key = std::filesystem::absolute(argv[i]);
        else {
            const std::string_view input(argv[i]);
            const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), options.setup_port);
            if (error != std::errc{} || end != input.data() + input.size() || options.setup_port < 1 || options.setup_port > 65535)
                throw std::invalid_argument("--setup-port must be 1..65535");
        }
    }
    return options;
}

bool stdin_is_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

void choose_setup_listener(Options& options) {
    if (!stdin_is_terminal()) return;
    if (!options.setup_bind_explicit) {
        std::cout << "\nFirst-time setup listening address:\n"
                     "  1) 127.0.0.1 (this computer only)\n"
                     "  2) 0.0.0.0 (allow remote setup)\n"
                     "Choose 1 or 2 [1]: " << std::flush;
        std::string choice;
        if (!std::getline(std::cin, choice)) throw std::invalid_argument("setup listening address selection cancelled");
        choice = trim(choice);
        if (choice == "2" || choice == "0.0.0.0") options.setup_bind = "0.0.0.0";
        else if (!choice.empty() && choice != "1" && choice != "127.0.0.1")
            throw std::invalid_argument("choose 1 or 2 for the setup listening address");
    }
    if (options.setup_bind == "0.0.0.0" && options.setup_host.empty()) {
        std::cout << "Hostname or IP used to open the remote setup page: " << std::flush;
        if (!std::getline(std::cin, options.setup_host)) throw std::invalid_argument("setup hostname selection cancelled");
        options.setup_host = trim(options.setup_host);
        if (options.setup_host.empty()) throw std::invalid_argument("a remote setup hostname or IP is required");
    }
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
    const auto listeners = service == "delivery" ? std::vector<TcpListener>{{service, service_port(config, service), false}} : config.listeners(service);
    for (const auto& listener : listeners) {
    const int port = listener.port;
    if (port < 1 || port > 65535) throw std::invalid_argument("invalid " + listener.name + " port");
    const auto address = asio::ip::make_address(internal_service(service) ? "127.0.0.1" : config.text(service == "admin" ? "admin_bind" : "bind", "127.0.0.1"));
    asio::io_context context;
    tcp::acceptor test(context);
    std::error_code error;
    test.open(address.is_v6() ? tcp::v6() : tcp::v4(), error);
#ifndef _WIN32
    // Match Asio's listener policy so a stopped service's TIME_WAIT sockets
    // do not prevent immediate startup (notably after administrator setup).
    if (!error) test.set_option(tcp::acceptor::reuse_address(true), error);
#endif
    if (!error) test.bind({address, static_cast<unsigned short>(port)}, error);
    if (!error) test.listen(asio::socket_base::max_listen_connections, error);
    if (error) throw std::runtime_error(listener.name + " cannot bind " + address.to_string() + ":" + std::to_string(port));
    }
}

void require_distinct_ports(const Config& config, const std::vector<std::string>& services) {
    std::set<int> ports;
    for (const auto& service : services) {
        const auto listeners = service == "delivery" ? std::vector<TcpListener>{{service, service_port(config, service), false}} : config.listeners(service);
        for (const auto& listener : listeners)
            if (!ports.insert(listener.port).second)
                throw std::invalid_argument("service ports must be distinct: " + listener.name);
    }
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

void readiness_https(const Config& config, const std::string& service,
                     std::chrono::steady_clock::time_point deadline) {
    // This local health probe pins the exact configured leaf, allowing private
    // certificates without changing trust or hostname checks for public clients.
    const auto path = std::filesystem::path(config.text("tls_certificate"));
    require_plain_path(path);
    if (std::filesystem::file_size(path) > 1024 * 1024) throw std::runtime_error("readiness certificate is too large");
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot read readiness certificate");
    const std::string pem{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!input) throw std::runtime_error("cannot load readiness certificate");
    std::shared_ptr<X509> expected(PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
    if (!expected) throw std::runtime_error("invalid readiness certificate");
    asio::io_context context;
    asio::ssl::context tls(asio::ssl::context::tls_client);
    tls.set_verify_mode(asio::ssl::verify_peer);
    tls.set_verify_callback([expected](bool, asio::ssl::verify_context& verification) {
        const auto native = verification.native_handle();
        if (X509_STORE_CTX_get_error_depth(native) != 0) return true;
        const auto presented = X509_STORE_CTX_get_current_cert(native);
        return presented && X509_cmp(expected.get(), presented) == 0;
    });
    asio::ssl::stream<tcp::socket> stream(context, tls);
    asio::steady_timer timer(context, std::min(deadline, std::chrono::steady_clock::now() + std::chrono::seconds(1)));
    asio::streambuf response(8192);
    const std::string request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    std::error_code failure;
    bool finished = false, healthy = false;
    auto finish = [&](std::error_code error) {
        if (finished) return;
        finished = true;
        failure = error;
        timer.cancel();
        std::error_code ignored;
        stream.lowest_layer().close(ignored);
    };
    timer.async_wait([&](std::error_code error) { if (!error) finish(asio::error::timed_out); });
    const tcp::endpoint endpoint(asio::ip::make_address(public_probe_host(config, service)),
                                 static_cast<unsigned short>(service_port(config, service)));
    stream.next_layer().async_connect(endpoint, [&](std::error_code error) {
        if (error) { finish(error); return; }
        stream.async_handshake(asio::ssl::stream_base::client, [&](std::error_code error) {
            if (error) { finish(error); return; }
            asio::async_write(stream, asio::buffer(request), [&](std::error_code error, std::size_t) {
                if (error) { finish(error); return; }
                asio::async_read_until(stream, response, "\r\n\r\n", [&](std::error_code error, std::size_t) {
                    if (!error) {
                        std::istream input(&response);
                        std::string line;
                        std::getline(input, line);
                        healthy = line.starts_with("HTTP/1.1 200 ");
                    }
                    finish(error);
                });
            });
        });
    });
    context.run();
    if (failure || !healthy) throw std::runtime_error("HTTPS application readiness probe failed");
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
            } else if ((service == "web" || service == "admin") && !config.text("tls_certificate").empty()) {
                readiness_https(config, service, deadline);
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
                if (service == "web" || service == "admin") {
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
                     "Usage: postplus [--config PATH] [--web-root PATH] [setup options]\n\n"
                     "  --config PATH       Configuration file (default: config/postplus.json)\n"
                     "  --web-root PATH     Web assets for first-run setup (default: executable/web, then ./web)\n"
                     "  --setup-port PORT   Setup page port (default: 8081)\n"
                     "  --setup-bind IP     Setup listening IP (interactive on first launch; otherwise 127.0.0.1)\n"
                     "  --setup-host HOST   Setup URL hostname; required for a wildcard bind\n"
                     "  --setup-tls-certificate PATH  Setup HTTPS certificate chain (PEM)\n"
                     "  --setup-tls-private-key PATH  Setup HTTPS private key (PEM)\n"
                     "  --help              Show this help\n\n"
                     "A missing or uninitialized configuration opens browser setup and prints\n"
                     "its URL and one-time password. An initialized configuration starts all\n"
                     "services. Saved administration settings restart affected services.\n"
                     "Manual configuration edits stay pending until restart. Ctrl+C stops them.\n"
                     "A terminal prompts for the first-run setup address. For unattended remote\n"
                     "setup, specify --setup-bind 0.0.0.0 and --setup-host HOST. Setup HTTPS\n"
                     "is optional; use a trusted network when configuring over HTTP.\n";
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
        if (value.value("setup_required",false) || ((!token || !*token) && value.value("service_token_file",std::string{}).empty() && !value.value("setup_complete",false))) {
            needs_setup = true;
            incomplete_configuration = std::move(bytes);
        }
    }
    if (needs_setup) {
        choose_setup_listener(options);
        if (!run_setup({options.config, options.web_root, options.setup_port, incomplete_configuration,
                       options.setup_bind,options.setup_host,options.setup_certificate,options.setup_key},
                       [&](const Config& staged, const std::string& username, const std::string& password) {
                           provision_admin(binaries, staged, username, password);
                       })) {
            std::cout << "Setup stopped; PostPlus services were not started.\n" << std::flush;
            return 0;
        }
    } else if (status_error) {
        throw std::runtime_error("cannot inspect configuration file: " + options.config.string());
    }
    // The setup listener temporarily owns SIGINT/SIGTERM through Asio. Its
    // destruction can restore the default POSIX dispositions, so reinstall the
    // supervisor handlers before any long-lived children are started.
    std::signal(SIGINT, stop_signal);
    std::signal(SIGTERM, stop_signal);
    if (stop_requested()) {
        std::cout << "Shutdown requested; PostPlus services were not started.\n" << std::flush;
        return 0;
    }
    auto config = Config::from_file(options.config);
    auto update_options = supervisor_update_options(config);
    const auto pending_relaunch = pending_update_relaunch(update_options);
    if (pending_relaunch && pending_relaunch->at("config") != config.source.string())
        throw MaintenanceError("Pending launcher update belongs to another configuration.");
    const std::filesystem::path data_directory(config.text("data_dir"));
    require_plain_path(data_directory);
    std::filesystem::create_directories(data_directory);
    DataDirectoryLock data_lease(data_directory);
    configure_logging(config, "postplus");
    // Create persistent restart tracking before installation/port preflight so
    // a failed manager relaunch records failure. Declare control before the
    // process group: children must be reaped before their snapshots are removed.
    SupervisorControl control(config);
    for (auto& recovered : recover_interrupted_updates(update_options)) {
        const auto id=recovered.at("job_id").get<std::string>();
        const auto version=recovered.at("version").get<std::string>();
        control.update_finished({"apply",id,version},std::move(recovered));
        log("postplus","restored an interrupted module update before starting services","warn");
    }
#ifndef _WIN32
    if (pending_relaunch) {
        const auto id=pending_relaunch->at("job_id").get<std::string>();
        const auto state=update_job_status(update_options,id).value("state","");
        if (state!="installed" && state!="complete" && state!="rolled_back") {
            auto restored=rollback_staged_update(update_options,id);
            finish_update_relaunch(update_options,id);
            restored["state"]="failed"; restored["rolled_back"]=true;
            restored["error"]="An interrupted launcher update was restored before service startup.";
            const auto version=restored.at("version").get<std::string>();
            control.update_finished({"apply",id,version},std::move(restored));
            const auto* manager=std::getenv("POSTPLUS_SERVICE_MANAGER");
            return manager && std::string_view(manager)=="systemd" ? 75 : 76;
        }
    }
#endif
    const auto& services = supervisor_services();
    // Validate the complete installation before creating any child process.
    ProcessGroup children;
    const auto initial_snapshot = control.snapshot_config(config);
    std::map<std::string, Config> running_config;
    std::map<std::string, std::filesystem::path> running_snapshot;
    auto start_service = [&](const std::string& service, const Config& active, const std::filesystem::path& snapshot) {
        children.start(service, service_executable(binaries, service),
            {"--config", path_argument(active.source), "--config-snapshot", path_argument(snapshot)});
        wait_ready(children, active, service);
        running_config[service] = active;
        running_snapshot[service] = snapshot;
        log("postplus", service + " is ready");
    };
    bool relaunch_committed = false;
    try {
    require_distinct_ports(config, services);
    for (const auto& service : services) {
        if (!std::filesystem::is_regular_file(service_executable(binaries, service)))
            throw std::runtime_error("missing executable for " + service + "; install all PostPlus services together");
        port_available(config, service);
    }
    log("postplus", "starting service group");
    for (const auto& service : services) {
        if (stop_requested()) break;
        try { start_service(service, config, initial_snapshot); }
        catch (const std::exception&) { if (stop_requested()) break; throw; }
    }
    if (!stop_requested()) { control.ready(config); log("postplus", "all services are ready"); }
    if (pending_relaunch && !stop_requested()) {
        const auto id=pending_relaunch->at("job_id").get<std::string>();
        auto result=update_job_status(update_options,id);
        if (result.value("state","")=="rolled_back") {
            result["state"]="failed";
            result["rolled_back"]=true;
            if (!result.contains("error")) result["error"]="Updated launcher failed; previous modules and services were restored.";
        } else { result=commit_staged_update(update_options,id); relaunch_committed=true; }
        finish_update_relaunch(update_options,id);
        const auto version=result.at("version").get<std::string>();
        control.update_finished({"apply",id,version},std::move(result));
        log("postplus","launcher update committed after all services became ready");
    }
    } catch (const std::exception& error) {
        if (!pending_relaunch) throw;
        const auto id=pending_relaunch->at("job_id").get<std::string>();
        if (relaunch_committed) {
            // Once readiness and the transaction are committed, failures in
            // status/marker cleanup must not kill the healthy new generation.
            log("postplus",std::string("launcher upgrade committed; completion reporting needs recovery: ")+error.what(),"warn");
            try {
                auto result=update_job_status(update_options,id);
                finish_update_relaunch(update_options,id);
                const auto version=result.at("version").get<std::string>();
                control.update_finished({"apply",id,version},std::move(result));
            } catch (const std::exception& reporting_error) {
                log("postplus",std::string("cannot publish committed launcher update status: ")+reporting_error.what(),"warn");
            }
        } else {
        children.stop();
        if (update_job_status(update_options,id).value("state","")=="complete") {
            // A leftover marker can also be read on a later ordinary start.
            // A failure before readiness then follows normal startup failure
            // handling; committed files cannot be restored by replaying a job.
            log("postplus",std::string("committed launcher failed service startup: ")+error.what(),"error");
            return 1;
        }
#ifdef _WIN32
        // The detached helper owns the running launcher's replacement and rollback.
        log("postplus",std::string("updated launcher startup failed: ")+error.what(),"error");
        return 1;
#else
        auto restored=rollback_staged_update(update_options,id);
        finish_update_relaunch(update_options,id);
        restored["state"]="failed"; restored["error"]=error.what(); restored["rolled_back"]=true;
        const auto version=restored.at("version").get<std::string>();
        control.update_finished({"apply",id,version},std::move(restored));
        log("postplus","updated launcher startup failed; restored previous modules","error");
        const auto* manager=std::getenv("POSTPLUS_SERVICE_MANAGER");
        return manager && std::string_view(manager)=="systemd" ? 75 : 76;
#endif
        }
    }
    std::cout << "Administration: " << settings_url(config,"admin") << '\n'
              << "Webmail:        " << settings_url(config,"web") << '\n' << std::flush;
    bool admin_shutdown = false;
    auto restart_progress = [&](const std::string& message) { log("postplus", "[restart] " + message); };
    auto stop_selected = [&](const std::vector<std::string>& selected) {
        auto phase = [&](std::initializer_list<const char*> group) {
            std::vector<std::string> names;
            for (auto name : group) if (std::find(selected.begin(), selected.end(), name) != selected.end()) names.emplace_back(name);
            return children.stop_services(names, std::chrono::seconds(35), restart_progress);
        };
        bool graceful = phase({"smtp", "pop3", "imap", "web", "admin"});
        graceful = phase({"delivery"}) && graceful;
        graceful = phase({"filter", "transfer", "storage", "auth"}) && graceful;
        return graceful;
    };
    std::atomic<bool> cancel_update = false;
    std::future<Json> download;
    std::optional<SupervisorUpdateRequest> downloading;
    struct CancelDownload {
        std::atomic<bool>& cancel;
        std::future<Json>& future;
        ~CancelDownload() { cancel.store(true); if (future.valid()) future.wait(); }
    } cancel_download{cancel_update, download};
    while (!stop_requested()) {
        ensure_alive(children);
        if (control.shutdown_requested()) { admin_shutdown = true; break; }
        if (download.valid() && download.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            try {
                auto result = download.get(); result["state"] = "staged";
                control.update_finished(*downloading, std::move(result));
                log("postplus", "update downloaded and verified; existing services remain running");
            } catch (const std::exception& error) {
                control.update_finished(*downloading, {{"state", "failed"}, {"error", error.what()}});
                log("postplus", std::string("update download failed: ") + error.what(), "error");
            }
            downloading.reset();
        }
        if (auto update = control.update_requested()) {
            if (update->action == "stage") {
                downloading = *update;
                control.update_progress(*update, {{"state", "downloading"}});
                const auto request = *update;
                download = std::async(std::launch::async, [&, request] {
                    return stage_update(update_options, request.version, request.job_id, cancel_update,
                        [&](const Json& progress) { control.update_progress(request, progress); });
                });
            } else {
                std::vector<std::string> selected;
                bool stopped = false;
                try {
                    auto plan = update_job_status(update_options, update->job_id);
                    const auto requested_services = plan.at("services").get<std::vector<std::string>>();
                    for (const auto& service : services)
                        if (std::find(requested_services.begin(), requested_services.end(), service) != requested_services.end()) selected.push_back(service);
                    if (selected.size() != requested_services.size()) throw MaintenanceError("Invalid update service plan.", 409);
                    plan["state"] = "applying"; control.update_progress(*update, plan);
                    const bool launcher_changed=plan.value("requires_launcher_restart",false);
                    if (launcher_changed) selected=services;
#ifdef _WIN32
                    if (launcher_changed) {
                        stopped=true;
                        if (!stop_selected(selected)) throw std::runtime_error("Affected services did not stop cleanly.");
                        (void)launch_update_takeover(update_options,update->job_id,config.source,GetCurrentProcessId());
                        log("postplus","handing launcher replacement to the verified private update helper");
                        return 0;
                    }
#endif
                    stopped = true;
                    if (!stop_selected(selected)) throw std::runtime_error("Affected services did not stop cleanly.");
                    if (launcher_changed) (void)prepare_update_relaunch(update_options,update->job_id,config.source);
                    (void)apply_staged_update(update_options, update->job_id);
                    if (launcher_changed) {
                        const auto* manager=std::getenv("POSTPLUS_SERVICE_MANAGER");
                        log("postplus","modules installed; relaunching to verify the new launcher");
                        return manager && std::string_view(manager)=="systemd" ? 75 : 76;
                    }
                    for (const auto& service : selected) {
                        if (stop_requested()) throw std::runtime_error("Update interrupted by shutdown.");
                        port_available(running_config.at(service), service);
                        start_service(service, running_config.at(service), running_snapshot.at(service));
                    }
                    ensure_alive(children);
                    auto result = commit_staged_update(update_options, update->job_id);
                    result["state"] = "complete";
                    control.update_finished(*update, std::move(result));
                    log("postplus", "changed modules upgraded; affected services are ready");
                } catch (const std::exception& error) {
                    const std::string failure = error.what();
                    if (stopped && update_job_status(update_options, update->job_id).value("state", "") == "complete") {
                        // A committed transaction must not be described as a
                        // rollback failure if later status reporting throws.
                        log("postplus","update committed; completion reporting failed: " + failure,"warn");
                        try { control.update_finished(*update,update_job_status(update_options,update->job_id)); }
                        catch (const std::exception& reporting_error) {
                            log("postplus",std::string("cannot publish committed update status: ")+reporting_error.what(),"warn");
                        }
                        continue;
                    }
                    bool rolled_back = !stopped;
                    if (stopped) {
                        (void)stop_selected(selected);
                        try {
                            // A failed apply can already have replaced some files,
                            // and its own rollback can fail. Consult the durable
                            // journal even when apply never returned successfully.
                            (void)rollback_staged_update(update_options, update->job_id);
                            finish_update_relaunch(update_options, update->job_id);
                            if (!stop_requested()) {
                                for (const auto& service : selected) {
                                    port_available(running_config.at(service), service);
                                    start_service(service, running_config.at(service), running_snapshot.at(service));
                                }
                                ensure_alive(children); rolled_back = true;
                            }
                        } catch (const std::exception& rollback_error) {
                            control.update_finished(*update, {{"state", "failed"}, {"error", failure + " Rollback failed: " + rollback_error.what()}, {"rolled_back", false}});
                            throw std::runtime_error("Update and rollback failed; stopping the service group.");
                        }
                    } else finish_update_relaunch(update_options, update->job_id);
                    control.update_finished(*update, {{"state", "failed"}, {"error", failure}, {"rolled_back", rolled_back}});
                    log("postplus", "update failed: " + failure, "error");
                }
            }
        }
        if (auto requested = control.restart_requested()) {
            auto request = std::move(*requested);
            const auto previous_active = config;
            const auto previous_config = running_config;
            const auto previous_snapshot = running_snapshot;
            bool children_stopped = false;
            try {
                // An editor changing the file after submission must not silently
                // alter the requested revision or trigger an implicit restart.
                if (Config::from_file(config.source).values != request.config.values)
                    throw MaintenanceError("Configuration changed after scheduling; reload and retry.", 409);
                request.services = restart_plan(config, request.config, request.mode);
                require_distinct_ports(request.config, services);
                const auto target_snapshot = control.snapshot_config(request.config);
                const auto* manager = std::getenv("POSTPLUS_SERVICE_MANAGER");
                const bool managed_all = request.mode == "all" && manager && std::string_view(manager) == "systemd";
                control.restart_running(request, managed_all);
                children_stopped = true;
                if (!stop_selected(request.services)) throw std::runtime_error("Affected services did not stop cleanly; the previous configuration will be restored.");
                if (stop_requested()) {
                    control.restart_failed(request, "Restart interrupted by a shutdown signal.");
                    break;
                }
                if (managed_all) {
                    // systemd relaunches only this deliberate exit. The child
                    // never invokes a shell or systemctl with admin privileges.
                    log("postplus", "all services stopped; requesting service-manager restart (exit 75)");
                    return 75;
                }
                for (const auto& service : request.services) port_available(request.config, service);
                for (const auto& service : request.services) {
                    if (stop_requested()) throw std::runtime_error("Restart interrupted by a shutdown signal.");
                    start_service(service, request.config, target_snapshot);
                }
                ensure_alive(children);
                config = request.config;
                update_options = supervisor_update_options(config);
                configure_logging(config, "postplus");
                control.restart_complete(request, config);
            } catch (const std::exception& error) {
                const auto failure = std::string(error.what());
                config = previous_active;
                configure_logging(config, "postplus");
                bool rolled_back = !children_stopped;
                if (children_stopped && !stop_requested()) {
                    restart_progress("restoring the previous configuration after a failed restart");
                    // Every affected service is stopped again before rollback;
                    // never leave new listeners using an old RPC dependency.
                    (void)stop_selected(request.services);
                    try {
                        for (const auto& service : request.services) {
                            port_available(previous_config.at(service), service);
                            start_service(service, previous_config.at(service), previous_snapshot.at(service));
                        }
                        ensure_alive(children);
                        rolled_back = true;
                    } catch (const std::exception& rollback_error) {
                        control.restart_failed(request, failure + " Rollback failed: " + rollback_error.what());
                        throw std::runtime_error("Restart and rollback failed; stopping the whole service group.");
                    }
                }
                control.restart_failed(request, failure, rolled_back);
                if (stop_requested()) break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    auto progress = [&](const std::string& message) {
        log("postplus", message);
        if (config.text("log_level", "info") != "info" && config.text("log_level", "info") != "debug")
            std::cout << "[shutdown] " << message << '\n' << std::flush;
    };
    progress(admin_shutdown ? "administrator requested shutdown; saved configuration is retained" : "shutdown signal received; stopping service group");
    progress("1/3 closing mail and web listeners; finishing active requests");
    bool graceful = children.stop_services({"smtp", "pop3", "imap", "web", "admin"}, std::chrono::seconds(35), progress);
    progress("2/3 stopping delivery; pending queue entries remain saved for the next start");
    graceful = children.stop_services({"delivery"}, std::chrono::seconds(35), progress) && graceful;
    progress("3/3 stopping supporting services and closing the mail and account databases");
    graceful = children.stop_services({"filter", "transfer", "storage", "auth"}, std::chrono::seconds(35), progress) && graceful;
    progress(graceful ? "service group stopped; data saved; it is safe to close this terminal" : "service group stopped with errors; review the logs before restarting");
    // An explicit administrator shutdown must remain stopped under systemd's
    // Restart=on-failure, even if forced cleanup was needed. Errors remain in
    // the logs; only the separate deliberate full-restart path exits 75.
    if (admin_shutdown) return 0;
    return graceful ? 0 : 1;
}
}
}

int main(int argc, char** argv) {
    try {
#ifndef _WIN32
        const auto initial_executable=postplus::executable_path(argv[0]);
#endif
        const auto result=postplus::run(argc, argv);
#ifndef _WIN32
        if (result==76) {
            execv(initial_executable.c_str(),argv);
            // exec can fail before the new launcher's startup recovery runs.
            // The old executable is still executing from its original inode.
            // Restore the journaled generation before attempting it again.
            {
                const auto config=postplus::Config::from_file(postplus::parse_options(argc,argv).config);
                auto update=postplus::supervisor_update_options(config);
                update.install_directory=initial_executable.parent_path();
                postplus::DataDirectoryLock lease(config.text("data_dir"));
                const auto pending=postplus::pending_update_relaunch(update);
                if (!pending) throw std::runtime_error("cannot relaunch PostPlus after module upgrade");
                (void)postplus::rollback_staged_update(update,pending->at("job_id").get<std::string>());
                // Keep the handoff so the restored launcher reports failure
                // only after all of its original services become ready.
                postplus::log("postplus","new launcher could not execute; restored previous modules","error");
            }
            execv(initial_executable.c_str(),argv);
            throw std::runtime_error("previous modules were restored but the launcher cannot execute");
        }
#endif
        return result;
    }
    catch (const std::exception& error) {
        if (postplus::stop_requested()) return 0;
        postplus::log("postplus", error.what(), "error");
        return 1;
    }
}
