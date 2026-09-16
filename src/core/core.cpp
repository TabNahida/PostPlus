#include <postplus/core.hpp>
#include <postplus/process.hpp>
#include <postplus/trust.hpp>
#include <asio/ssl.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

namespace postplus {
std::string lower(std::string value) {
    for (auto& c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return value;
}
std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}
bool valid_address(std::string_view value) {
    if (value.empty() || value.size() > 254) return false;
    const auto at = value.find('@');
    if (at == std::string_view::npos || at == 0 || at > 64 || at + 1 == value.size() || value.find('@', at + 1) != std::string_view::npos) return false;
    if (value.front() == '.' || value[at - 1] == '.' || value.find("..") != std::string_view::npos) return false;
    constexpr std::string_view local_symbols = ".!#$%&'*+-/=?^_`{|}~";
    for (std::size_t i = 0; i < at; ++i) {
        const auto c = value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || local_symbols.find(c) != std::string_view::npos)) return false;
    }
    std::size_t label = 0;
    for (std::size_t i = at + 1; i < value.size(); ++i) {
        const auto c = value[i];
        if (c == '.') {
            if (!label || value[i - 1] == '-') return false;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return false;
            if ((!label && c == '-') || ++label > 63) return false;
        }
    }
    return label && value.back() != '-';
}
std::string random_hex(std::size_t bytes) {
    if (!bytes || bytes > 1024) throw std::invalid_argument("invalid random length");
    std::vector<unsigned char> data(bytes);
    if (RAND_bytes(data.data(), static_cast<int>(bytes)) != 1) throw std::runtime_error("secure random generator failed");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes * 2);
    for (auto byte : data) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
bool secure_equal(std::string_view a, std::string_view b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
std::string base64_encode(std::string_view input) {
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max() / 2)) throw std::length_error("base64 input too large");
    std::string output(4 * ((input.size() + 2) / 3) + 1, '\0');
    const int size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()), reinterpret_cast<const unsigned char*>(input.data()), static_cast<int>(input.size()));
    output.resize(static_cast<std::size_t>(size));
    return output;
}
std::string base64_decode(std::string_view input) {
    if (input.empty()) return {};
    if (input.size() % 4 != 0 || input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::invalid_argument("invalid base64");
    std::size_t padding = 0;
    if (input.back() == '=') ++padding;
    if (input.size() > 1 && input[input.size() - 2] == '=') ++padding;
    for (std::size_t i = 0; i < input.size() - padding; ++i) {
        const char c = input[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/')) throw std::invalid_argument("invalid base64");
    }
    std::string output(input.size() / 4 * 3, '\0');
    const int size = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(output.data()), reinterpret_cast<const unsigned char*>(input.data()), static_cast<int>(input.size()));
    if (size < 0) throw std::invalid_argument("invalid base64");
    output.resize(static_cast<std::size_t>(size) - padding);
    if (base64_encode(output) != input) throw std::invalid_argument("noncanonical base64");
    return output;
}
Config Config::load(int argc, char** argv) {
    std::filesystem::path path = "config/postplus.json";
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--config") {
            if (++i >= argc) throw std::invalid_argument("--config requires a path");
            path = argv[i];
        }
    }
    return from_file(path);
}
Config Config::from_file(const std::filesystem::path& path) {
    Config config;
    config.source = std::filesystem::absolute(path);
    std::ifstream file(config.source);
    if (!file) throw std::runtime_error("cannot open config: " + config.source.string());
    file >> config.values;
    if (!config.values.is_object()) throw std::invalid_argument("config must be a JSON object");
    for (const auto* key : {"data_dir", "web_root", "tls_certificate", "tls_private_key", "log_dir", "service_token_file", "smarthost_password_file"}) {
        auto value = config.text(key);
        if (value.empty()) continue;
        auto resolved = std::filesystem::path(value);
        if (resolved.is_relative()) resolved = config.source.parent_path() / resolved;
        config.values[key] = resolved.lexically_normal().string();
    }
    if (config.text("data_dir").empty()) config.values["data_dir"] = (config.source.parent_path() / "../data").lexically_normal().string();
    if (config.text("log_dir").empty()) config.values["log_dir"] = (std::filesystem::path(config.text("data_dir")) / "logs").string();
    if (config.text("tls_certificate").empty() != config.text("tls_private_key").empty()) throw std::invalid_argument("both TLS certificate and private key are required");
    if (config.number("max_message_bytes", 10485760) < 1024 || config.number("max_message_bytes", 10485760) > 100 * 1024 * 1024) throw std::invalid_argument("max_message_bytes must be 1024..104857600");
    if (config.number("max_connections", 32) < 1 || config.number("max_connections", 32) > 1024) throw std::invalid_argument("max_connections must be 1..1024");
    if (config.number("timeout_seconds", 30) < 1 || config.number("timeout_seconds", 30) > 300) throw std::invalid_argument("timeout_seconds must be 1..300");
    if (!valid_address("postmaster@" + config.text("domain", "localhost"))) throw std::invalid_argument("invalid domain");
    (void)config.token();
    return config;
}
std::string Config::text(const std::string& key, const std::string& fallback) const { return values.value(key, fallback); }
int Config::number(const std::string& key, int fallback) const { return values.value(key, fallback); }
bool Config::flag(const std::string& key, bool fallback) const { return values.value(key, fallback); }
int Config::port(const std::string& service) const {
    static const std::map<std::string, int> defaults{{"auth",18081},{"storage",18082},{"filter",18083},{"transfer",18084},{"smtp",2525},{"pop3",1110},{"imap",1143},{"web",8080},{"admin",8081}};
    int port_value = defaults.at(service);
    if (values.contains("ports")) port_value = values.at("ports").value(service, port_value);
    if (port_value < 1 || port_value > 65535) throw std::invalid_argument("invalid service port");
    return port_value;
}
std::string Config::token() const {
    const auto name = text("service_token_env", "POSTPLUS_SERVICE_TOKEN");
    const char* token_value = std::getenv(name.c_str());
    std::string result;
    if (token_value && *token_value) result = token_value;
    else if (!text("service_token_file").empty()) {
        auto path = std::filesystem::path(text("service_token_file"));
        if (path.is_relative()) path = source.parent_path() / path;
        if (std::filesystem::is_symlink(std::filesystem::symlink_status(path)) || !std::filesystem::is_regular_file(path) || std::filesystem::file_size(path) > 1024)
            throw std::runtime_error("invalid service token file");
        std::ifstream file(path,std::ios::binary);
        if (!file) throw std::runtime_error("cannot read service token file");
        result.assign(std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>());
        result = trim(result);
    } else throw std::runtime_error("set " + name + " or configure service_token_file");
    if (result.size() < 32 || result.size() > 1024 || result.find_first_of("\r\n\0",0,3) != std::string::npos) throw std::invalid_argument("invalid service token");
    return result;
}

std::string Config::relay_password() const {
    const auto name = text("smarthost_password_env", "POSTPLUS_SMARTHOST_PASSWORD");
    std::string result;
    if (const char* value = std::getenv(name.c_str()); value && *value) result = value;
    else if (!text("smarthost_password_file").empty()) {
        auto path = std::filesystem::path(text("smarthost_password_file"));
        if (path.is_relative()) path = source.parent_path() / path;
        const auto status = std::filesystem::symlink_status(path);
        if (!std::filesystem::is_regular_file(status) || std::filesystem::file_size(path) > 4096)
            throw std::runtime_error("invalid smarthost password file");
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("cannot read smarthost password file");
        result.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        // Permit a text file's final newline while preserving password spaces.
        if (result.ends_with('\n')) result.pop_back();
        if (result.ends_with('\r')) result.pop_back();
    }
    if (result.size() > 4096 || result.find_first_of("\r\n\0", 0, 3) != std::string::npos)
        throw std::invalid_argument("invalid smarthost password");
    return result;
}

struct Connection::Impl {
    asio::io_context io;
    tcp::socket socket{io};
    tcp::resolver resolver{io};
    asio::steady_timer timer{io};
    std::chrono::seconds timeout;
    std::optional<std::chrono::steady_clock::time_point> operation_deadline;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::atomic<bool> stopping = false;
    std::string buffer;
    std::unique_ptr<asio::ssl::context> tls_context;
    std::unique_ptr<asio::ssl::stream<tcp::socket&>> tls;
    explicit Impl(std::chrono::seconds value) : timeout(value) {}
    template<class Start> void wait(Start start) {
        if (stopping.load()) throw std::runtime_error("service stopping");
        io.restart();
        std::error_code result;
        bool expired = false;
        auto expires = std::chrono::steady_clock::now() + timeout;
        if (operation_deadline) expires = std::min(expires, *operation_deadline);
        if (deadline) expires = std::min(expires, *deadline);
        if (expires <= std::chrono::steady_clock::now()) throw std::runtime_error("transaction timed out");
        timer.expires_at(expires);
        timer.async_wait([&](std::error_code ec) {
            if (!ec) { expired = true; std::error_code ignored; socket.cancel(ignored); resolver.cancel(); }
        });
        try {
            start([&](std::error_code ec) { result = ec; timer.cancel(); });
            io.run();
        } catch (...) { timer.cancel(); io.poll(); throw; }
        if (expired) throw std::runtime_error("connection timed out");
        if (result) throw std::system_error(result);
    }
    std::string receive(std::size_t size) {
        std::string bytes(size, '\0');
        std::size_t count = 0;
        wait([&](auto done) {
            auto handler = [&, done](std::error_code ec, std::size_t n) { count = n; done(ec); };
            if (tls) tls->async_read_some(asio::buffer(bytes), handler);
            else socket.async_read_some(asio::buffer(bytes), handler);
        });
        bytes.resize(count);
        return bytes;
    }
};
Connection::Connection(std::chrono::seconds timeout) : impl_(std::make_unique<Impl>(timeout)) {}
Connection::~Connection() = default;
tcp::socket& Connection::socket() { return impl_->socket; }
bool Connection::encrypted() const { return static_cast<bool>(impl_->tls); }
void Connection::set_deadline(std::optional<std::chrono::steady_clock::time_point> deadline) { impl_->deadline = deadline; }
void Connection::request_stop() { impl_->stopping.store(true); }
void Connection::connect(const std::string& host, int port) {
    tcp::resolver::results_type endpoints;
    impl_->wait([&](auto done) {
        impl_->resolver.async_resolve(host, std::to_string(port), [&,done](std::error_code ec, auto resolved) { endpoints = std::move(resolved); done(ec); });
    });
    impl_->wait([&](auto done) { asio::async_connect(impl_->socket, endpoints, [done](std::error_code ec, const auto&) { done(ec); }); });
}
std::string Connection::line(std::size_t limit) {
    // A slow byte stream must not reset the deadline for the same logical line.
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& impl; ~Reset() { impl.operation_deadline.reset(); } } reset{*impl_};
    for (;;) {
        const auto end = impl_->buffer.find("\r\n");
        if (end != std::string::npos) {
            if (end > limit || impl_->buffer.find('\n') < end) throw std::length_error("invalid or oversized line");
            auto line_value = impl_->buffer.substr(0, end);
            impl_->buffer.erase(0, end + 2);
            return line_value;
        }
        if (impl_->buffer.size() >= limit + 2) throw std::length_error("line too long");
        impl_->buffer += impl_->receive(std::min<std::size_t>(4096, limit + 2 - impl_->buffer.size()));
    }
}
std::string Connection::read(std::size_t count) {
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& impl; ~Reset() { impl.operation_deadline.reset(); } } reset{*impl_};
    std::string result = impl_->buffer.substr(0, count);
    impl_->buffer.erase(0, result.size());
    while (result.size() < count) result += impl_->receive(std::min<std::size_t>(65536, count - result.size()));
    return result;
}
void Connection::write(std::string_view bytes) {
    impl_->wait([&](auto done) {
        auto handler = [done](std::error_code ec, std::size_t) { done(ec); };
        if (impl_->tls) asio::async_write(*impl_->tls, asio::buffer(bytes), handler);
        else asio::async_write(impl_->socket, asio::buffer(bytes), handler);
    });
}
void Connection::start_tls_server(const Config& config) {
    if (encrypted() || !impl_->buffer.empty()) throw std::runtime_error("invalid TLS transition");
    impl_->tls_context = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_server);
    SSL_CTX_set_min_proto_version(impl_->tls_context->native_handle(), TLS1_2_VERSION);
    impl_->tls_context->use_certificate_chain_file(config.text("tls_certificate"));
    impl_->tls_context->use_private_key_file(config.text("tls_private_key"), asio::ssl::context::pem);
    impl_->tls = std::make_unique<asio::ssl::stream<tcp::socket&>>(impl_->socket, *impl_->tls_context);
    impl_->wait([&](auto done) { impl_->tls->async_handshake(asio::ssl::stream_base::server, done); });
}
void Connection::start_tls_client(const std::string& hostname) {
    if (encrypted() || !impl_->buffer.empty()) throw std::runtime_error("invalid TLS transition");
    impl_->tls_context = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client);
    SSL_CTX_set_min_proto_version(impl_->tls_context->native_handle(), TLS1_2_VERSION);
    impl_->tls_context->set_default_verify_paths();
    add_platform_trust_roots(SSL_CTX_get_cert_store(impl_->tls_context->native_handle()));
    impl_->tls_context->set_verify_mode(asio::ssl::verify_peer);
    impl_->tls = std::make_unique<asio::ssl::stream<tcp::socket&>>(impl_->socket, *impl_->tls_context);
    impl_->tls->set_verify_callback(asio::ssl::host_name_verification(hostname));
    if (SSL_set_tlsext_host_name(impl_->tls->native_handle(), hostname.c_str()) != 1) throw std::runtime_error("cannot set TLS hostname");
    impl_->wait([&](auto done) { impl_->tls->async_handshake(asio::ssl::stream_base::client, done); });
}
void serve_tcp(const Config& config, const std::string& service, Session handler, bool internal, std::function<bool()> stop_requested) {
    asio::io_context io;
    const auto address = asio::ip::make_address(internal ? "127.0.0.1" : config.text(service == "admin" ? "admin_bind" : "bind", "127.0.0.1"));
    tcp::acceptor acceptor(io, {address, static_cast<unsigned short>(config.port(service))});
    const auto max = config.number("max_connections", 32);
    asio::thread_pool workers(static_cast<std::size_t>(max));
    std::atomic<int> active = 0;
    // Registry is only accessed from the listener executor, never from workers.
    std::vector<std::weak_ptr<Connection>> connections;
    asio::signal_set signals(io, SIGINT, SIGTERM);
    asio::steady_timer stop_timer(io);
    (void)process_stop_requested();
    auto stop_listener = [&](bool cancel_sessions) {
        std::error_code ec; acceptor.close(ec);
        signals.cancel(); stop_timer.cancel();
        if (cancel_sessions) for (auto& weak : connections) if (auto connection = weak.lock()) connection->request_stop();
    };
    signals.async_wait([&](std::error_code ec, int) {
        if (!ec) stop_listener(true);
    });
    std::function<void()> check_stop;
    check_stop = [&] {
        if (process_stop_requested()) { stop_listener(true); return; }
        if (stop_requested && stop_requested()) { stop_listener(false); return; }
        stop_timer.expires_after(std::chrono::milliseconds(100));
        stop_timer.async_wait([&](std::error_code ec) { if (!ec) check_stop(); });
    };
    check_stop();
    std::function<void()> accept_next;
    accept_next = [&] {
        auto connection = std::make_shared<Connection>(std::chrono::seconds(config.number("timeout_seconds", 30)));
        acceptor.async_accept(connection->socket(), [&,connection](std::error_code ec) {
            if (!ec && active.load() < max) {
                std::erase_if(connections, [](const auto& weak) { return weak.expired(); });
                connections.push_back(connection);
                ++active;
                asio::post(workers, [&,connection] {
                    try { handler(*connection); }
                    catch (const std::exception&) { log(service, "session closed after I/O or protocol error", "debug"); }
                    --active;
                });
            }
            if (acceptor.is_open()) accept_next();
        });
    };
    accept_next();
    log(service, "listening on " + address.to_string() + ":" + std::to_string(config.port(service)));
    io.run();
    workers.join();
}

namespace {
Json wire_encode(Json value) {
    if (value.is_object()) {
        if (value.contains("raw")) {
            value["raw_base64"] = base64_encode(value.at("raw").get<std::string>());
            value.erase("raw");
        }
        for (auto& item : value.items()) item.value() = wire_encode(std::move(item.value()));
    } else if (value.is_array()) for (auto& item : value) item = wire_encode(std::move(item));
    return value;
}
Json wire_decode(Json value) {
    if (value.is_object()) {
        if (value.contains("raw_base64")) {
            if (value.contains("raw")) throw std::invalid_argument("ambiguous raw encoding");
            value["raw"] = base64_decode(value.at("raw_base64").get<std::string>());
            value.erase("raw_base64");
        }
        for (auto& item : value.items()) item.value() = wire_decode(std::move(item.value()));
    } else if (value.is_array()) for (auto& item : value) item = wire_decode(std::move(item));
    return value;
}
std::size_t body_size(const std::map<std::string,std::string>& headers, std::size_t limit) {
    if (headers.contains("transfer-encoding")) throw std::invalid_argument("chunked transfer is unsupported");
    const auto it = headers.find("content-length");
    if (it == headers.end()) return 0;
    std::size_t size = 0;
    const auto [end, ec] = std::from_chars(it->second.data(), it->second.data() + it->second.size(), size);
    if (ec != std::errc{} || end != it->second.data() + it->second.size() || size > limit) throw std::length_error("invalid content length");
    return size;
}
std::map<std::string,std::string> read_headers(Connection& connection) {
    std::map<std::string,std::string> headers;
    std::size_t bytes = 0;
    for (int count = 0; count < 100; ++count) {
        auto line = connection.line();
        if (line.empty()) return headers;
        bytes += line.size();
        if (bytes > 32768) throw std::length_error("headers too large");
        const auto split = line.find(':');
        if (!split || split == std::string::npos) throw std::invalid_argument("invalid header");
        auto name = lower(line.substr(0, split));
        for (char c : name) if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) throw std::invalid_argument("invalid header name");
        auto value = trim(line.substr(split + 1));
        for (unsigned char c : value) if ((c < 32 && c != '\t') || c == 127) throw std::invalid_argument("invalid header value");
        if (!headers.emplace(name, value).second) throw std::invalid_argument("duplicate header");
    }
    throw std::length_error("too many headers");
}
std::size_t rpc_limit(const Config& config) {
    // JSON escaping may expand a raw mail byte to six bytes.
    return static_cast<std::size_t>(config.number("max_message_bytes", 10485760)) * 6 + 1048576;
}
void check_json_depth(std::string_view body) {
    bool quoted = false, escaped = false;
    int depth = 0;
    for (const char c : body) {
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') quoted = true;
        else if (c == '{' || c == '[') { if (++depth > 64) throw std::invalid_argument("JSON nesting limit exceeded"); }
        else if (c == '}' || c == ']') --depth;
    }
}
void send_response(Connection& connection, const HttpResponse& response) {
    static const std::map<int,std::string> reasons{{200,"OK"},{201,"Created"},{202,"Accepted"},{204,"No Content"},{400,"Bad Request"},{401,"Unauthorized"},{403,"Forbidden"},{404,"Not Found"},{405,"Method Not Allowed"},{409,"Conflict"},{413,"Payload Too Large"},{429,"Too Many Requests"},{500,"Internal Server Error"},{503,"Service Unavailable"}};
    const auto it = reasons.find(response.status);
    std::string out = "HTTP/1.1 " + std::to_string(response.status) + " " + (it == reasons.end() ? "Response" : it->second) + "\r\n";
    out += "Content-Type: " + response.content_type + "\r\nContent-Length: " + std::to_string(response.body.size()) + "\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n";
    for (const auto& [name,value] : response.headers) {
        if (name.find_first_of("\r\n:") != std::string::npos || value.find_first_of("\r\n") != std::string::npos) throw std::invalid_argument("invalid response header");
        out += name + ": " + value + "\r\n";
    }
    out += "\r\n";
    connection.write(out);
    connection.write(response.body);
}
void reject_request(Connection& connection, const HttpRequest& request, const HttpResponse& response) {
    connection.set_deadline(std::nullopt);
    send_response(connection,response);
    // Consume a small already-sent body so closing does not reset the response on Windows.
    // Never drain an attacker-controlled large body or wait for a full normal timeout.
    try {
        const auto size = body_size(request.headers,8192);
        connection.set_deadline(std::chrono::steady_clock::now() + std::chrono::seconds(1));
        (void)connection.read(size);
    } catch (const std::exception&) {}
}
}
HttpResponse json_response(const Json& value, int status) {
    return {status, "application/json; charset=utf-8", value.dump(-1, ' ', false, Json::error_handler_t::replace), {}};
}
void serve_http(const Config& config, const std::string& service, HttpHandler handler, bool internal, HttpPreflight preflight, std::function<bool()> stop_requested) {
    serve_tcp(config, service, [&](Connection& connection) {
        if (!internal && !config.text("tls_certificate").empty()) connection.start_tls_server(config);
        try {
            connection.set_deadline(std::chrono::steady_clock::now() + std::chrono::seconds(config.number("timeout_seconds",30)));
            HttpRequest request;
            request.encrypted = connection.encrypted();
            const auto peer = connection.socket().remote_endpoint().address();
            request.peer_address = peer.to_string();
            request.peer_loopback = peer.is_loopback();
            std::istringstream line(connection.line());
            std::string version, extra;
            if (!(line >> request.method >> request.path >> version) || line >> extra || version != "HTTP/1.1" || request.path.empty() || request.path.front() != '/') throw std::invalid_argument("invalid request line");
            request.headers = read_headers(connection);
            if (!request.headers.contains("host")) throw std::invalid_argument("Host required");
            if (internal) {
                const auto auth = request.headers.find("authorization");
                if (auth == request.headers.end() || !secure_equal(auth->second, "Bearer " + config.token())) {
                    reject_request(connection, request, json_response({{"ok",false},{"error","unauthorized"}}, 401));
                    return;
                }
            }
            if (preflight) {
                if (auto response = preflight(request)) { reject_request(connection,request,*response); return; }
            }
            std::size_t limit = rpc_limit(config);
            if (!internal) {
                limit = (request.path == "/api/send" || request.path == "/api/drafts") ? static_cast<std::size_t>(config.number("max_message_bytes",10485760)) * 2 + 16384 : 16384;
                if (service == "admin" && request.path == "/api/admin/config") limit = 1024 * 1024;
                if (service == "web" && request.path == "/api/setup") limit = 1024 * 1024;
                if (request.method == "GET" || request.method == "DELETE") limit = 0;
            }
            const auto size = body_size(request.headers, limit);
            if (request.headers.contains("expect")) throw std::invalid_argument("Expect unsupported");
            request.body = connection.read(size);
            check_json_depth(request.body);
            connection.set_deadline(std::nullopt);
            send_response(connection, handler(request));
        } catch (const std::invalid_argument&) {
            connection.set_deadline(std::nullopt);
            send_response(connection, json_response({{"ok",false},{"error","invalid request"}}, 400));
        } catch (const Json::exception&) {
            connection.set_deadline(std::nullopt);
            send_response(connection, json_response({{"ok",false},{"error","invalid JSON request"}}, 400));
        } catch (const std::length_error&) {
            connection.set_deadline(std::nullopt);
            send_response(connection, json_response({{"ok",false},{"error","request too large"}}, 413));
        } catch (const std::exception&) {
            connection.set_deadline(std::nullopt);
            send_response(connection, json_response({{"ok",false},{"error","service unavailable"}}, 503));
        }
    }, internal, std::move(stop_requested));
}
void serve_rpc(const Config& config, const std::string& service, std::function<Json(const Json&)> handler) {
    serve_http(config, service, [handler](const HttpRequest& request) {
        if (request.method != "POST" || request.path != "/rpc") return json_response({{"ok",false},{"error","not found"}},404);
        const auto input = wire_decode(Json::parse(request.body));
        if (!input.is_object()) throw std::invalid_argument("object required");
        return json_response(wire_encode(handler(input)));
    });
}
Json rpc(const Config& config, const std::string& service, const Json& request) {
    const int timeout = service == "transfer" ? config.number("smarthost_timeout_seconds",30) + 10 : config.number("timeout_seconds",30);
    Connection connection{std::chrono::seconds(timeout)};
    connection.connect("127.0.0.1", config.port(service));
    const auto body = wire_encode(request).dump();
    connection.write("POST /rpc HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + config.token() + "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n");
    connection.write(body);
    std::istringstream status(connection.line());
    std::string version;
    int code = 0;
    status >> version >> code;
    if (version != "HTTP/1.1" || code != 200) throw std::runtime_error(service + " RPC unavailable (HTTP " + std::to_string(code) + ")");
    const auto headers = read_headers(connection);
    const auto result = wire_decode(Json::parse(connection.read(body_size(headers, rpc_limit(config)))));
    if (!result.is_object() || !result.contains("ok") || !result.at("ok").is_boolean()) throw std::runtime_error("invalid RPC response");
    return result;
}
int service_main(const std::string& name, int argc, char** argv, std::function<void(const Config&)> run) {
    try {
        for (int i = 1; i < argc; ++i) if (std::string_view(argv[i]) == "--help") {
            std::cout << "PostPlus " << name << " 0.1.0\nUsage: postplus-" << name << " --config PATH\n";
            return 0;
        }
        const auto config = Config::load(argc, argv);
        configure_logging(config,name);
        log(name,"service starting");
        run(config);
        log(name,"service stopped");
        return 0;
    } catch (const std::exception& error) {
        log(name, error.what(), "error");
        return 1;
    }
}
}
