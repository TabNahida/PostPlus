#pragma once
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace postplus {
using Json = nlohmann::json;
using tcp = asio::ip::tcp;
struct Config {
    Json values;
    std::filesystem::path source;
    static Config load(int argc, char** argv);
    static Config from_file(const std::filesystem::path& path);
    std::string text(const std::string& key, const std::string& fallback = "") const;
    int number(const std::string& key, int fallback) const;
    bool flag(const std::string& key, bool fallback = false) const;
    int port(const std::string& service) const;
    std::string token() const;
    std::string relay_password() const;
};
std::string lower(std::string text);
std::string trim(std::string text);
bool valid_address(std::string_view value);
std::string random_hex(std::size_t bytes = 16);
bool secure_equal(std::string_view a, std::string_view b);
std::string base64_encode(std::string_view input);
std::string base64_decode(std::string_view input);
void configure_logging(const Config& config, const std::string& service);
void log(const std::string& service, const std::string& message, const std::string& level = "info");
Json read_logs(const Config& config, const std::string& service = "", const std::string& level = "", std::size_t limit = 100);

// Each connection owns its executor. Operations enforce a per-operation deadline.
class Connection {
public:
    explicit Connection(std::chrono::seconds timeout = std::chrono::seconds(30));
    ~Connection();
    tcp::socket& socket();
    void connect(const std::string& host, int port);
    std::string line(std::size_t limit = 8192); // strips CRLF; requires CRLF
    std::string read(std::size_t count);
    void write(std::string_view bytes);
    void start_tls_server(const Config& config);
    void start_tls_client(const std::string& hostname);
    bool encrypted() const;
    void set_deadline(std::optional<std::chrono::steady_clock::time_point> deadline);
    void request_stop(); // Thread safe; active operation exits within its deadline.
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
using Session = std::function<void(Connection&)>;
void serve_tcp(const Config& config, const std::string& service, Session handler, bool internal = false,
               std::function<bool()> stop_requested = {});

struct HttpRequest {
    std::string method, path, body;
    std::map<std::string, std::string> headers;
    bool encrypted = false;
    bool peer_loopback = false;
    std::string peer_address;
};
struct HttpResponse {
    int status = 200;
    std::string content_type = "application/json; charset=utf-8";
    std::string body;
    std::map<std::string, std::string> headers;
};
HttpResponse json_response(const Json& value, int status = 200);
using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;
using HttpPreflight = std::function<std::optional<HttpResponse>(const HttpRequest&)>;
void serve_http(const Config& config, const std::string& service, HttpHandler handler, bool internal = true,
                HttpPreflight preflight = {}, std::function<bool()> stop_requested = {});
void serve_rpc(const Config& config, const std::string& service, std::function<Json(const Json&)> handler);
Json rpc(const Config& config, const std::string& service, const Json& request);
int service_main(const std::string& name, int argc, char** argv, std::function<void(const Config&)> run);
}
