#include <postplus/core.hpp>
#include <cstdlib>
#include <stdexcept>

using namespace postplus;
namespace {
std::string reply(Connection& peer, int expected, int alternative = 0) {
    std::string all;
    for (int i = 0; i < 100; ++i) {
        auto line = peer.line(2048);
        if (line.size() < 4 || line[0] < '0' || line[0] > '9' || line[1] < '0' || line[1] > '9' || line[2] < '0' || line[2] > '9') throw std::runtime_error("invalid upstream reply");
        const int code = (line[0]-'0')*100 + (line[1]-'0')*10 + line[2]-'0';
        if (code != expected && code != alternative) throw std::runtime_error("upstream SMTP status " + std::to_string(code));
        all += line + "\n";
        if (line[3] == ' ') return all;
        if (line[3] != '-') throw std::runtime_error("invalid upstream continuation");
    }
    throw std::runtime_error("upstream reply too long");
}
void send(const Config& config, const Json& input) {
    const auto sender = input.at("sender").get<std::string>();
    const auto recipient = input.at("recipient").get<std::string>();
    const auto raw = input.at("raw").get<std::string>();
    if ((!sender.empty() && !valid_address(sender)) || !valid_address(recipient)) throw std::invalid_argument("invalid envelope");
    if (raw.size() > static_cast<std::size_t>(config.number("max_message_bytes", 10485760))) throw std::length_error("message too large");
    const auto host = config.text("smarthost_host");
    if (host.empty()) throw std::runtime_error("smarthost is not configured");
    const auto mode = config.text("smarthost_tls", "starttls");
    if (mode != "starttls" && mode != "implicit" && mode != "none") throw std::invalid_argument("smarthost_tls must be starttls, implicit, or none");
    Connection peer(std::chrono::seconds(config.number("timeout_seconds",30)));
    const auto budget = config.number("smarthost_timeout_seconds",30);
    if (budget < 1 || budget > 300) throw std::invalid_argument("smarthost_timeout_seconds must be 1..300");
    peer.set_deadline(std::chrono::steady_clock::now() + std::chrono::seconds(budget));
    peer.connect(host, config.number("smarthost_port",587));
    if (mode == "none" && !peer.socket().remote_endpoint().address().is_loopback()) throw std::runtime_error("unencrypted smarthost allowed only on loopback");
    if (mode == "implicit") peer.start_tls_client(host);
    reply(peer,220);
    peer.write("EHLO " + config.text("domain","localhost") + "\r\n");
    auto capabilities = lower(reply(peer,250));
    if (mode == "starttls") {
        if (capabilities.find("starttls") == std::string::npos) throw std::runtime_error("upstream requires STARTTLS support");
        peer.write("STARTTLS\r\n"); reply(peer,220);
        peer.start_tls_client(host);
        peer.write("EHLO " + config.text("domain","localhost") + "\r\n");
        capabilities = lower(reply(peer,250));
    }
    const auto username = config.text("smarthost_username");
    if (!username.empty()) {
        if (!peer.encrypted()) throw std::runtime_error("upstream authentication requires TLS");
        const auto env = config.text("smarthost_password_env", "POSTPLUS_SMARTHOST_PASSWORD");
        const char* password = std::getenv(env.c_str());
        if (!password || !*password) throw std::runtime_error("smarthost password not configured");
        if (capabilities.find("auth") == std::string::npos || capabilities.find("plain") == std::string::npos) throw std::runtime_error("upstream lacks AUTH PLAIN");
        std::string credentials(1,'\0'); credentials += username; credentials += '\0'; credentials += password;
        peer.write("AUTH PLAIN " + base64_encode(credentials) + "\r\n"); reply(peer,235);
    }
    peer.write("MAIL FROM:<" + sender + ">\r\n"); reply(peer,250);
    peer.write("RCPT TO:<" + recipient + ">\r\n"); reply(peer,250,251);
    peer.write("DATA\r\n"); reply(peer,354);
    std::string escaped;
    escaped.reserve(raw.size() + 256);
    bool beginning = true;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        const char c = raw[i];
        if (beginning && c == '.') escaped += '.';
        if (c == '\n') {
            if (i == 0 || raw[i-1] != '\r') escaped += '\r';
            escaped += '\n'; beginning = true;
        } else { escaped += c; beginning = false; }
    }
    if (!escaped.ends_with("\r\n")) escaped += "\r\n";
    peer.write(escaped); peer.write(".\r\n"); reply(peer,250);
    // Return acceptance immediately. Closing the connection also ends the session;
    // waiting for QUIT would introduce a failure window after final acceptance.
}
}
int main(int argc, char** argv) {
    return service_main("transfer",argc,argv,[](const Config& config) {
        serve_rpc(config,"transfer",[&](const Json& input) -> Json {
            if (input.value("op","") != "send") return {{"ok",false},{"error","unknown operation"}};
            try { send(config,input); return {{"ok",true}}; }
            catch (const std::exception& error) { return {{"ok",false},{"error",error.what()}}; }
        });
    });
}
