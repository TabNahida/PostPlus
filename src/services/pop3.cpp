#include "postplus/core.hpp"
#include <algorithm>
#include <charconv>
#include <mutex>
#include <set>
#include <sstream>

using namespace postplus;
namespace {
// Both POP3 listeners share one maildrop lease. Deferred DELE changes belong
// only to the successful authorization transaction and disappear on disconnect.
class MaildropLease {
    static std::mutex mutex_;
    static std::set<std::string> owners_;
    std::string owner_;
public:
    bool acquire(const std::string& username) {
        std::lock_guard guard(mutex_);
        if (!owner_.empty() || !owners_.insert(username).second) return false;
        owner_ = username; return true;
    }
    void release() {
        std::lock_guard guard(mutex_);
        if (!owner_.empty()) owners_.erase(owner_);
        owner_.clear();
    }
    ~MaildropLease() { release(); }
};
std::mutex MaildropLease::mutex_;
std::set<std::string> MaildropLease::owners_;

bool number(std::string_view token, std::size_t& value) {
    if (token.empty()) return false;
    auto [p, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
    return ec == std::errc{} && p == token.data() + token.size();
}
std::string multiline(std::string_view raw) {
    std::string out; out.reserve(raw.size() + 16); bool start = true;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        char ch = raw[i];
        if (ch == '\r' && i + 1 < raw.size() && raw[i + 1] == '\n') continue;
        if (ch == '\n') { out += "\r\n"; start = true; continue; }
        if (start && ch == '.') out += '.';
        out += ch; start = false;
    }
    if (!start) out += "\r\n";
    out += ".\r\n"; return out;
}
void pop3(Connection& c, const Config& cfg) {
    std::string candidate, user, credential_version;
    const auto peer_ip = c.socket().remote_endpoint().address().to_string();
    unsigned auth_failures = 0;
    const auto auth_limit = static_cast<unsigned>(std::clamp(cfg.number("max_auth_attempts", 5), 1, 20));
    std::vector<Json> messages;
    std::set<std::size_t> deleted;
    MaildropLease lease;
    auto allowed = [&] { return c.encrypted() || (cfg.flag("allow_insecure_auth") && c.socket().remote_endpoint().address().is_loopback()); };
    auto tls = [&] { return !cfg.text("tls_certificate").empty() && !cfg.text("tls_private_key").empty(); };
    auto auth_failure = [&](const char* message) {
        candidate.clear();
        if (++auth_failures >= auth_limit) { c.write("-ERR [LOGIN-DELAY] Too many failed authentication attempts\r\n"); return true; }
        c.write(message); return false;
    };
    auto banned = [&](const Json& result) {
        const auto code = result.value("code", "");
        if (code != "ip_banned" && code != "rate_limit") return false;
        c.write(result.value("permanent", false) ? "-ERR [LOGIN-DELAY] IP address blocked; contact administrator\r\n" :
                                                  "-ERR [LOGIN-DELAY] Too many authentication attempts; try again later\r\n"); return true;
    };
    auto malformed_auth = [&](const std::string& username = "") {
        return banned(rpc(cfg, "auth", {{"op", "security_failure"}, {"peer_ip", peer_ip}, {"protocol", "pop3"}, {"username", username}, {"reason", "malformed_auth"}}));
    };
    auto login = [&](std::string username, const std::string& password) {
        username = lower(std::move(username)); candidate.clear();
        const auto result = rpc(cfg, "auth", {{"op", "verify"}, {"username", username}, {"password", password}, {"session", true}, {"peer_ip", peer_ip}, {"protocol", "pop3"}});
        if (banned(result)) return true;
        if (!result.value("ok", false)) return auth_failure("-ERR [AUTH] Invalid credentials\r\n");
        username = result.value("username", username);
        if (!lease.acquire(username)) { c.write("-ERR [IN-USE] Mailbox is locked by another POP3 session\r\n"); return false; }
        try {
            auto mailbox = rpc(cfg, "storage", {{"op", "list"}, {"username", username}, {"folder", "INBOX"}, {"include_pop3_size", true}});
            if (!mailbox.value("ok", false)) { lease.release(); c.write("-ERR [SYS/TEMP] Mailbox unavailable\r\n"); return false; }
            messages = mailbox.at("messages").get<std::vector<Json>>();
            credential_version = result.at("credential_version").get<std::string>(); user = std::move(username);
            log("pop3","Mailbox opened for "+user+": "+std::to_string(messages.size())+" messages","debug");
        } catch (...) { lease.release(); throw; }
        c.write("+OK Mailbox ready\r\n"); return false;
    };
    c.write("+OK PostPlus POP3 ready\r\n");
    for (;;) {
        // RFC 1939 permits a client to remain idle for at least ten minutes.
        // The short connection deadline still bounds a command once its first
        // bytes arrive, and the poll observes supervisor shutdown promptly.
        const auto idle_deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
        while (!c.wait_readable(std::chrono::seconds(1))) {
            if (std::chrono::steady_clock::now() >= idle_deadline) { c.write("-ERR [SYS/TEMP] Inactivity timeout\r\n"); return; }
        }
        auto line = c.line(8192); auto space = line.find_first_of(" \t");
        auto cmd = lower(line.substr(0, space));
        auto arg = space == std::string::npos ? "" : line.substr(space + 1);
        try {
            if (!user.empty()) {
                const auto valid = rpc(cfg, "auth", {{"op", "session_check"}, {"username", user}, {"credential_version", credential_version}});
                if (!valid.value("ok", false) || !valid.value("valid", false)) { c.write("-ERR [AUTH] Account credentials changed\r\n"); return; }
            }
            if ((cmd == "quit" || cmd == "capa" || cmd == "noop" || cmd == "rset" || cmd == "stat") && !trim(arg).empty()) {
                c.write("-ERR Unexpected command arguments\r\n"); continue;
            }
            if (cmd == "quit") {
                if (!user.empty() && !deleted.empty()) {
                    Json ids = Json::array(), expected_uids = Json::object();
                    for (auto index : deleted) {
                        ids.push_back(messages[index].at("id"));
                        expected_uids[messages[index].at("id").get<std::string>()] = messages[index].at("uid");
                    }
                    auto result = rpc(cfg, "storage", {{"op", "delete"}, {"username", user}, {"ids", ids},
                        {"permanent", true}, {"folder", "INBOX"}, {"expected_uids", expected_uids}});
                    if (!result.value("ok", false)) { c.write("-ERR Unable to commit deletions\r\n"); return; }
                }
                lease.release(); c.write("+OK Goodbye\r\n"); return;
            }
            if (cmd == "capa") {
                std::string capabilities = "+OK Capability list follows\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\n";
                if (user.empty() && allowed()) capabilities += "USER\r\nSASL PLAIN LOGIN\r\n";
                if (user.empty() && !c.encrypted() && tls()) capabilities += "STLS\r\n";
                c.write(capabilities + ".\r\n"); continue;
            }
            if (cmd == "stls") {
                if (!arg.empty() || !user.empty() || c.encrypted() || !tls()) { c.write("-ERR STLS unavailable\r\n"); continue; }
                c.write("+OK Begin TLS negotiation\r\n");
                try { c.start_tls_server(cfg); } catch (...) { return; }
                candidate.clear(); continue;
            }
            if (user.empty()) {
                if (cmd != "user" && cmd != "pass" && cmd != "auth") { c.write("-ERR Authenticate first\r\n"); continue; }
                if (!allowed()) { c.write("-ERR [AUTH] TLS required\r\n"); continue; }
                if (cmd == "auth") {
                    candidate.clear();
                    if (trim(arg).empty()) { c.write("+OK Supported authentication mechanisms\r\nPLAIN\r\nLOGIN\r\n.\r\n"); continue; }
                    std::istringstream arguments(arg); std::string mechanism, initial, extra;
                    arguments >> mechanism >> initial >> extra; mechanism = lower(mechanism);
                    if (!extra.empty()) { if (malformed_auth() || auth_failure("-ERR Invalid authentication arguments\r\n")) return; continue; }
                    if (mechanism != "plain" && mechanism != "login") { c.write("-ERR Unsupported authentication mechanism\r\n"); continue; }
                    std::string username, password;
                    try {
                        if (initial.empty()) { c.write(mechanism == "plain" ? "+ \r\n" : "+ VXNlcm5hbWU6\r\n"); initial = c.line(8192); }
                        if (initial == "*") { c.write("-ERR Authentication canceled\r\n"); continue; }
                        const auto decoded = base64_decode(initial == "=" ? "" : initial);
                        if (mechanism == "plain") {
                            const auto first = decoded.find('\0');
                            const auto second = first == decoded.npos ? first : decoded.find('\0', first + 1);
                            if (first == decoded.npos || second == decoded.npos || decoded.find('\0', second + 1) != decoded.npos)
                                throw std::invalid_argument("Invalid PLAIN data");
                            username = lower(decoded.substr(first + 1, second - first - 1)); password = decoded.substr(second + 1);
                            if (first && lower(decoded.substr(0, first)) != username) throw std::invalid_argument("Authorization identity mismatch");
                        } else {
                            username = decoded;
                            c.write("+ UGFzc3dvcmQ6\r\n"); initial = c.line(8192);
                            if (initial == "*") { c.write("-ERR Authentication canceled\r\n"); continue; }
                            password = base64_decode(initial == "=" ? "" : initial);
                        }
                    } catch (const std::invalid_argument&) { if (malformed_auth(username) || auth_failure("-ERR Invalid authentication encoding\r\n")) return; continue; }
                    if (login(std::move(username), password)) return;
                    continue;
                }
                if (cmd == "user") {
                    candidate = lower(trim(arg));
                    if (!valid_address(candidate)) { if (malformed_auth(candidate) || auth_failure("-ERR Invalid username\r\n")) return; }
                    else c.write("+OK Send password\r\n");
                    continue;
                }
                if (candidate.empty()) { c.write("-ERR Send USER first\r\n"); continue; }
                if (login(candidate, arg)) return;
                continue;
            }
            if (cmd == "noop") { c.write("+OK\r\n"); continue; }
            if (cmd == "rset") { deleted.clear(); c.write("+OK Deletions reset\r\n"); continue; }
            if (cmd == "stat") {
                std::uint64_t size = 0; std::size_t count = 0;
                for (std::size_t i = 0; i < messages.size(); ++i) if (!deleted.contains(i)) { ++count; size += messages[i].at("pop3_size").get<std::uint64_t>(); }
                c.write("+OK " + std::to_string(count) + " " + std::to_string(size) + "\r\n"); continue;
            }
            if ((cmd == "list" || cmd == "uidl") && arg.empty()) {
                c.write("+OK Listing follows\r\n");
                for (std::size_t i = 0; i < messages.size(); ++i) if (!deleted.contains(i)) {
                    auto value = messages[i].at(cmd == "list" ? "pop3_size" : "uid").get<std::uint64_t>();
                    c.write(std::to_string(i + 1) + " " + std::to_string(value) + "\r\n");
                }
                c.write(".\r\n"); continue;
            }
            if (cmd != "retr" && cmd != "top" && cmd != "dele" && cmd != "list" && cmd != "uidl") { c.write("-ERR Unsupported command\r\n"); continue; }
            std::istringstream args(arg); std::string index_token, lines_token, extra;
            args >> index_token; if (cmd == "top") args >> lines_token;
            args >> extra;
            std::size_t index = 0, body_lines = 0;
            if (!extra.empty() || !number(index_token, index) || index == 0 || index > messages.size() || deleted.contains(index - 1) ||
                (cmd == "top" && !number(lines_token, body_lines))) { c.write("-ERR Invalid message or arguments\r\n"); continue; }
            --index;
            if (cmd == "dele") { deleted.insert(index); c.write("+OK Message marked for deletion\r\n"); continue; }
            if (cmd == "list" || cmd == "uidl") {
                c.write("+OK " + std::to_string(index + 1) + " " + std::to_string(messages[index].at(cmd == "list" ? "pop3_size" : "uid").get<std::uint64_t>()) + "\r\n"); continue;
            }
            auto result = rpc(cfg, "storage", {{"op", "get"}, {"username", user}, {"id", messages[index].at("id")},
                {"folder", "INBOX"}, {"uid", messages[index].at("uid")}});
            if (!result.value("ok", false)) { c.write("-ERR Message unavailable\r\n"); continue; }
            auto raw = result.at("raw").get<std::string>();
            if (cmd == "top") {
                auto boundary = raw.find("\r\n\r\n"); std::size_t delimiter = 4;
                if (boundary == std::string::npos) { boundary = raw.find("\n\n"); delimiter = 2; }
                if (boundary != std::string::npos) {
                    std::size_t end = boundary + delimiter;
                    for (std::size_t n = 0; n < body_lines && end < raw.size(); ++n) {
                        auto next = raw.find('\n', end); end = next == std::string::npos ? raw.size() : next + 1;
                    }
                    raw.resize(end);
                }
            }
            c.write("+OK Message follows\r\n"); c.write(multiline(raw));
        } catch (const std::exception&) { c.write("-ERR Temporary service failure\r\n"); if (cmd == "quit") return; }
    }
}
}
int main(int argc, char** argv) {
    return service_main("pop3", argc, argv, [](const Config& cfg) { serve_tcp_listeners(cfg, "pop3", [&](Connection& c, const TcpListener&) { pop3(c, cfg); }); });
}
