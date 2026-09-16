#include "postplus/core.hpp"
#include <algorithm>
#include <charconv>
#include <set>
#include <sstream>

using namespace postplus;
namespace {
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
    std::string candidate, user;
    unsigned auth_failures = 0;
    const auto auth_limit = static_cast<unsigned>(std::clamp(cfg.number("max_auth_attempts", 5), 1, 20));
    std::vector<Json> messages;
    std::set<std::size_t> deleted;
    auto allowed = [&] { return c.encrypted() || (cfg.flag("allow_insecure_auth") && c.socket().remote_endpoint().address().is_loopback()); };
    auto tls = [&] { return !cfg.text("tls_certificate").empty() && !cfg.text("tls_private_key").empty(); };
    c.write("+OK PostPlus POP3 ready\r\n");
    for (;;) {
        auto line = c.line(8192); auto space = line.find(' ');
        auto cmd = lower(line.substr(0, space));
        auto arg = space == std::string::npos ? "" : line.substr(space + 1);
        try {
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
                c.write("+OK Goodbye\r\n"); return;
            }
            if (cmd == "capa") {
                c.write("+OK Capability list follows\r\nTOP\r\nUIDL\r\nRESP-CODES\r\n");
                if (user.empty() && allowed()) c.write("USER\r\n");
                if (user.empty() && !c.encrypted() && tls()) c.write("STLS\r\n");
                c.write(".\r\n"); continue;
            }
            if (cmd == "stls") {
                if (!arg.empty() || !user.empty() || c.encrypted() || !tls()) { c.write("-ERR STLS unavailable\r\n"); continue; }
                c.write("+OK Begin TLS negotiation\r\n");
                try { c.start_tls_server(cfg); } catch (...) { return; }
                candidate.clear(); continue;
            }
            if (user.empty()) {
                if (cmd != "user" && cmd != "pass") { c.write("-ERR Authenticate first\r\n"); continue; }
                if (!allowed()) { c.write("-ERR [AUTH] TLS required\r\n"); continue; }
                if (cmd == "user") {
                    candidate = lower(trim(arg));
                    if (!valid_address(candidate)) { candidate.clear(); c.write("-ERR Invalid username\r\n"); }
                    else c.write("+OK Send password\r\n");
                    continue;
                }
                if (candidate.empty()) { c.write("-ERR Send USER first\r\n"); continue; }
                auto result = rpc(cfg, "auth", {{"op", "verify"}, {"username", candidate}, {"password", arg}});
                if (!result.value("ok", false)) {
                    candidate.clear();
                    if (++auth_failures >= auth_limit) { c.write("-ERR [LOGIN-DELAY] Too many failed authentication attempts\r\n"); return; }
                    c.write("-ERR [AUTH] Invalid credentials\r\n"); continue;
                }
                auto mailbox = rpc(cfg, "storage", {{"op", "list"}, {"username", candidate}, {"folder", "INBOX"}});
                if (!mailbox.value("ok", false)) { c.write("-ERR Mailbox unavailable\r\n"); continue; }
                messages = mailbox.at("messages").get<std::vector<Json>>(); user = candidate;
                c.write("+OK Mailbox ready\r\n"); continue;
            }
            if (cmd == "noop") { c.write("+OK\r\n"); continue; }
            if (cmd == "rset") { deleted.clear(); c.write("+OK Deletions reset\r\n"); continue; }
            if (cmd == "stat") {
                std::uint64_t size = 0; std::size_t count = 0;
                for (std::size_t i = 0; i < messages.size(); ++i) if (!deleted.contains(i)) { ++count; size += messages[i].at("size").get<std::uint64_t>(); }
                c.write("+OK " + std::to_string(count) + " " + std::to_string(size) + "\r\n"); continue;
            }
            if ((cmd == "list" || cmd == "uidl") && arg.empty()) {
                c.write("+OK Listing follows\r\n");
                for (std::size_t i = 0; i < messages.size(); ++i) if (!deleted.contains(i)) {
                    auto value = messages[i].at(cmd == "list" ? "size" : "uid").get<std::uint64_t>();
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
                c.write("+OK " + std::to_string(index + 1) + " " + std::to_string(messages[index].at(cmd == "list" ? "size" : "uid").get<std::uint64_t>()) + "\r\n"); continue;
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
    return service_main("pop3", argc, argv, [](const Config& cfg) { serve_tcp(cfg, "pop3", [&](Connection& c) { pop3(c, cfg); }); });
}
