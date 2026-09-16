#include "postplus/core.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

using namespace postplus;
namespace {
bool may_auth(Connection& c, const Config& cfg) {
    return c.encrypted() || (cfg.flag("allow_insecure_auth") && c.socket().remote_endpoint().address().is_loopback());
}
bool tls_available(const Config& cfg) {
    return !cfg.text("tls_certificate").empty() && !cfg.text("tls_private_key").empty();
}
std::pair<std::string, std::string> command(const std::string& line) {
    auto p = line.find(' ');
    return {lower(line.substr(0, p)), p == std::string::npos ? "" : trim(line.substr(p + 1))};
}
bool path(const std::string& arg, const std::string& prefix, std::string& address, std::string& suffix) {
    if (lower(arg.substr(0, prefix.size())) != prefix) return false;
    auto rest = trim(arg.substr(prefix.size()));
    if (rest.empty() || rest.front() != '<') return false;
    auto end = rest.find('>');
    if (end == std::string::npos) return false;
    address = lower(rest.substr(1, end - 1)); suffix = trim(rest.substr(end + 1));
    return address.empty() || valid_address(address);
}
void smtp(Connection& c, const Config& cfg, std::chrono::seconds data_timeout) {
    const auto maximum = static_cast<std::size_t>(cfg.number("max_message_bytes", 10485760));
    bool greeted = false, extended = false, have_sender = false;
    unsigned auth_failures = 0;
    const auto auth_limit = static_cast<unsigned>(std::clamp(cfg.number("max_auth_attempts", 5), 1, 20));
    const auto recipient_limit = static_cast<std::size_t>(std::clamp(cfg.number("max_recipients", 100), 1, 100));
    std::string username, sender;
    std::vector<std::string> recipients;
    auto reset = [&] { have_sender = false; sender.clear(); recipients.clear(); };
    auto reply = [&](std::string_view s) { c.write(s); };
    auto auth_failure = [&](std::string_view response) {
        if (++auth_failures >= auth_limit) { reply("421 4.7.0 Too many failed authentication attempts\r\n"); return true; }
        reply(response); return false;
    };
    reply("220 " + cfg.text("domain", "localhost") + " PostPlus ESMTP ready\r\n");
    for (;;) {
        // RFC 4954 permits larger AUTH command lines than ordinary SMTP commands.
        auto command_line = c.line(12286);
        auto [verb, arg] = command(command_line);
        // A new MAIL command abandons the previous transaction even if its new arguments fail.
        if (verb == "mail") reset();
        if (verb != "auth" && command_line.size() > 510) { reply("500 5.5.2 Command line too long\r\n"); continue; }
        try {
            if (verb == "quit") { reply("221 2.0.0 Goodbye\r\n"); return; }
            if (verb == "noop") { reply("250 2.0.0 OK\r\n"); continue; }
            if (verb == "rset") { reset(); reply("250 2.0.0 Reset\r\n"); continue; }
            if (verb == "ehlo" || verb == "helo") {
                if (arg.empty()) { reply("501 5.5.2 Greeting requires a hostname\r\n"); continue; }
                reset(); greeted = true; extended = verb == "ehlo";
                if (!extended) { reply("250 " + cfg.text("domain", "localhost") + "\r\n"); continue; }
                reply("250-" + cfg.text("domain", "localhost") + "\r\n250-SIZE " + std::to_string(maximum) + "\r\n");
                if (!c.encrypted() && tls_available(cfg)) reply("250-STARTTLS\r\n");
                if (may_auth(c, cfg)) reply("250-AUTH PLAIN LOGIN\r\n");
                reply("250 HELP\r\n"); continue;
            }
            if (verb == "help") { reply("214 Supported: EHLO HELO STARTTLS AUTH MAIL RCPT DATA RSET NOOP QUIT HELP\r\n"); continue; }
            if (!greeted) { reply("503 5.5.1 Send EHLO or HELO first\r\n"); continue; }
            if (verb == "starttls") {
                if (!arg.empty()) { reply("501 5.5.2 No arguments allowed\r\n"); continue; }
                if (!extended || c.encrypted() || !tls_available(cfg) || have_sender) { reply("503 5.5.1 STARTTLS unavailable in this state\r\n"); continue; }
                reply("220 2.0.0 Begin TLS negotiation\r\n");
                // A failed TLS handshake is fatal; never resume plaintext command parsing.
                try { c.start_tls_server(cfg); } catch (...) { return; }
                reset(); username.clear(); greeted = false; extended = false; continue;
            }
            if (verb == "auth") {
                if (!extended || have_sender || !username.empty()) { reply("503 5.5.1 AUTH unavailable in this state\r\n"); continue; }
                if (!may_auth(c, cfg)) { reply("538 5.7.11 Encryption required\r\n"); continue; }
                auto [mechanism, initial] = command(arg);
                std::string user, password;
                try {
                    if (mechanism == "plain") {
                        if (initial.empty()) { reply("334 \r\n"); initial = c.line(8192); }
                        if (initial == "*") { reply("501 5.7.0 Authentication canceled\r\n"); continue; }
                        auto decoded = base64_decode(initial == "=" ? "" : initial);
                        auto a = decoded.find('\0');
                        auto b = a == std::string::npos ? a : decoded.find('\0', a + 1);
                        if (a == std::string::npos || b == std::string::npos || decoded.find('\0', b + 1) != std::string::npos) throw std::runtime_error("invalid PLAIN");
                        user = lower(decoded.substr(a + 1, b - a - 1)); password = decoded.substr(b + 1);
                        if (a && lower(decoded.substr(0, a)) != user) throw std::runtime_error("authorization identity mismatch");
                    } else if (mechanism == "login") {
                        if (initial.empty()) { reply("334 VXNlcm5hbWU6\r\n"); initial = c.line(8192); }
                        if (initial == "*") { reply("501 5.7.0 Authentication canceled\r\n"); continue; }
                        user = lower(base64_decode(initial)); reply("334 UGFzc3dvcmQ6\r\n");
                        initial = c.line(8192);
                        if (initial == "*") { reply("501 5.7.0 Authentication canceled\r\n"); continue; }
                        password = base64_decode(initial);
                    } else { reply("504 5.5.4 Unsupported authentication mechanism\r\n"); continue; }
                } catch (const std::exception&) { if (auth_failure("501 5.5.2 Invalid authentication encoding\r\n")) return; continue; }
                auto result = rpc(cfg, "auth", {{"op", "verify"}, {"username", user}, {"password", password}});
                if (!result.value("ok", false)) { if (auth_failure("535 5.7.8 Invalid credentials\r\n")) return; continue; }
                username = result.value("username", user); reply("235 2.7.0 Authentication successful\r\n"); continue;
            }
            if (verb == "mail") {
                std::string suffix, proposed;
                if (!path(arg, "from:", proposed, suffix)) { reply("501 5.1.7 Invalid reverse path\r\n"); continue; }
                if (!suffix.empty()) {
                    if (!extended || lower(suffix.substr(0, 5)) != "size=" || suffix.size() <= 5 ||
                        !std::all_of(suffix.begin() + 5, suffix.end(), [](unsigned char ch) { return std::isdigit(ch); })) {
                        reply("555 5.5.4 Unsupported MAIL parameter\r\n"); continue;
                    }
                    try { if (std::stoull(suffix.substr(5)) > maximum) { reply("552 5.3.4 Message exceeds size limit\r\n"); continue; } }
                    catch (...) { reply("552 5.3.4 Message exceeds size limit\r\n"); continue; }
                }
                reset(); sender = proposed; have_sender = true; reply("250 2.1.0 Sender accepted\r\n"); continue;
            }
            if (verb == "rcpt") {
                if (!have_sender) { reply("503 5.5.1 Send MAIL first\r\n"); continue; }
                std::string recipient, suffix;
                if (!path(arg, "to:", recipient, suffix) || recipient.empty()) { reply("501 5.1.3 Invalid recipient\r\n"); continue; }
                if (!suffix.empty()) { reply("555 5.5.4 Unsupported RCPT parameter\r\n"); continue; }
                if (recipients.size() >= recipient_limit) { reply("452 4.5.3 Too many recipients\r\n"); continue; }
                bool local = recipient.substr(recipient.rfind('@') + 1) == lower(cfg.text("domain", "localhost"));
                if (local) {
                    auto result = rpc(cfg, "auth", {{"op", "exists"}, {"username", recipient}});
                    if (!result.value("ok", false)) { reply("451 4.3.0 Recipient service unavailable\r\n"); continue; }
                    if (!result.value("exists", false)) { reply("550 5.1.1 Unknown recipient\r\n"); continue; }
                } else if (username.empty() || cfg.text("smarthost_host").empty()) { reply("550 5.7.1 Relay denied\r\n"); continue; }
                if (std::find(recipients.begin(), recipients.end(), recipient) == recipients.end()) recipients.push_back(recipient);
                reply("250 2.1.5 Recipient accepted\r\n"); continue;
            }
            if (verb == "data") {
                if (!arg.empty()) { reply("501 5.5.2 No DATA arguments allowed\r\n"); continue; }
                if (!have_sender || recipients.empty()) { reply("503 5.5.1 Send MAIL and RCPT first\r\n"); continue; }
                const auto data_deadline = std::chrono::steady_clock::now() + data_timeout;
                c.set_deadline(data_deadline);
                reply("354 End with <CRLF>.<CRLF>\r\n");
                std::string raw; bool too_large = false;
                for (;;) {
                    std::string line;
                    // A deadline covers all DATA lines, including already-buffered lines.
                    // Framing errors or expiry close the connection without queuing partial mail.
                    try {
                        if (std::chrono::steady_clock::now() >= data_deadline) return;
                        line = c.line(999);
                        if (std::chrono::steady_clock::now() >= data_deadline) return;
                    } catch (...) { return; }
                    if (line == ".") break;
                    if (!line.empty() && line.front() == '.') line.erase(0, 1);
                    if (line.size() > 998) too_large = true;
                    if (line.size() + 2 > maximum - std::min(maximum, raw.size())) too_large = true;
                    if (!too_large) { raw += line; raw += "\r\n"; }
                }
                c.set_deadline(std::nullopt);
                if (too_large) { reset(); reply("552 5.3.4 Message exceeds size limit\r\n"); continue; }
                Json submission = {{"op", "enqueue"}, {"sender", sender}, {"recipients", recipients}, {"raw", raw}};
                if (!username.empty()) submission["sent_username"] = username;
                auto result = rpc(cfg, "storage", submission);
                reset();
                if (result.value("ok", false)) reply("250 2.0.0 Message durably queued\r\n");
                else reply("451 4.3.0 Unable to queue message\r\n");
                continue;
            }
            reply("502 5.5.1 Command not implemented\r\n");
        } catch (const std::exception&) { reset(); reply("451 4.3.0 Temporary service failure\r\n"); }
    }
}
}
int main(int argc, char** argv) {
    return service_main("smtp", argc, argv, [](const Config& cfg) {
        const auto value = cfg.values.value("smtp_data_timeout_seconds", Json(120));
        if (!value.is_number_integer() || value.get<std::int64_t>() < 1 || value.get<std::int64_t>() > 3600)
            throw std::invalid_argument("smtp_data_timeout_seconds must be an integer from 1 to 3600");
        const auto timeout = std::chrono::seconds(value.get<std::int64_t>());
        serve_tcp(cfg, "smtp", [&](Connection& c) { smtp(c, cfg, timeout); });
    });
}
