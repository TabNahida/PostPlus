#include <postplus/core.hpp>
#include <postplus/mime.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cctype>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>

namespace postplus {
namespace {
struct Rule { std::string term; double weight; };
enum class ScanResult { clean, infected };

class Filter {
public:
    explicit Filter(const Config& config)
        : max_bytes_(config.number("max_message_bytes", 10485760)),
          clamav_host_(config.text("clamav_host")), clamav_port_(config.number("clamav_port", 3310)),
          clamav_timeout_(config.number("clamav_timeout_seconds", 15)),
          spam_threshold_(config.number("spam_threshold", 5)),
          rspamd_enabled_(config.flag("rspamd_enabled")),
          rspamd_host_(config.text("rspamd_host", "127.0.0.1")),
          rspamd_port_(config.number("rspamd_port", 11333)),
          rspamd_timeout_(config.number("rspamd_timeout_seconds", 5)) {
        if (max_bytes_ < 1 || max_bytes_ > 100 * 1024 * 1024 || clamav_port_ < 1 || clamav_port_ > 65535 ||
            clamav_timeout_ < 1 || clamav_timeout_ > 120 || spam_threshold_ < 1 || spam_threshold_ > 1000)
            throw std::invalid_argument("invalid filter settings");
        if (clamav_host_.size() > 253 || clamav_host_.find_first_of("\r\n\0", 0, 3) != std::string::npos)
            throw std::invalid_argument("invalid ClamAV host");
        std::error_code address_error;
        const auto scanner_address = asio::ip::make_address(rspamd_host_, address_error);
        if (address_error || !scanner_address.is_loopback() || rspamd_port_ < 1 || rspamd_port_ > 65535 ||
            rspamd_timeout_ < 1 || rspamd_timeout_ > 30)
            throw std::invalid_argument("Rspamd must use a loopback IP and valid port/timeout");
        auto policies = [&](const char* key, std::set<std::string>& destination) {
            if (!config.values.contains(key)) return;
            const auto& entries = config.values.at(key);
            if (!entries.is_array() || entries.size() > 1000) throw std::invalid_argument("invalid sender policy");
            for (const auto& entry : entries) {
                if (!entry.is_string()) throw std::invalid_argument("sender policies must be strings");
                auto value = lower(trim(entry.get<std::string>()));
                if (value.starts_with('@')) value.erase(0, 1);
                if (!(value.find('@') == std::string::npos ? valid_address("policy@" + value) : valid_address(value)))
                    throw std::invalid_argument("sender policies need an email address or domain");
                destination.insert(std::move(value));
            }
        };
        policies("spam_allow_senders", allow_);
        policies("spam_block_senders", block_);
        if (config.values.contains("blocked_terms")) {
            const auto& terms = config.values.at("blocked_terms");
            if (!terms.is_array() || terms.size() > 1000) throw std::invalid_argument("invalid blocked_terms");
            for (const auto& term : terms) {
                if (!term.is_string()) throw std::invalid_argument("blocked_terms entries must be strings");
                auto value = lower(trim(term.get<std::string>()));
                if (value.empty() || value.size() > 256) throw std::invalid_argument("invalid blocked term length");
                blocked_.push_back(std::move(value));
            }
        }
        rules_ = {{"lottery winner", 3}, {"urgent money transfer", 3}, {"free money", 2}, {"viagra", 2}, {"click here", 1}};
        if (config.values.contains("spam_rules")) {
            const auto& rules = config.values.at("spam_rules");
            if (!rules.is_array() || rules.size() > 1000) throw std::invalid_argument("invalid spam_rules");
            rules_.clear();
            for (const auto& rule : rules) {
                if (!rule.is_object() || !rule.contains("term") || !rule.at("term").is_string() ||
                    !rule.contains("weight") || !rule.at("weight").is_number())
                    throw std::invalid_argument("spam_rules need term and weight");
                auto term = lower(trim(rule.at("term").get<std::string>()));
                const auto weight = rule.at("weight").get<double>();
                if (term.empty() || term.size() > 256 || !std::isfinite(weight) || weight <= 0 || weight > 1000)
                    throw std::invalid_argument("invalid spam rule");
                rules_.push_back({std::move(term), weight});
            }
        }
    }

    Json handle(const Json& request) const {
        if (!request.is_object() || request.value("op", std::string{}) != "scan")
            return {{"ok", false}, {"error", "unknown filter operation"}};
        if (!request.contains("raw") || !request.at("raw").is_string())
            throw std::invalid_argument("raw must be a string");
        const auto& raw = request.at("raw").get_ref<const std::string&>();
        if (raw.empty() || raw.size() > static_cast<std::size_t>(max_bytes_) || raw.find('\0') != std::string::npos)
            throw std::invalid_argument("invalid message length or content");
        if (request.contains("inbound") && !request.at("inbound").is_boolean())
            throw std::invalid_argument("inbound must be a boolean");
        const bool inbound = request.value("inbound", true);
        const auto sender = lower(metadata(request, "sender"));
        if (!sender.empty() && !valid_address(sender)) throw std::invalid_argument("invalid envelope sender");
        mime::Part message;
        try {
            message = mime::parse(raw, mime::Limits{static_cast<std::size_t>(max_bytes_)});
        } catch (const std::exception&) {
            return verdict("reject", "malformed MIME message", 0);
        }
        std::vector<std::string_view> payloads{raw};
        std::string searchable;
        collect(message, payloads, searchable);
        for (const auto payload : payloads) {
            if (payload.find(eicar_) != std::string_view::npos)
                return verdict("reject", "EICAR antivirus test signature detected", 0);
        }
        searchable = lower(std::move(searchable));
        for (const auto& term : blocked_)
            if (searchable.find(term) != std::string::npos)
                return verdict("reject", "configured blocked term detected", 0);
        double score = 0;
        Json reasons = Json::array();
        bool spam = false;
        const bool blocked_sender = inbound && matches(block_, sender);
        const bool allowed_sender = inbound && !blocked_sender && matches(allow_, sender);
        if (inbound && !allowed_sender) {
            if (blocked_sender) {
                score += spam_threshold_;
                reasons.push_back("Envelope sender matches administrator block policy");
                spam = true;
            }
            for (const auto& rule : rules_) {
                if (searchable.find(rule.term) != std::string::npos) {
                    score += rule.weight;
                    if (reasons.size() < 128) reasons.push_back("Weighted term: " + reason_term(rule.term));
                }
            }
            heuristic(message, score, reasons);
            if (reasons.size() > 128) reasons.erase(reasons.begin() + 128, reasons.end());
            if (rspamd_enabled_) {
                try {
                    const auto external = scan_rspamd(raw, request);
                    const auto action = external.value("action", std::string{});
                    if (action == "soft reject" || action == "greylist")
                        return deferred("Rspamd requested a temporary retry", score, reasons);
                    if (action != "no action" && action != "reject" && action != "add header" && action != "rewrite subject" &&
                        action != "discard" && action != "quarantine")
                        throw std::runtime_error("unsupported Rspamd action");
                    const auto external_score = external.at("score").get<double>();
                    if (!std::isfinite(external_score) || std::abs(external_score) > 1000)
                        throw std::runtime_error("invalid Rspamd score");
                    score += external_score;
                    spam = spam || action != "no action";
                    if (external.contains("symbols") && external.at("symbols").is_object()) {
                        for (const auto& symbol : external.at("symbols").items()) {
                            if (reasons.size() >= 128) break;
                            const auto& name = symbol.key();
                            if (name.size() <= 96 && !name.empty() &&
                                name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == std::string::npos)
                                reasons.push_back("Rspamd: " + name);
                        }
                    }
                } catch (const std::exception&) {
                    return deferred("Rspamd unavailable or scan incomplete", score, reasons);
                }
            }
            score = std::clamp(score, -1000000.0, 1000000.0);
            spam = spam || score >= spam_threshold_;
        }
        if (!clamav_host_.empty()) {
            // One deadline covers every MIME part, not one full timeout per part.
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(clamav_timeout_);
            try {
                for (const auto payload : payloads) {
                    if (payload.empty()) continue;
                    if (scan_clamav(payload, deadline) == ScanResult::infected)
                        return verdict("reject", "ClamAV detected malware", score);
                }
            } catch (const std::exception&) {
                // Availability errors are retryable. Never report a failed scan
                // as clean, and never permanently quarantine on scanner outages.
                return deferred("ClamAV unavailable or scan incomplete", score, reasons);
            }
        }
        auto result = verdict(spam ? "spam" : "accept", spam ? "Inbound spam policy moved message to Junk" :
            allowed_sender ? "Sender allow policy matched; malware checks passed" :
            inbound ? "Inbound spam and malware checks passed" : "Authenticated submission passed malware checks", score);
        result["spam_reasons"] = std::move(reasons);
        result["inbound"] = inbound;
        result["spam_engine"] = rspamd_enabled_ && inbound && !allowed_sender ? "local+rspamd" : "local";
        return result;
    }
private:
    Json verdict(const char* action, const char* reason, double score) const {
        return {{"ok", true}, {"action", action}, {"reason", reason}, {"spam_score", score},
            {"spam_reasons", Json::array()}, {"antivirus", clamav_host_.empty() ? "eicar-only" : "clamav"}};
    }
    static Json deferred(const char* reason, double score, const Json& reasons) {
        return {{"ok", false}, {"action", "defer"}, {"error", reason}, {"reason", reason},
            {"spam_score", score}, {"spam_reasons", reasons}};
    }
    static std::string reason_term(std::string value) {
        for (auto& ch : value) if (static_cast<unsigned char>(ch) < 32 || ch == 127) ch = ' ';
        if (value.size() <= 200) return value;
        std::size_t length = 200;
        while (length && (static_cast<unsigned char>(value[length]) & 0xc0) == 0x80) --length;
        return value.substr(0, length) + "...";
    }
    static std::string metadata(const Json& request, const char* key) {
        if (!request.contains(key)) return {};
        if (!request.at(key).is_string()) throw std::invalid_argument("invalid scan metadata");
        const auto value = request.at(key).get<std::string>();
        if (value.size() > 320 || std::any_of(value.begin(), value.end(), [](unsigned char ch) { return ch < 32 || ch == 127; }))
            throw std::invalid_argument("invalid scan metadata");
        return value;
    }
    static bool matches(const std::set<std::string>& policy, const std::string& sender) {
        if (sender.empty()) return false;
        const auto at = sender.rfind('@');
        return policy.contains(sender) || (at != std::string::npos && policy.contains(sender.substr(at + 1)));
    }
    static void heuristic(const mime::Part& part, double& score, Json& reasons) {
        bool executable = false, form = false, shortened_link = false;
        std::function<void(const mime::Part&)> inspect = [&](const mime::Part& item) {
            if (item.content_type == "text/html") {
                const auto html = lower(mime::decode_text(item));
                form = form || html.find("<form") != std::string::npos || html.find("<input") != std::string::npos;
                for (const auto* url : {"bit.ly/", "tinyurl.com/", "t.co/", "is.gd/"})
                    shortened_link = shortened_link || html.find(url) != std::string::npos;
            }
            try {
                const auto filename = lower(mime::attachment_filename(item));
                for (const auto* suffix : {".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs"})
                    executable = executable || filename.ends_with(suffix);
            } catch (const std::exception&) {}
            for (const auto& child : item.parts) inspect(child);
        };
        inspect(part);
        if (form) { score += 2; reasons.push_back("HTML contains a form or input control"); }
        if (shortened_link) { score += 1; reasons.push_back("HTML contains a shortened link"); }
        if (executable) { score += 3; reasons.push_back("Executable attachment filename"); }
    }
    static void collect(const mime::Part& part, std::vector<std::string_view>& payloads, std::string& searchable) {
        for (const auto& [name, value] : part.headers) {
            const auto header_name = lower(name);
            // Internet senders control these fields. Only our RPC metadata and
            // local scanner response can establish filtering policy.
            if (header_name == "authentication-results" || header_name == "arc-authentication-results" ||
                header_name.starts_with("x-spam") || header_name == "dkim-signature" || header_name == "received") continue;
            searchable += name; searchable += ": ";
            try { searchable += mime::decode_header(value); }
            catch (const std::exception&) { searchable += value; }
            searchable += '\n';
        }
        if (!part.body.empty()) {
            payloads.emplace_back(part.body);
            // Arbitrary attachment bytes still enter the malware scanner, while
            // text bodies and headers are the input to the spam policy.
            if (part.content_type.starts_with("text/") || part.content_type.empty()) {
                searchable += mime::decode_text(part); searchable += '\n';
            }
        }
        for (const auto& child : part.parts) collect(child, payloads, searchable);
    }
    Json scan_rspamd(std::string_view raw, const Json& request) const {
        Connection connection{std::chrono::seconds(rspamd_timeout_)};
        connection.set_deadline(std::chrono::steady_clock::now() + std::chrono::seconds(rspamd_timeout_));
        connection.connect(rspamd_host_, rspamd_port_);
        std::string head = "POST /checkv2 HTTP/1.1\r\nHost: localhost\r\nContent-Type: message/rfc822\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: " + std::to_string(raw.size()) + "\r\n";
        for (const auto& [field, header] : std::array<std::pair<const char*, const char*>, 4>{{
            {"sender", "From"}, {"peer_ip", "IP"}, {"helo", "Helo"}, {"recipient", "Rcpt"}}}) {
            const auto value = metadata(request, field);
            if (!value.empty()) head += std::string(header) + ": " + value + "\r\n";
        }
        connection.write(head + "\r\n");
        connection.write(raw);
        const auto status = connection.line(1024);
        if (!status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 "))
            throw std::runtime_error("Rspamd rejected scan");
        std::map<std::string, std::string> headers;
        std::size_t header_bytes = 0;
        for (;;) {
            const auto line = connection.line(8192);
            header_bytes += line.size() + 2;
            if (header_bytes > 32768 || headers.size() > 64) throw std::runtime_error("oversized Rspamd headers");
            if (line.empty()) break;
            const auto colon = line.find(':');
            if (colon == std::string::npos || !headers.emplace(lower(line.substr(0, colon)), trim(line.substr(colon + 1))).second)
                throw std::runtime_error("invalid Rspamd headers");
        }
        constexpr std::size_t limit = 131072;
        std::string body;
        const auto length = headers.find("content-length"), encoding = headers.find("transfer-encoding");
        if (encoding != headers.end() && lower(encoding->second) == "chunked" && length == headers.end()) {
            for (;;) {
                const auto line = connection.line(128);
                const auto semicolon = line.find(';');
                const auto number = line.substr(0, semicolon);
                if (number.empty() || number.size() > 8 || number.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                    throw std::runtime_error("invalid Rspamd chunk");
                const auto bytes = std::stoull(number, nullptr, 16);
                if (bytes > limit - body.size()) throw std::runtime_error("oversized Rspamd result");
                if (!bytes) {
                    if (!connection.line(8192).empty()) throw std::runtime_error("unsupported Rspamd trailers");
                    break;
                }
                body += connection.read(bytes);
                if (!connection.line(2).empty()) throw std::runtime_error("invalid Rspamd chunk terminator");
            }
        } else if (length != headers.end() && encoding == headers.end()) {
            if (length->second.empty() || length->second.size() > 7 || length->second.find_first_not_of("0123456789") != std::string::npos)
                throw std::runtime_error("invalid Rspamd length");
            const auto size = std::stoull(length->second);
            if (size > limit) throw std::runtime_error("oversized Rspamd result");
            body = connection.read(size);
        } else throw std::runtime_error("Rspamd result needs bounded framing");
        const auto result = Json::parse(body);
        if (!result.is_object() || !result.contains("score") || !result.at("score").is_number() ||
            (result.contains("action") && !result.at("action").is_string()))
            throw std::runtime_error("invalid Rspamd result");
        return result;
    }
    ScanResult scan_clamav(std::string_view payload, std::chrono::steady_clock::time_point deadline) const {
        if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("ClamAV scan deadline");
        asio::io_context context;
        tcp::resolver resolver(context);
        tcp::socket socket(context);
        asio::steady_timer timer(context, deadline);
        std::exception_ptr failure;
        auto result = ScanResult::clean;
        timer.async_wait([&](const std::error_code& error) {
            if (!error) {
                resolver.cancel();
                std::error_code ignored;
                socket.cancel(ignored);
                socket.close(ignored);
            }
        });
        asio::co_spawn(context, [&]() -> asio::awaitable<void> {
            const auto endpoints = co_await resolver.async_resolve(clamav_host_, std::to_string(clamav_port_), asio::use_awaitable);
            if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("ClamAV scan deadline");
            co_await asio::async_connect(socket, endpoints, asio::use_awaitable);
            co_await asio::async_write(socket, asio::buffer("zINSTREAM\0", 10), asio::use_awaitable);
            for (std::size_t position = 0; position < payload.size();) {
                const auto count = std::min<std::size_t>(65536, payload.size() - position);
                const std::array<char, 4> size_bytes{
                    static_cast<char>((count >> 24) & 255), static_cast<char>((count >> 16) & 255),
                    static_cast<char>((count >> 8) & 255), static_cast<char>(count & 255)};
                co_await asio::async_write(socket, asio::buffer(size_bytes), asio::use_awaitable);
                co_await asio::async_write(socket, asio::buffer(payload.data() + position, count), asio::use_awaitable);
                position += count;
            }
            co_await asio::async_write(socket, asio::buffer("\0\0\0\0", 4), asio::use_awaitable);
            std::string reply;
            while (reply.size() < 4096) {
                char byte = 0;
                co_await asio::async_read(socket, asio::buffer(&byte, 1), asio::use_awaitable);
                if (byte == '\0' || byte == '\n') {
                    if (reply == "stream: OK") co_return;
                    if (reply.starts_with("stream: ") && reply.ends_with(" FOUND")) {
                        result = ScanResult::infected;
                        co_return;
                    }
                    throw std::runtime_error("ClamAV rejected stream");
                }
                reply += byte;
            }
            throw std::runtime_error("oversized ClamAV reply");
        }, [&](std::exception_ptr error) { failure = error; timer.cancel(); });
        context.run();
        if (failure) std::rethrow_exception(failure);
        return result;
    }
    static constexpr std::string_view eicar_ = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    int max_bytes_;
    std::string clamav_host_;
    int clamav_port_, clamav_timeout_, spam_threshold_;
    bool rspamd_enabled_;
    std::string rspamd_host_;
    int rspamd_port_, rspamd_timeout_;
    std::set<std::string> allow_, block_;
    std::vector<std::string> blocked_;
    std::vector<Rule> rules_;
};
}
}

int main(int argc, char** argv) {
    return postplus::service_main("filter", argc, argv, [](const postplus::Config& config) {
        auto filter = std::make_shared<postplus::Filter>(config);
        postplus::serve_rpc(config, "filter", [filter](const postplus::Json& request) { return filter->handle(request); });
    });
}
