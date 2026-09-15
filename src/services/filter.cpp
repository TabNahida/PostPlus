#include <postplus/core.hpp>
#include <postplus/mime.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <set>
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
          spam_threshold_(config.number("spam_threshold", 5)) {
        if (max_bytes_ < 1 || max_bytes_ > 100 * 1024 * 1024 || clamav_port_ < 1 || clamav_port_ > 65535 ||
            clamav_timeout_ < 1 || clamav_timeout_ > 120 || spam_threshold_ < 1 || spam_threshold_ > 1000)
            throw std::invalid_argument("invalid filter settings");
        if (clamav_host_.size() > 253 || clamav_host_.find_first_of("\r\n\0", 0, 3) != std::string::npos)
            throw std::invalid_argument("invalid ClamAV host");
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
        for (const auto& rule : rules_)
            if (searchable.find(rule.term) != std::string::npos) score += rule.weight;
        if (score >= spam_threshold_) return verdict("reject", "spam score exceeds threshold", score);
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
                return {{"ok", false}, {"action", "defer"}, {"error", "ClamAV unavailable or scan incomplete"},
                    {"reason", "ClamAV unavailable or scan incomplete"}, {"spam_score", score}};
            }
            return verdict("accept", "ClamAV and baseline rules passed", score);
        }
        return verdict("accept", "baseline rules passed; ClamAV is disabled", score);
    }
private:
    Json verdict(const char* action, const char* reason, double score) const {
        return {{"ok", true}, {"action", action}, {"reason", reason}, {"spam_score", score},
            {"antivirus", clamav_host_.empty() ? "eicar-only" : "clamav"}};
    }
    static void collect(const mime::Part& part, std::vector<std::string_view>& payloads, std::string& searchable) {
        for (const auto& [name, value] : part.headers) {
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
                searchable += part.body; searchable += '\n';
            }
        }
        for (const auto& child : part.parts) collect(child, payloads, searchable);
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
