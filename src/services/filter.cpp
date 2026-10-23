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
struct HtmlSignals { std::string text; bool form = false, shortened_link = false; };

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
        const auto scanner_address = ip::make_address(rspamd_host_, address_error);
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
        std::string searchable, rule_text;
        bool html_form = false, shortened_link = false;
        collect(message, payloads, searchable, rule_text, html_form, shortened_link);
        for (const auto payload : payloads) {
            if (payload.find(eicar_) != std::string_view::npos)
                return verdict("reject", "EICAR antivirus test signature detected", 0);
        }
        searchable = lower(std::move(searchable));
        rule_text = lower(std::move(rule_text));
        for (const auto& term : blocked_)
            if (searchable.find(term) != std::string::npos || matches_term(rule_text, term))
                return verdict("reject", "configured blocked term detected", 0);
        double score = 0;
        Json reasons = Json::array();
        bool spam = false;
        const bool blocked_sender = inbound && matches(block_, sender);
        const bool allowed_sender = inbound && !blocked_sender && matches(allow_, sender);
        if (inbound && !allowed_sender) {
            if (rule_text.find(lower(std::string(gtube_))) != std::string::npos ||
                std::any_of(payloads.begin(), payloads.end(), [](std::string_view payload) { return payload.find(gtube_) != payload.npos; })) {
                score += spam_threshold_;
                reasons.push_back("GTUBE anti-spam test signature detected");
                spam = true;
            }
            if (blocked_sender) {
                score += spam_threshold_;
                reasons.push_back("Envelope sender matches administrator block policy");
                spam = true;
            }
            for (const auto& rule : rules_) {
                if (matches_term(rule_text, rule.term)) {
                    score += rule.weight;
                    if (reasons.size() < 128) reasons.push_back("Weighted term: " + reason_term(rule.term));
                }
            }
            heuristic(message, html_form, shortened_link, score, reasons);
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
    static std::string normalize_text(std::string_view input) {
        std::string output;
        output.reserve(input.size());
        for (std::size_t at = 0; at < input.size();) {
            const auto tail = input.substr(at);
            // Ignore common invisible word separators used to obscure terms.
            if (tail.starts_with("\xE2\x80\x8B") || tail.starts_with("\xE2\x80\x8C") ||
                tail.starts_with("\xE2\x80\x8D") || tail.starts_with("\xE2\x81\xA0") || tail.starts_with("\xEF\xBB\xBF")) { at += 3; continue; }
            if (tail.starts_with("\xC2\xAD")) { at += 2; continue; }
            const auto ch = static_cast<unsigned char>(input[at]);
            const bool unicode_space = (tail.size() >= 3 && tail[0] == '\xE2' && tail[1] == '\x80' &&
                ((static_cast<unsigned char>(tail[2]) >= 0x80 && static_cast<unsigned char>(tail[2]) <= 0x8a) ||
                 tail[2] == '\xA8' || tail[2] == '\xA9' || tail[2] == '\xAF')) ||
                tail.starts_with("\xE2\x81\x9F") || tail.starts_with("\xE3\x80\x80");
            if (std::isspace(ch) || tail.starts_with("\xC2\xA0") || unicode_space) {
                if (!output.empty() && output.back() != ' ') output += ' ';
                at += unicode_space ? 3 : tail.starts_with("\xC2\xA0") ? 2 : 1;
            } else { output += input[at++]; }
        }
        return trim(output);
    }
    static bool matches_term(std::string_view text, std::string_view term) {
        const auto normalized = normalize_text(term);
        return !normalized.empty() && text.find(normalized) != text.npos;
    }
    static std::string html_entities(std::string_view input) {
        std::string output;
        output.reserve(input.size());
        for (std::size_t at = 0; at < input.size();) {
            if (input[at] != '&') { output += input[at++]; continue; }
            const auto offset = input.substr(at, 17).find(';');
            if (offset == input.npos) { output += input[at++]; continue; }
            const auto end = at + offset;
            const auto entity = input.substr(at + 1, end - at - 1);
            unsigned point = 0;
            if (entity == "nbsp" || entity == "ensp" || entity == "emsp" || entity == "thinsp") point = ' ';
            else if (entity == "Tab") point = '\t';
            else if (entity == "NewLine") point = '\n';
            else if (entity == "amp") point = '&';
            else if (entity == "lt") point = '<';
            else if (entity == "gt") point = '>';
            else if (entity == "quot") point = '"';
            else if (entity == "apos") point = '\'';
            else if (entity == "colon") point = ':';
            else if (entity == "sol") point = '/';
            else if (entity == "period") point = '.';
            else if (entity == "shy") point = 0xad;
            else if (entity == "ZeroWidthSpace" || entity == "zwnj" || entity == "zwj") point = 0x200b;
            else if (entity.starts_with('#')) {
                std::size_t index = 1;
                unsigned base = 10;
                if (index < entity.size() && (entity[index] == 'x' || entity[index] == 'X')) { base = 16; ++index; }
                for (; index < entity.size(); ++index) {
                    const auto ch = entity[index];
                    const unsigned digit = ch >= '0' && ch <= '9' ? ch - '0' :
                        ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : base;
                    if (digit >= base || point > (0x10ffff - digit) / base) { point = 0; break; }
                    point = point * base + digit;
                }
            }
            if (!point || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
                output.append(input.substr(at, end - at + 1));
            } else if (point <= 0x7f) output += static_cast<char>(point);
            else if (point <= 0x7ff) {
                output += static_cast<char>(0xc0 | (point >> 6)); output += static_cast<char>(0x80 | (point & 63));
            } else if (point <= 0xffff) {
                output += static_cast<char>(0xe0 | (point >> 12)); output += static_cast<char>(0x80 | ((point >> 6) & 63));
                output += static_cast<char>(0x80 | (point & 63));
            } else {
                output += static_cast<char>(0xf0 | (point >> 18)); output += static_cast<char>(0x80 | ((point >> 12) & 63));
                output += static_cast<char>(0x80 | ((point >> 6) & 63)); output += static_cast<char>(0x80 | (point & 63));
            }
            at = end + 1;
        }
        return output;
    }
    static bool shortened_url(std::string_view input) {
        const auto value = lower(trim(html_entities(input)));
        std::size_t start = value.starts_with("https://") ? 8 : value.starts_with("http://") ? 7 : value.starts_with("//") ? 2 : 0;
        if (!start) return false;
        auto host = value.substr(start, value.find_first_of("/?#", start) - start);
        if (const auto at = host.rfind('@'); at != host.npos) host.erase(0, at + 1);
        if (const auto colon = host.find(':'); colon != host.npos) host.resize(colon);
        if (host.ends_with('.')) host.pop_back();
        return host == "bit.ly" || host == "tinyurl.com" || host == "t.co" || host == "is.gd";
    }
    static HtmlSignals html_signals(std::string_view input) {
        HtmlSignals result;
        const auto lowered = lower(std::string(input));
        std::string raw_element;
        std::size_t template_depth = 0;
        auto name_char = [](unsigned char ch) { return !std::isspace(ch) && ch != '/' && ch != '>'; };
        for (std::size_t at = 0; at < input.size();) {
            if (!raw_element.empty()) {
                // JavaScript/CSS/title text is not HTML markup. In particular,
                // a literal '<' or quote cannot swallow the following body.
                const auto marker = "</" + raw_element;
                auto close = lowered.find(marker, at);
                while (close != lowered.npos) {
                    const auto after = close + marker.size();
                    if (after < input.size() && (std::isspace(static_cast<unsigned char>(input[after])) || input[after] == '>' || input[after] == '/')) break;
                    close = lowered.find(marker, after);
                }
                if (close == lowered.npos) break;
                at = close;
                raw_element.clear();
            }
            if (input.substr(at).starts_with("<!--")) {
                const auto end = input.find("-->", at + 4);
                at = end == input.npos ? input.size() : end + 3;
                continue;
            }
            if (input[at] != '<') {
                const auto next = input.find('<', at);
                const auto end = next == input.npos ? input.size() : next;
                if (!template_depth) result.text.append(input.substr(at, end - at));
                at = end;
                continue;
            }
            std::size_t name_at = at + 1;
            const bool closing = name_at < input.size() && input[name_at] == '/';
            if (closing) ++name_at;
            if (name_at == input.size() || !((input[name_at] >= 'a' && input[name_at] <= 'z') || (input[name_at] >= 'A' && input[name_at] <= 'Z'))) {
                if (!template_depth) result.text += input[at];
                ++at; continue;
            }
            std::size_t name_end = name_at;
            while (name_end < input.size() && name_char(static_cast<unsigned char>(input[name_end]))) ++name_end;
            if (name_end == name_at) { if (!template_depth) result.text += input[at]; ++at; continue; }
            const auto name = lowered.substr(name_at, name_end - name_at);
            std::size_t end = name_end;
            char quote = 0;
            for (; end < input.size(); ++end) {
                const auto ch = input[end];
                if (quote) { if (ch == quote) quote = 0; }
                else if (ch == '\'' || ch == '"') quote = ch;
                else if (ch == '>') break;
            }
            if (end == input.size()) break;
            if (name == "template") {
                if (!closing) ++template_depth;
                else if (template_depth) --template_depth;
            } else if (!closing && (name == "title" || name == "script" || name == "style")) {
                raw_element = name;
            } else if (!template_depth) {
                if (!closing && (name == "form" || name == "input")) result.form = true;
                if (!closing && (name == "a" || name == "area")) {
                    for (std::size_t pos = name_end; pos < end;) {
                        while (pos < end && (std::isspace(static_cast<unsigned char>(input[pos])) || input[pos] == '/')) ++pos;
                        const auto begin = pos;
                        while (pos < end && !std::isspace(static_cast<unsigned char>(input[pos])) && input[pos] != '=' && input[pos] != '/') ++pos;
                        const auto attribute = lowered.substr(begin, pos - begin);
                        while (pos < end && std::isspace(static_cast<unsigned char>(input[pos]))) ++pos;
                        if (pos == end || input[pos] != '=') continue;
                        ++pos;
                        while (pos < end && std::isspace(static_cast<unsigned char>(input[pos]))) ++pos;
                        const auto delimiter = pos < end && (input[pos] == '\'' || input[pos] == '"') ? input[pos++] : '\0';
                        const auto value_begin = pos;
                        while (pos < end && (delimiter ? input[pos] != delimiter : !std::isspace(static_cast<unsigned char>(input[pos])))) ++pos;
                        if (attribute == "href") result.shortened_link = result.shortened_link || shortened_url(input.substr(value_begin, pos - value_begin));
                        if (delimiter && pos < end) ++pos;
                    }
                }
                for (const auto* block : {"br", "p", "div", "li", "tr", "td", "th", "table", "section", "article", "h1", "h2", "h3", "hr"})
                    if (name == block) { result.text += ' '; break; }
            }
            at = end + 1;
        }
        result.text = html_entities(result.text);
        return result;
    }
    static void heuristic(const mime::Part& part, bool form, bool shortened_link, double& score, Json& reasons) {
        bool executable = false;
        std::function<void(const mime::Part&)> inspect = [&](const mime::Part& item) {
            try {
                const auto filename = lower(mime::attachment_filename(item));
                for (const auto* suffix : {".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".msi", ".hta", ".lnk", ".wsf", ".jse", ".vbe"})
                    executable = executable || filename.ends_with(suffix);
            } catch (const std::exception&) {}
            for (const auto& child : item.parts) inspect(child);
        };
        inspect(part);
        if (form) { score += 2; reasons.push_back("HTML contains a form or input control"); }
        if (shortened_link) { score += 1; reasons.push_back("HTML contains a shortened link"); }
        if (executable) { score += 3; reasons.push_back("Executable attachment filename"); }
    }
    static void collect(const mime::Part& part, std::vector<std::string_view>& payloads, std::string& searchable,
                        std::string& rule_text, bool& form, bool& shortened_link) {
        for (const auto& [name, value] : part.headers) {
            const auto header_name = lower(name);
            // Internet senders control these fields. Only our RPC metadata and
            // local scanner response can establish filtering policy.
            if (header_name == "authentication-results" || header_name == "arc-authentication-results" ||
                header_name.starts_with("x-spam") || header_name == "dkim-signature" || header_name == "received") continue;
            std::string decoded;
            try { decoded = mime::decode_header(value); }
            catch (const std::exception&) { decoded = value; }
            searchable += name; searchable += ": "; searchable += decoded;
            searchable += '\n';
            rule_text += normalize_text(decoded); rule_text += '\n';
        }
        if (!part.body.empty()) {
            payloads.emplace_back(part.body);
            // Arbitrary attachment bytes still enter the malware scanner, while
            // text bodies and headers are the input to the spam policy.
            if (part.content_type.starts_with("text/") || part.content_type.empty()) {
                const auto decoded = mime::decode_text(part);
                searchable += decoded; searchable += '\n';
                if (part.content_type == "text/html") {
                    const auto html = html_signals(decoded);
                    rule_text += normalize_text(html.text);
                    form = form || html.form;
                    shortened_link = shortened_link || html.shortened_link;
                } else rule_text += normalize_text(decoded);
                rule_text += '\n';
            }
        }
        for (const auto& child : part.parts) collect(child, payloads, searchable, rule_text, form, shortened_link);
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
        Connection connection{std::chrono::seconds(clamav_timeout_)};
        // The caller shares this absolute deadline across all MIME parts.
        connection.set_deadline(deadline);
        connection.connect(clamav_host_, clamav_port_);
        connection.write(std::string_view("zINSTREAM\0", 10));
        for (std::size_t position = 0; position < payload.size();) {
            const auto count = std::min<std::size_t>(65536, payload.size() - position);
            const std::array<char, 4> size_bytes{
                static_cast<char>((count >> 24) & 255), static_cast<char>((count >> 16) & 255),
                static_cast<char>((count >> 8) & 255), static_cast<char>(count & 255)};
            connection.write(std::string_view(size_bytes.data(), size_bytes.size()));
            connection.write(payload.substr(position, count));
            position += count;
        }
        connection.write(std::string_view("\0\0\0\0", 4));
        std::string reply;
        while (reply.size() < 4096) {
            const auto byte = connection.read(1).front();
            if (byte == '\0' || byte == '\n') {
                if (reply == "stream: OK") return ScanResult::clean;
                if (reply.starts_with("stream: ") && reply.ends_with(" FOUND"))
                    return ScanResult::infected;
                throw std::runtime_error("ClamAV rejected stream");
            }
            reply += byte;
        }
        throw std::runtime_error("oversized ClamAV reply");
    }
    static constexpr std::string_view eicar_ = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    static constexpr std::string_view gtube_ = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
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
