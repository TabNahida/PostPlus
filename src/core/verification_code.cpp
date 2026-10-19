#include "postplus/verification_code.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

namespace postplus {
namespace {
constexpr std::size_t max_text = 64 * 1024, max_total = 128 * 1024;
bool ascii_alnum(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool digit(char c) { return c >= '0' && c <= '9'; }
std::string lowered(std::string_view value) {
    std::string result(value);
    for (char& c : result) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return result;
}
bool boundary(std::string_view value, std::size_t start, std::size_t length) {
    return (!start || !ascii_alnum(value[start - 1])) &&
           (start + length == value.size() || !ascii_alnum(value[start + length]));
}
const std::vector<std::string_view> cues{
    "verification code", "security code", "one-time code", "one time code",
    "one-time password", "one time password", "one-time passcode", "one time passcode",
    "login code", "log-in code", "sign-in code", "sign in code", "authentication code",
    "confirmation code", "reset code", "otp", "验证码", "校验码", "动态码", "安全码",
    "一次性密码", "登录代码", "确认码", "passcode", "email code", "auth code", "2fa code",
    "verification-code", "验证代码", "一次性代码", "登录码"
};
bool has_context(std::string_view value) {
    for (auto cue : cues) {
        for (auto at = value.find(cue); at != value.npos; at = value.find(cue, at + cue.size()))
            if (boundary(value, at, cue.size())) return true;
    }
    for (auto cue : {"verify your email", "verify your account", "confirm your email", "email verification",
                     "邮箱验证", "验证您的邮箱", "身份验证"})
        if (value.find(cue) != value.npos) return true;
    return false;
}
void replace_all(std::string& value, std::string_view what, std::string_view with) {
    for (auto at = value.find(what); at != value.npos; at = value.find(what, at + with.size())) value.replace(at, what.size(), with);
}
bool connector(std::string gap) {
    if (gap.size() > 64) return false;
    gap = lowered(gap);
    for (auto word : {"是", "为", "如下", "请输入", "请使用", "：", "，", "。", "（", "）", "【", "】"}) replace_all(gap, word, " ");
    for (char& c : gap) {
        if (std::isspace(static_cast<unsigned char>(c)) || std::string_view(":;=\"'(),.[]{}-<>*").find(c) != std::string_view::npos) c = ' ';
    }
    const std::set<std::string_view> allowed{"is", "are", "your", "the", "a", "use", "enter", "please", "number", "code", "otp"};
    std::size_t count = 0;
    for (std::size_t at = 0; at < gap.size();) {
        if (gap[at] == ' ') { ++at; continue; }
        const auto end = gap.find(' ', at);
        const auto word = std::string_view(gap).substr(at, end == gap.npos ? gap.size() - at : end - at);
        if (!allowed.contains(word) || ++count > 4) return false;
        at += word.size();
    }
    return true;
}
std::string normalized_text(std::string input) {
    // Common typography in real OTP templates; never normalize URL tokens.
    for (auto value : {"\xc2\xa0", "\xe2\x80\xaf", "\xe3\x80\x80"}) replace_all(input, value, " ");
    for (auto value : {"\xe2\x80\x8b", "\xe2\x80\x8c", "\xe2\x80\x8d", "\xef\xbb\xbf"}) replace_all(input, value, "");
    for (unsigned digit = 0; digit < 10; ++digit) {
        std::string wide{"\xef\xbc"}; wide += static_cast<char>(0x90 + digit);
        replace_all(input, wide, std::string(1, static_cast<char>('0' + digit)));
    }
    return input;
}
std::string unquoted_text(std::string_view input, bool remove_urls = true) {
    std::string output;
    for (std::size_t at = 0; at < input.size();) {
        const auto end = input.find('\n', at);
        auto line = input.substr(at, end == input.npos ? input.size() - at : end - at);
        const auto first = line.find_first_not_of(" \t\r");
        const auto lower = lowered(line.substr(first == line.npos ? 0 : first));
        if (lower.find("original message") != lower.npos || lower.find("forwarded message") != lower.npos ||
            lower.find("begin forwarded") != lower.npos || lower.find("转发邮件") != lower.npos || lower.find("原始邮件") != lower.npos ||
            (lower.starts_with("on ") && lower.find("wrote:") != lower.npos)) break;
        if (first == line.npos || line[first] != '>') output.append(line);
        else output.append(line.size(), ' ');
        if (end != input.npos) output += '\n';
        if (end == input.npos) break;
        at = end + 1;
    }
    if (!remove_urls) return output;
    // Remove complete URL/email tokens, including their path/query digits.
    for (std::size_t at = 0; at < output.size();) {
        if (std::isspace(static_cast<unsigned char>(output[at]))) { ++at; continue; }
        auto end = at;
        while (end < output.size() && !std::isspace(static_cast<unsigned char>(output[end]))) ++end;
        const auto token = lowered(std::string_view(output).substr(at, end - at));
        if (token.find("://") != token.npos || token.find("www.") != token.npos || token.find('@') != token.npos || token.starts_with("mailto:"))
            std::fill(output.begin() + at, output.begin() + end, ' ');
        at = end;
    }
    return output;
}
void append_entity(std::string& output, std::string_view entity) {
    if (entity == "nbsp") output += ' ';
    else if (entity == "amp") output += '&';
    else if (entity == "lt") output += '<';
    else if (entity == "gt") output += '>';
    else if (entity == "quot") output += '"';
    else if (entity == "apos") output += '\'';
    else if (entity == "colon") output += ':';
    else if (entity.starts_with('#')) {
        std::size_t at = 1; unsigned base = 10, number = 0;
        if (at < entity.size() && (entity[at] == 'x' || entity[at] == 'X')) { base = 16; ++at; }
        if (at == entity.size() || entity.size() > 9) { output += ' '; return; }
        for (; at < entity.size(); ++at) {
            const char c = entity[at];
            const unsigned value = digit(c) ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99;
            if (value >= base) { output += ' '; return; }
            number = number * base + value;
        }
        if (number > 0 && number < 128) output += static_cast<char>(number);
        else if (number == 160) output += ' ';
        else if (number >= 0x80 && number <= 0x7ff) {
            output += static_cast<char>(0xc0 | (number >> 6)); output += static_cast<char>(0x80 | (number & 63));
        } else if (number >= 0x800 && number <= 0xffff && !(number >= 0xd800 && number <= 0xdfff)) {
            output += static_cast<char>(0xe0 | (number >> 12)); output += static_cast<char>(0x80 | ((number >> 6) & 63)); output += static_cast<char>(0x80 | (number & 63));
        } else output += ' ';
    } else output += ' ';
}
std::string entity_text(std::string_view input) {
    std::string output;
    for (std::size_t at = 0; at < input.size(); ++at) {
        if (input[at] == '&') {
            const auto end = input.find(';', at + 1);
            if (end != input.npos && end - at <= 12) { append_entity(output, input.substr(at + 1, end - at - 1)); at = end; continue; }
        }
        output += input[at];
    }
    return output;
}
std::string html_attribute(std::string_view token, std::size_t at, std::string_view wanted) {
    std::string result; bool found = false;
    while (at < token.size()) {
        while (at < token.size() && (std::isspace(static_cast<unsigned char>(token[at])) || token[at] == '/')) ++at;
        const auto start = at;
        while (at < token.size() && !std::isspace(static_cast<unsigned char>(token[at])) && token[at] != '=' && token[at] != '/') ++at;
        const auto name = lowered(token.substr(start, at - start));
        while (at < token.size() && std::isspace(static_cast<unsigned char>(token[at]))) ++at;
        std::string value;
        if (at < token.size() && token[at] == '=') {
            ++at; while (at < token.size() && std::isspace(static_cast<unsigned char>(token[at]))) ++at;
            if (at < token.size() && (token[at] == '\'' || token[at] == '"')) {
                const auto quote = token[at++]; const auto begin = at;
                while (at < token.size() && token[at] != quote) ++at;
                if (at == token.size()) return {};
                value = std::string(token.substr(begin, at - begin)); ++at;
            } else {
                const auto begin = at;
                while (at < token.size() && !std::isspace(static_cast<unsigned char>(token[at]))) ++at;
                value = std::string(token.substr(begin, at - begin));
            }
        }
        if (name == wanted) { if (found) return {}; found = true; result = entity_text(value); }
        if (at == start) ++at;
    }
    return result;
}
struct HtmlLink { std::string url, label; std::size_t start, end; };
std::string visible_html(std::string_view input, std::vector<HtmlLink>* links = nullptr) {
    std::string output;
    const auto lower_input = lowered(input);
    std::vector<std::pair<std::string, bool>> tags;
    std::size_t hidden = 0;
    std::optional<std::pair<std::string, std::size_t>> anchor;
    for (std::size_t at = 0; at < input.size();) {
        if (input.substr(at).starts_with("<!--")) {
            const auto end = input.find("-->", at + 4); if (end == input.npos) break; at = end + 3; continue;
        }
        if (input[at] == '<') {
            auto end = at + 1; char quote = 0;
            for (; end < input.size() && end - at <= 4096; ++end) {
                if (quote) { if (input[end] == quote) quote = 0; }
                else if (input[end] == '\'' || input[end] == '"') quote = input[end];
                else if (input[end] == '>') break;
            }
            if (end == input.size() || end - at > 4096) break;
            auto token = lowered(input.substr(at + 1, end - at - 1));
            bool closing = token.starts_with('/'); std::size_t start = closing ? 1 : 0;
            while (start < token.size() && token[start] == ' ') ++start;
            auto name_end = start; while (name_end < token.size() && ((token[name_end] >= 'a' && token[name_end] <= 'z') || digit(token[name_end]))) ++name_end;
            const auto name = token.substr(start, name_end - start);
            // HTML raw-text contents are not a sequence of tags. In particular,
            // quotes or '<' in JavaScript must not swallow the next visible CTA.
            if (!closing && (name == "script" || name == "style" || name == "title" || name == "textarea" ||
                             name == "iframe" || name == "xmp" || name == "noembed" || name == "noframes" || name == "noscript")) {
                const auto closing_name = "</" + name;
                auto close = lower_input.find(closing_name, end + 1);
                while (close != input.npos) {
                    const auto after = close + closing_name.size();
                    if (after < input.size() && (input[after] == '>' || std::isspace(static_cast<unsigned char>(input[after])))) break;
                    close = lower_input.find(closing_name, after);
                }
                if (close == input.npos) break;
                const auto close_end = input.find('>', close + closing_name.size());
                if (close_end == input.npos) break;
                at = close_end + 1; continue;
            }
            const bool block = name == "p" || name == "div" || name == "br" || name == "tr" || name == "td" || name == "h1" || name == "h2" || name == "h3" || name == "li";
            if (links && closing && name == "a" && anchor) {
                if (!hidden && output.size() - anchor->second <= 512) {
                    if (links->size() >= 128) throw std::invalid_argument("Too many verification links");
                    links->push_back({anchor->first, output.substr(anchor->second), anchor->second, output.size()});
                }
                anchor.reset();
            }
            if (closing) {
                auto match = std::find_if(tags.rbegin(), tags.rend(), [&](const auto& tag) { return tag.first == name; });
                if (match != tags.rend()) {
                    const auto index = static_cast<std::size_t>(std::distance(tags.begin(), match.base()) - 1);
                    for (auto i = index; i < tags.size(); ++i) if (tags[i].second) --hidden;
                    tags.resize(index);
                }
            } else if (!name.empty()) {
                auto compact = lowered(entity_text(token)); compact.erase(std::remove_if(compact.begin(), compact.end(), [](unsigned char c) { return std::isspace(c); }), compact.end());
                const bool skip = name == "head" || name == "blockquote" || name == "template" ||
                    compact.find("display:none") != compact.npos || compact.find("visibility:hidden") != compact.npos ||
                    lowered(html_attribute(token, name_end, "aria-hidden")) == "true" ||
                    token.find(" hidden") != token.npos || token.find("gmail_quote") != token.npos || token.find("yahoo_quoted") != token.npos;
                const bool empty = token.ends_with('/') || name == "br" || name == "hr" || name == "img" || name == "meta" || name == "input" || name == "link";
                if (!empty) { if (tags.size() >= 64) throw std::invalid_argument("HTML nesting exceeds verification limit"); tags.emplace_back(name, skip); if (skip) ++hidden; }
                if (links && name == "a") {
                    anchor.reset();
                    if (!hidden) {
                        const auto href = html_attribute(input.substr(at + 1, end - at - 1), name_end, "href");
                        if (!href.empty()) anchor = std::make_pair(href, output.size());
                    }
                }
            }
            if (block && !hidden) output += '\n';
            at = end + 1; continue;
        }
        if (!hidden) {
            if (input[at] == '&') {
                const auto end = input.find(';', at + 1);
                if (end != input.npos && end - at <= 12) { append_entity(output, input.substr(at + 1, end - at - 1)); at = end + 1; continue; }
            }
            output += input[at];
        }
        ++at;
    }
    return unquoted_text(output, links == nullptr);
}
struct Candidate { std::size_t start, end; std::string code; };
std::vector<Candidate> candidates(std::string_view text) {
    std::vector<Candidate> result;
    for (std::size_t at = 0; at < text.size();) {
        if (!ascii_alnum(text[at])) { ++at; continue; }
        auto end = at; bool letters = false, digits = false;
        while (end < text.size() && ascii_alnum(text[end])) { digits |= digit(text[end]); letters |= !digit(text[end]); ++end; }
        auto code = std::string(text.substr(at, end - at));
        if (!letters && code.size() == 1) {
            auto tail = end;
            std::string grouped = code;
            while (tail < text.size() && grouped.size() <= 8) {
                auto next = tail;
                while (next < text.size() && (text[next] == ' ' || text[next] == '\t' || text[next] == '-')) ++next;
                if (next == tail || next - tail > 3 || next >= text.size() || !digit(text[next]) ||
                    (next + 1 < text.size() && ascii_alnum(text[next + 1]))) break;
                grouped += text[next]; tail = next + 1;
            }
            if (grouped.size() >= 4 && grouped.size() <= 8) { code = std::move(grouped); end = tail; }
        }
        if (!letters && (code.size() == 3 || code.size() == 4) && end < text.size() && (text[end] == ' ' || text[end] == '-')) {
            auto tail = end + 1;
            while (tail < text.size() && digit(text[tail])) ++tail;
            if (tail - end - 1 == code.size() && (tail == text.size() || !ascii_alnum(text[tail]))) {
                code.append(text.substr(end + 1, tail - end - 1)); end = tail;
            }
        }
        const bool size = !letters ? code.size() >= 4 && code.size() <= 8 : digits && code.size() >= 6 && code.size() <= 10;
        const bool fragmented = (at > 1 && (text[at - 1] == '-' || text[at - 1] == '/' || text[at - 1] == '.') && digit(text[at - 2])) ||
            (end + 1 < text.size() && (text[end] == '-' || text[end] == '/' || text[end] == '.') && digit(text[end + 1]));
        if (size && !fragmented) {
            if (result.size() >= 4096) throw std::invalid_argument("Too many possible verification codes");
            result.push_back({at, end, std::move(code)});
        }
        at = end;
    }
    return result;
}
void scan(std::string_view input, bool subject_context, std::map<std::string, int>& found) {
    const auto normalized = normalized_text(std::string(input));
    const std::string_view text = normalized;
    const auto lower = lowered(text);
    std::vector<std::pair<std::size_t, std::size_t>> contexts;
    for (auto cue : cues) {
        for (auto at = lower.find(cue); at != lower.npos; at = lower.find(cue, at + cue.size())) {
            if (!boundary(lower, at, cue.size())) continue;
            if (contexts.size() >= 1024) throw std::invalid_argument("Too many verification contexts");
            contexts.emplace_back(at, at + cue.size());
        }
    }
    std::sort(contexts.begin(), contexts.end());
    for (const auto& candidate : candidates(text)) {
        int strength = 0;
        const auto first = std::lower_bound(contexts.begin(), contexts.end(),
            std::make_pair(candidate.start > 96 ? candidate.start - 96 : 0, std::size_t{0}));
        for (auto item = first; item != contexts.end() && item->first <= candidate.end + 64; ++item) {
            const auto [at, end] = *item;
            if (end <= candidate.start && candidate.start - end <= 64 &&
                connector(std::string(text.substr(end, candidate.start - end)))) strength = 2;
            if (candidate.end <= at && at - candidate.end <= 64) {
                // A following label describes the preceding code only on the
                // same line. Otherwise a new "Your verification code" line
                // could incorrectly promote an unrelated standalone number.
                const auto gap = text.substr(candidate.end, at - candidate.end);
                if (gap.find_first_of("\r\n") == gap.npos && connector(std::string(gap))) strength = 2;
            }
        }
        const bool year = candidate.code.size() == 4 && candidate.code >= "1900" && candidate.code <= "2099";
        if (!strength && subject_context && !year) {
            const auto start = text.rfind('\n', candidate.start), end = text.find('\n', candidate.end);
            const auto line_start = start == text.npos ? 0 : start + 1, line_end = end == text.npos ? text.size() : end;
            if (candidate.start - line_start <= 64 && line_end - candidate.end <= 64 &&
                connector(std::string(text.substr(line_start, candidate.start - line_start))) &&
                connector(std::string(text.substr(candidate.end, line_end - candidate.end)))) strength = 1;
        }
        if (strength) found[candidate.code] = std::max(found[candidate.code], strength);
    }
}
bool collect(const mime::Part& part, std::vector<std::string>& texts, std::size_t& total, std::size_t& parts, unsigned depth = 0) {
    if (++parts > 128 || depth > 12) return false;
    const auto disposition = lowered(mime::header(part, "content-disposition"));
    if (part.content_type == "message/rfc822" || disposition.starts_with("attachment") ||
        disposition.find("filename") != disposition.npos ||
        !mime::parameter(mime::header(part, "content-disposition"), "filename").empty() ||
        !mime::parameter(mime::header(part, "content-type"), "name").empty()) return true;
    if (part.content_type == "text/plain" || part.content_type == "text/html") {
        if (part.body.size() > max_text) return false;
        auto text = mime::decode_text(part);
        if (text.size() > max_text || total + text.size() > max_total) return false;
        total += text.size(); texts.push_back(part.content_type == "text/html" ? visible_html(text) : unquoted_text(text));
    }
    for (const auto& child : part.parts) if (!collect(child, texts, total, parts, depth + 1)) return false;
    return true;
}
bool phrase(std::string_view text, std::string_view cue) {
    for (auto at = text.find(cue); at != text.npos; at = text.find(cue, at + cue.size()))
        if (boundary(text, at, cue.size())) return true;
    return false;
}
bool action_context(std::string_view input) {
    const auto text = lowered(input);
    for (auto cue : {"verify your email", "verify email", "verify your account", "verify account", "email verification",
                     "confirm your email", "confirm email", "confirm your account", "confirm account", "activate your account", "activate account",
                     "reset your password", "reset password", "password reset", "sign in", "sign-in", "log in", "login link", "magic link",
                     "verification link", "confirmation link", "activation link", "验证邮箱", "验证您的邮箱", "验证电子邮件", "确认邮箱",
                     "确认您的邮箱", "验证账户", "验证账号", "激活账号", "激活账户", "重置密码", "登录链接", "验证链接", "确认链接"})
        if (phrase(text, cue)) return true;
    return false;
}
std::string trimmed(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == value.npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}
bool action_url(std::string_view value) {
    const auto scheme = value.find("://");
    const auto start = value.find_first_of("/?#", scheme + 3);
    if (start == value.npos) return false;
    const auto target = lowered(value.substr(start));
    // Inspect route/key words, never opaque token values for positive evidence.
    const auto path_end = target.find_first_of("?#");
    const auto path = std::string_view(target).substr(0, path_end);
    for (auto cue : {"verify", "verification", "confirm", "confirmation", "activate", "activation", "reset", "signin", "sign-in", "login", "magic-link"})
        if (phrase(path, cue)) return true;
    return false;
}
bool safe_link(std::string_view value) {
    if (value.size() > 2048) return false;
    const auto lower = lowered(value);
    const auto scheme = lower.starts_with("https://") ? 8u : lower.starts_with("http://") ? 7u : 0u;
    if (!scheme) return false;
    for (const unsigned char c : value) if (c <= 32 || c == 127 || c == '\\' || c == '<' || c == '>' || c == '"') return false;
    if (lower.find("%0a") != lower.npos || lower.find("%0d") != lower.npos || lower.find("%00") != lower.npos) return false;
    const auto authority_end = value.find_first_of("/?#", scheme);
    const auto authority = value.substr(scheme, authority_end == value.npos ? value.size() - scheme : authority_end - scheme);
    if (authority.empty() || authority.find('@') != authority.npos) return false;
    std::string_view host = authority, port;
    if (authority.front() == '[') {
        const auto end = authority.find(']');
        if (end == authority.npos || end < 3 || authority.substr(1, end - 1).find(':') == authority.npos) return false;
        for (const char c : authority.substr(1, end - 1)) if (!digit(c) && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') && c != ':' && c != '.') return false;
        host = authority.substr(0, end + 1);
        if (end + 1 < authority.size()) { if (authority[end + 1] != ':') return false; port = authority.substr(end + 2); if (port.empty()) return false; }
    } else {
        const auto colon = authority.find(':');
        if (colon != authority.npos) { host = authority.substr(0, colon); port = authority.substr(colon + 1); if (port.empty()) return false; }
        if (host.empty() || host.size() > 253 || host.front() == '.' || host.front() == '-' || host.back() == '-' || host.find("..") != host.npos) return false;
        for (char c : host) if (!ascii_alnum(c) && c != '-' && c != '.') return false;
    }
    if (!port.empty()) {
        unsigned number = 0;
        if (port.size() > 5) return false;
        for (const char c : port) { if (!digit(c)) return false; number = number * 10 + c - '0'; }
        if (!number || number > 65535) return false;
    }
    const auto route = std::string_view(lower).substr(0, lower.find_first_of("?#"));
    for (auto cue : {"unsubscribe", "optout", "opt-out", "preferences", "privacy", "terms", "tracking", "track", "click", "pixel", "redirect", "share", "support", "help"})
        if (phrase(route, cue)) return false;
    return true;
}
struct LinkMatch { VerificationLink link; int strength; };
void add_link(std::string url, std::string label, int strength, std::map<std::string, LinkMatch>& found) {
    url = trimmed(std::move(url)); label = trimmed(normalized_text(std::move(label)));
    if (!strength || !safe_link(url)) return;
    const auto lower_label = lowered(label);
    for (auto cue : {"unsubscribe", "privacy", "terms", "preferences", "help", "support", "取消订阅", "退订", "隐私"}) if (phrase(lower_label, cue)) return;
    // Keep the label small and on one line; the UI always displays the URL too.
    for (char& c : label) if (static_cast<unsigned char>(c) < 32) c = ' ';
    if (label.size() > 160) label.clear();
    if (found.size() >= 128) throw std::invalid_argument("Too many verification links");
    const auto previous = found.find(url);
    if (previous == found.end() || previous->second.strength < strength) found[url] = {{url, label}, strength};
}
void plain_links(std::string_view text, bool subject_context, std::map<std::string, LinkMatch>& found) {
    const auto lower = lowered(text);
    std::size_t count = 0;
    for (std::size_t at = 0; at < text.size();) {
        const auto http = lower.find("http://", at), https = lower.find("https://", at);
        at = std::min(http, https); if (at == text.npos) break;
        if (++count > 128) throw std::invalid_argument("Too many verification links");
        auto end = text.find_first_of(" \t\r\n<>\"", at); if (end == text.npos) end = text.size();
        auto url = std::string(text.substr(at, end - at));
        while (!url.empty() && std::string_view(".,;!?)\"'").find(url.back()) != std::string_view::npos) url.pop_back();
        bool punctuation = true;
        while (punctuation) {
            punctuation = false;
            for (std::string_view suffix : {"。", "，", "！", "）", "、", "”", "’"})
                if (url.ends_with(suffix)) { url.resize(url.size() - suffix.size()); punctuation = true; break; }
        }
        const auto start = at > 160 ? at - 160 : 0;
        const auto before = text.substr(start, at - start);
        const auto last_line = before.rfind('\n');
        const auto local = before.substr(last_line == before.npos ? 0 : last_line + 1);
        const bool nearby = std::count(before.begin(), before.end(), '\n') <= 3 && action_context(before);
        const int strength = action_context(local) ? 3 : nearby && action_url(url) ? 3 : subject_context && action_url(url) ? 1 : 0;
        if (at == 0 || !ascii_alnum(text[at - 1])) add_link(std::move(url), {}, strength, found);
        at = end;
    }
}
bool collect_links(const mime::Part& part, bool subject_context, std::map<std::string, LinkMatch>& found,
                   std::size_t& total, std::size_t& parts, unsigned depth = 0) {
    if (++parts > 128 || depth > 12) return false;
    const auto disposition = lowered(mime::header(part, "content-disposition"));
    if (part.content_type == "message/rfc822" || disposition.starts_with("attachment") ||
        disposition.find("filename") != disposition.npos || !mime::parameter(mime::header(part, "content-type"), "name").empty()) return true;
    if (part.content_type == "text/plain" || part.content_type == "text/html") {
        if (part.body.size() > max_text) return false;
        const auto decoded = mime::decode_text(part);
        if (decoded.size() > max_text || total + decoded.size() > max_total) return false;
        total += decoded.size();
        if (part.content_type == "text/plain") plain_links(unquoted_text(decoded, false), subject_context, found);
        else {
            std::vector<HtmlLink> links;
            const auto text = visible_html(decoded, &links);
            for (auto& link : links) {
                if (link.end > text.size()) continue; // Forwarded tail was removed.
                if (std::string_view(text).substr(link.start, link.end - link.start) != link.label) continue; // Quoted line was masked.
                const auto start = link.start > 160 ? link.start - 160 : 0;
                const auto context = std::string_view(text).substr(start, link.start - start);
                const bool nearby = std::count(context.begin(), context.end(), '\n') <= 3 && action_context(context);
                const auto label = trimmed(lowered(link.label));
                const bool generic_action = label == "verify" || label == "verify now" || label == "confirm" || label == "activate" || label == "验证" || label == "立即验证";
                const int strength = action_context(label) ? 3 : generic_action && (subject_context || nearby || action_url(link.url)) ? 3 :
                    (subject_context || nearby) && action_url(link.url) ? 1 : 0;
                add_link(std::move(link.url), std::move(link.label), strength, found);
            }
            // Visible absolute URLs are useful in HTML without anchors too.
            plain_links(text, subject_context, found);
        }
    }
    for (const auto& child : part.parts) if (!collect_links(child, subject_context, found, total, parts, depth + 1)) return false;
    return true;
}
}
std::optional<VerificationCode> extract_verification_code(const mime::Part& message) {
    try {
        const auto subject = unquoted_text(mime::decode_header(mime::header(message, "subject")));
        const auto lower_subject = lowered(subject);
        if (lower_subject.starts_with("fwd:") || lower_subject.starts_with("fw:") || lower_subject.starts_with("转发:") || lower_subject.starts_with("转发：")) return std::nullopt;
        if (subject.size() > 4096) return std::nullopt;
        std::vector<std::string> texts; std::size_t total = 0, parts = 0;
        if (!collect(message, texts, total, parts)) return std::nullopt;
        std::map<std::string, int> found;
        const bool context = has_context(lower_subject);
        scan(subject, false, found);
        for (const auto& text : texts) scan(text, context, found);
        int best = 0; std::optional<VerificationCode> result;
        for (const auto& [code, strength] : found) {
            if (strength > best) { best = strength; result = VerificationCode{code}; }
            else if (strength == best) result = std::nullopt;
        }
        return result;
    } catch (const std::exception&) { return std::nullopt; }
}
std::optional<VerificationCode> extract_verification_code(std::string_view raw) {
    try { return extract_verification_code(mime::parse(raw, {10485760, 128, 12, 128})); }
    catch (const std::exception&) { return std::nullopt; }
}
std::optional<VerificationLink> extract_verification_link(const mime::Part& message) {
    try {
        const auto subject = lowered(mime::decode_header(mime::header(message, "subject")));
        if (subject.size() > 4096 || subject.starts_with("fwd:") || subject.starts_with("fw:") || subject.starts_with("转发:") || subject.starts_with("转发：")) return std::nullopt;
        std::map<std::string, LinkMatch> found; std::size_t total = 0, parts = 0;
        if (!collect_links(message, action_context(subject), found, total, parts)) return std::nullopt;
        int best = 0; std::optional<VerificationLink> result;
        for (const auto& [url, candidate] : found) {
            if (candidate.strength > best) { best = candidate.strength; result = candidate.link; }
            else if (candidate.strength == best) result = std::nullopt;
        }
        return result;
    } catch (const std::exception&) { return std::nullopt; }
}
std::optional<VerificationLink> extract_verification_link(std::string_view raw) {
    try { return extract_verification_link(mime::parse(raw, {10485760, 128, 12, 128})); }
    catch (const std::exception&) { return std::nullopt; }
}
}
