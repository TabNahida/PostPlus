#include <postplus/remote_image.hpp>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <condition_variable>
#include <mutex>

namespace postplus {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::size_t maximum = 2 * 1024 * 1024;
[[noreturn]] void invalid() { throw RemoteImageError("Remote image is unavailable or unsafe."); }
struct Url { std::string scheme, host, target; int port; };
Url parse_url(const std::string& input) {
    if (input.empty() || input.size() > 4096 || input.find_first_of("\\#") != input.npos ||
        std::any_of(input.begin(), input.end(), [](unsigned char ch) { return ch <= 32 || ch >= 127; })) invalid();
    const auto separator = input.find("://");
    if (separator == input.npos) invalid();
    Url result; result.scheme = lower(input.substr(0, separator));
    if (result.scheme != "http" && result.scheme != "https") invalid();
    result.port = result.scheme == "https" ? 443 : 80;
    const auto start = separator + 3, end = input.find_first_of("/?", start);
    auto authority = input.substr(start, end - start);
    const auto colon = authority.find(':');
    if (colon != authority.npos) {
        if (authority.substr(colon + 1) != std::to_string(result.port)) invalid();
        authority.resize(colon);
    }
    result.host = lower(authority);
    std::error_code error; (void)ip::make_address(result.host, error);
    if (!error || !valid_public_dns_name(result.host) || result.host.find('.') == result.host.npos ||
        result.host.ends_with(".localhost") || result.host.ends_with(".local") || result.host.ends_with(".internal")) invalid();
    result.target = end == input.npos ? "/" : input.substr(end);
    if (result.target.front() == '?') result.target.insert(0, "/");
    return result;
}
std::string entity_decode(std::string_view input) {
    std::string result;
    for (std::size_t at = 0; at < input.size();) {
        if (input[at] != '&') { result += input[at++]; continue; }
        const auto end = input.find(';', at + 1);
        if (end == input.npos || end - at > 12) { result += input[at++]; continue; }
        const auto name = input.substr(at + 1, end - at - 1); char decoded = 0;
        if (name == "amp") decoded = '&'; else if (name == "quot") decoded = '"';
        else if (name == "apos") decoded = '\''; else if (name == "lt") decoded = '<';
        else if (name == "gt") decoded = '>'; else if (name == "colon") decoded = ':';
        else if (name.starts_with("#")) {
            auto digits = name.substr(1); int base = 10;
            if (digits.starts_with("x") || digits.starts_with("X")) { base = 16; digits.remove_prefix(1); }
            unsigned value = 0; const auto [last, issue] = std::from_chars(digits.data(), digits.data() + digits.size(), value, base);
            if (!digits.empty() && issue == std::errc{} && last == digits.data() + digits.size() && value > 0 && value < 128) decoded = static_cast<char>(value);
        }
        if (decoded) { result += decoded; at = end + 1; } else result += input[at++];
    }
    return result;
}
bool whitespace(char ch) { return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f'; }
std::vector<ip::address> addresses(const Url& url, const DnsResolver& resolver, Clock::time_point deadline) {
    std::vector<ip::address> result;
    for (const auto type : {DnsType::a, DnsType::aaaa}) {
        try {
            const auto answer = resolver.lookup(url.host, type, deadline);
            for (const auto& value : answer.values) {
                std::error_code error; const auto address = ip::make_address(value, error);
                if (error || !is_public_mail_address(address)) continue;
                if (std::find(result.begin(), result.end(), address) == result.end() && result.size() < 16) result.push_back(address);
            }
        } catch (const DnsError&) { /* A valid address from the other family is usable. */ }
    }
    if (result.empty()) invalid();
    return result;
}
struct Response { int status; std::map<std::string, std::string> headers; std::string body; };
std::size_t number(const std::string& text, int base = 10) {
    std::size_t value = 0; const auto [last, issue] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (text.empty() || issue != std::errc{} || last != text.data() + text.size()) invalid();
    return value;
}
Response read_response(Connection& peer) {
    const auto status = peer.line(4096);
    if ((!status.starts_with("HTTP/1.1 ") && !status.starts_with("HTTP/1.0 ")) || status.size() < 12 ||
        (status.size() > 12 && status[12] != ' ')) invalid();
    const auto code = number(status.substr(9, 3));
    if (code < 200 || code > 599) invalid();
    Response result{static_cast<int>(code), {}, {}}; std::size_t header_bytes = 0; bool complete = false;
    for (unsigned index = 0; index < 100; ++index) {
        const auto header = peer.line(8192); if (header.empty()) { complete = true; break; }
        header_bytes += header.size(); const auto colon = header.find(':');
        if (header_bytes > 32768 || colon == header.npos || !colon) invalid();
        const auto name = lower(header.substr(0, colon)), value = trim(header.substr(colon + 1));
        if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-_!#$%&'*+.^`|~") != name.npos ||
            std::any_of(value.begin(), value.end(), [](unsigned char ch) { return (ch < 32 && ch != '\t') || ch == 127; })) invalid();
        if (result.headers.contains(name)) {
            if (name == "content-type" || name == "content-length" || name == "transfer-encoding" || name == "content-encoding" || name == "location") invalid();
        } else result.headers[name] = value;
    }
    if (!complete) invalid();
    if (result.status != 200) return result;
    if (result.headers.contains("content-encoding") && lower(result.headers.at("content-encoding")) != "identity") invalid();
    if (result.headers.contains("transfer-encoding")) {
        if (result.headers.contains("content-length") || lower(result.headers.at("transfer-encoding")) != "chunked") invalid();
        for (unsigned index = 0; index < 32768; ++index) {
            const auto line = peer.line(1024); const auto size = number(line.substr(0, line.find(';')), 16);
            if (size > maximum - result.body.size()) invalid();
            if (!size) {
                std::size_t trailer_bytes = 0;
                for (unsigned trailer = 0; trailer < 32; ++trailer) {
                    const auto value = peer.line(8192); trailer_bytes += value.size();
                    if (trailer_bytes > 32768) invalid();
                    if (value.empty()) return result;
                }
                invalid();
            }
            result.body += peer.read(size); if (peer.read(2) != "\r\n") invalid();
        }
        invalid();
    }
    if (!result.headers.contains("content-length")) invalid();
    const auto size = number(result.headers.at("content-length")); if (size > maximum) invalid();
    result.body = peer.read(size); return result;
}
bool signature(std::string_view type, std::string_view data) {
    if (type == "image/png") return data.starts_with(std::string_view("\x89PNG\r\n\x1a\n", 8));
    if (type == "image/jpeg") return data.starts_with(std::string_view("\xff\xd8\xff", 3));
    if (type == "image/gif") return data.starts_with("GIF87a") || data.starts_with("GIF89a");
    return type == "image/webp" && data.size() >= 12 && data.starts_with("RIFF") && data.substr(8, 4) == "WEBP";
}
}
std::vector<std::string> extract_remote_image_urls(std::string_view input) {
    input = input.substr(0, 2 * 1024 * 1024);
    std::vector<std::string> result; std::size_t at = 0;
    while (at < input.size() && result.size() < 64) {
        at = input.find('<', at); if (at == input.npos) break;
        if (input.substr(at, 4) == "<!--") { const auto end = input.find("-->", at + 4); if (end == input.npos) break; at = end + 3; continue; }
        auto start = ++at;
        while (at < input.size() && std::isalnum(static_cast<unsigned char>(input[at]))) ++at;
        const auto tag = lower(std::string(input.substr(start, at - start)));
        const bool tag_delimited = at < input.size() && (whitespace(input[at]) || input[at] == '/' || input[at] == '>');
        const auto attributes = at; char quote = 0;
        while (at < input.size()) {
            const auto ch = input[at++];
            if (quote) { if (ch == quote) quote = 0; }
            else if (ch == '\'' || ch == '"') quote = ch;
            else if (ch == '>') break;
        }
        if (at == input.size() && (input.empty() || input.back() != '>')) break;
        if (tag_delimited && (tag == "script" || tag == "style" || tag == "textarea" || tag == "title" || tag == "noscript" || tag == "template")) {
            const auto closing = "</" + tag;
            const auto found = std::search(input.begin() + static_cast<std::ptrdiff_t>(at), input.end(), closing.begin(), closing.end(),
                [](unsigned char first, unsigned char second) { return std::tolower(first) == second; });
            if (found == input.end()) break;
            at = static_cast<std::size_t>(found - input.begin()); continue;
        }
        if (tag != "img" || !tag_delimited) continue;
        auto cursor = attributes; const auto limit = at - 1; bool had_src = false;
        while (cursor < limit) {
            while (cursor < limit && (whitespace(input[cursor]) || input[cursor] == '/')) ++cursor;
            start = cursor;
            while (cursor < limit && !whitespace(input[cursor]) && input[cursor] != '=' && input[cursor] != '/') ++cursor;
            if (start == cursor) { ++cursor; continue; }
            const auto name = lower(std::string(input.substr(start, cursor - start)));
            while (cursor < limit && whitespace(input[cursor])) ++cursor;
            if (cursor == limit || input[cursor] != '=') continue;
            ++cursor; while (cursor < limit && whitespace(input[cursor])) ++cursor;
            std::string_view value;
            if (cursor < limit && (input[cursor] == '\'' || input[cursor] == '"')) {
                const auto delimiter = input[cursor++]; start = cursor;
                while (cursor < limit && input[cursor] != delimiter) ++cursor;
                value = input.substr(start, cursor - start); if (cursor < limit) ++cursor;
            } else { start = cursor; while (cursor < limit && !whitespace(input[cursor])) ++cursor; value = input.substr(start, cursor - start); }
            if (name != "src" || had_src) continue;
            had_src = true;
            try { auto url = entity_decode(trim(std::string(value))); (void)parse_url(url);
                if (std::find(result.begin(), result.end(), url) == result.end()) result.push_back(std::move(url));
            } catch (const RemoteImageError&) {}
        }
    }
    return result;
}
RemoteImage fetch_remote_image(const std::string& original, RemoteImageOptions options) {
    static std::mutex slots_mutex;
    static std::condition_variable slots_available;
    static unsigned active = 0;
    const auto deadline = Clock::now() + std::chrono::seconds(10);
    std::unique_lock lock(slots_mutex);
    if (!slots_available.wait_until(lock, deadline, [] { return active < 4; })) invalid();
    ++active; lock.unlock();
    struct Release {
        std::mutex& mutex;
        std::condition_variable& available;
        unsigned& count;
        ~Release() { { std::lock_guard guard(mutex); --count; } available.notify_one(); }
    } release{slots_mutex, slots_available, active};
    try {
        options.dns.timeout = std::chrono::seconds(3); const DnsResolver resolver(options.dns);
        const auto address = parse_url(original);
        const auto endpoints = addresses(address, resolver, deadline); std::optional<Response> response;
        for (const auto& endpoint : endpoints) {
            try {
                Connection peer(std::chrono::seconds(3)); peer.set_deadline(deadline);
                if (options.connect) options.connect(peer, {endpoint, static_cast<unsigned short>(address.port)}, address.host, address.scheme == "https");
                else { peer.connect({endpoint, static_cast<unsigned short>(address.port)}); if (address.scheme == "https") peer.start_tls_client(address.host); }
                peer.write("GET " + address.target + " HTTP/1.1\r\nHost: " + address.host +
                    "\r\nUser-Agent: PostPlus-MailImages/1\r\nAccept: image/png, image/jpeg, image/gif, image/webp\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
                response = read_response(peer); break;
            } catch (const std::exception&) { if (Clock::now() >= deadline) invalid(); }
        }
        if (!response) invalid();
        if (response->status == 200) {
            const auto found = response->headers.find("content-type"); if (found == response->headers.end()) invalid();
            const auto type = lower(trim(found->second.substr(0, found->second.find(';'))));
            if (!signature(type, response->body)) invalid();
            return {type, std::move(response->body)};
        }
        invalid();
    } catch (const RemoteImageError&) { throw; }
    catch (const std::exception&) { invalid(); }
}
}
