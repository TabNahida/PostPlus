#include "postplus/mime.hpp"
#include "postplus/core.hpp"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace postplus::mime {
namespace {
[[noreturn]] void invalid(const char* why) { throw std::invalid_argument(why); }
int hex(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
std::string qp(std::string_view in, bool word = false) {
    std::string out; out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (word && in[i] == '_') { out += ' '; continue; }
        if (in[i] != '=') { out += in[i]; continue; }
        if (!word && i + 1 < in.size() && in[i + 1] == '\n') { ++i; continue; }
        if (!word && i + 2 < in.size() && in[i + 1] == '\r' && in[i + 2] == '\n') { i += 2; continue; }
        if (i + 2 >= in.size() || hex(in[i + 1]) < 0 || hex(in[i + 2]) < 0) invalid("Malformed quoted-printable data");
        out += static_cast<char>(hex(in[i + 1]) * 16 + hex(in[i + 2])); i += 2;
    }
    return out;
}
std::string decode64(std::string_view in) {
    std::string compact; compact.reserve(in.size());
    for (unsigned char c : in) if (c != ' ' && c != '\t' && c != '\r' && c != '\n') compact += static_cast<char>(c);
    return base64_decode(compact);
}
std::string parameter(std::string_view value, std::string_view name) {
    std::string found; bool present = false;
    auto at = value.find(';');
    while (at != std::string::npos) {
        ++at; while (at < value.size() && (value[at] == ' ' || value[at] == '\t')) ++at;
        auto eq = value.find('=', at); if (eq == std::string::npos) break;
        auto key = lower(trim(std::string(value.substr(at, eq - at)))); at = eq + 1;
        while (at < value.size() && (value[at] == ' ' || value[at] == '\t')) ++at;
        std::string val;
        if (at < value.size() && value[at] == '"') {
            ++at; bool closed = false;
            for (; at < value.size(); ++at) {
                if (value[at] == '"') { ++at; closed = true; break; }
                if (value[at] == '\\') { if (++at == value.size()) invalid("Malformed MIME parameter"); }
                val += value[at];
            }
            if (!closed) invalid("Unclosed MIME parameter");
            auto tail = at; while (tail < value.size() && (value[tail] == ' ' || value[tail] == '\t')) ++tail;
            if (tail < value.size() && value[tail] != ';') invalid("Malformed MIME parameter suffix");
        } else {
            auto end = value.find(';', at); val = trim(std::string(value.substr(at, end - at))); at = end;
        }
        if (key == name) {
            if (present) invalid("Ambiguous duplicate MIME parameter");
            found = std::move(val); present = true;
        }
        at = value.find(';', at);
    }
    return found;
}
struct Parser {
    Limits limits;
    std::size_t part_count = 0, decoded_bytes = 0;
    Part parse_part(std::string_view raw, std::size_t depth) {
        if (depth > limits.max_depth || ++part_count > limits.max_parts) invalid("MIME nesting or part limit exceeded");
        Part out; std::size_t offset = 0, header_bytes = 0; bool end_headers = false;
        while (offset < raw.size()) {
            auto end = raw.find('\n', offset); if (end == std::string::npos) end = raw.size();
            auto line = raw.substr(offset, end - offset); if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            offset = end == raw.size() ? end : end + 1;
            header_bytes += line.size() + 2;
            if (header_bytes > 65536) invalid("MIME headers too large");
            if (line.empty()) { end_headers = true; break; }
            if (line.find('\0') != std::string_view::npos || line.find('\r') != std::string_view::npos) invalid("Invalid MIME header control byte");
            if (line.front() == ' ' || line.front() == '\t') {
                if (out.headers.empty()) invalid("Orphan MIME header continuation");
                out.headers.back().second += " " + trim(std::string(line)); continue;
            }
            auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0) invalid("Malformed MIME header");
            for (unsigned char ch : line.substr(0, colon)) if (ch <= 32 || ch >= 127 || ch == ':') invalid("Invalid MIME header name");
            if (out.headers.size() >= limits.max_headers) invalid("Too many MIME headers");
            auto name = lower(std::string(line.substr(0, colon)));
            if ((name == "content-type" || name == "content-transfer-encoding") &&
                std::any_of(out.headers.begin(), out.headers.end(), [&](const auto& field) { return field.first == name; })) invalid("Ambiguous duplicate MIME header");
            out.headers.emplace_back(std::move(name), trim(std::string(line.substr(colon + 1))));
        }
        auto body = end_headers ? raw.substr(offset) : std::string_view{};
        auto content_type = header(out, "content-type");
        out.content_type = content_type.empty() ? "text/plain" : lower(trim(content_type.substr(0, content_type.find(';'))));
        auto encoding = lower(trim(header(out, "content-transfer-encoding")));
        if (out.content_type.rfind("multipart/", 0) == 0) {
            if (!encoding.empty() && encoding != "7bit" && encoding != "8bit" && encoding != "binary") invalid("Encoded multipart is invalid");
            auto boundary = parameter(content_type, "boundary");
            if (boundary.empty() || boundary.size() > 70 || boundary.find_first_of("\r\n") != std::string::npos) invalid("Invalid multipart boundary");
            std::string marker = "--" + boundary;
            std::size_t pos = 0, start = std::string_view::npos; bool closed = false;
            while (pos <= body.size()) {
                auto end = body.find('\n', pos); if (end == std::string_view::npos) end = body.size();
                auto line = body.substr(pos, end - pos);
                while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.remove_suffix(1);
                bool opening = line == marker, closing = line == marker + "--";
                if (opening || closing) {
                    if (start != std::string_view::npos) {
                        auto part_end = pos;
                        if (part_end > start && body[part_end - 1] == '\n') --part_end;
                        if (part_end > start && body[part_end - 1] == '\r') --part_end;
                        out.parts.push_back(parse_part(body.substr(start, part_end - start), depth + 1));
                    }
                    if (closing) { closed = true; break; }
                    start = end == body.size() ? end : end + 1;
                }
                if (end == body.size()) break;
                pos = end + 1;
            }
            if (!closed || out.parts.empty()) invalid("Incomplete MIME multipart");
            return out;
        }
        std::string decoded;
        if (encoding == "base64") decoded = decode64(body);
        else if (encoding == "quoted-printable") decoded = qp(body);
        else if (encoding.empty() || encoding == "7bit" || encoding == "8bit" || encoding == "binary") decoded = std::string(body);
        else invalid("Unsupported MIME content transfer encoding");
        if (decoded.size() > limits.max_bytes - std::min(limits.max_bytes, decoded_bytes)) invalid("Decoded MIME size limit exceeded");
        decoded_bytes += decoded.size();
        if (out.content_type == "message/rfc822") out.parts.push_back(parse_part(decoded, depth + 1));
        else out.body = std::move(decoded);
        return out;
    }
};
}
Part parse(std::string_view raw, Limits limits) {
    if (raw.size() > limits.max_bytes) invalid("MIME input size limit exceeded");
    return Parser{limits}.parse_part(raw, 0);
}
std::string header(const Part& part, std::string_view name) {
    auto wanted = lower(std::string(name));
    for (const auto& [key, value] : part.headers) if (key == wanted) return value;
    return "";
}
std::string decode_header(std::string_view value) {
    std::string out; std::size_t pos = 0; bool previous_encoded = false;
    while (pos < value.size()) {
        auto start = value.find("=?", pos);
        if (start == std::string_view::npos) { out += value.substr(pos); break; }
        auto charset_end = value.find('?', start + 2);
        auto payload = charset_end == std::string_view::npos ? charset_end : value.find('?', charset_end + 1);
        auto end = payload == std::string_view::npos ? payload : value.find("?=", payload + 1);
        if (end == std::string_view::npos || payload != charset_end + 2 || charset_end == start + 2) { out += value.substr(pos, start + 2 - pos); pos = start + 2; previous_encoded = false; continue; }
        auto gap = value.substr(pos, start - pos);
        bool whitespace = std::all_of(gap.begin(), gap.end(), [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
        auto mode = static_cast<char>(std::tolower(static_cast<unsigned char>(value[charset_end + 1])));
        try {
            std::string decoded;
            if (mode == 'b') decoded = decode64(value.substr(payload + 1, end - payload - 1));
            else if (mode == 'q') decoded = qp(value.substr(payload + 1, end - payload - 1), true);
            else throw std::invalid_argument("Unknown encoded word encoding");
            if (!previous_encoded || !whitespace) out += gap;
            out += decoded; previous_encoded = true; pos = end + 2;
        } catch (...) { out += value.substr(pos, end + 2 - pos); pos = end + 2; previous_encoded = false; }
    }
    return out;
}
std::string compose(const std::string& from, const std::vector<std::string>& to, const std::string& subject, const std::string& text) {
    if (!valid_address(from) || to.empty() || to.size() > 100) invalid("Invalid message addresses");
    if (subject.size() > 998 || subject.find_first_of("\r\n\0", 0, 3) != std::string::npos) invalid("Invalid message subject");
    std::string raw = "From: " + from + "\r\nTo: ";
    for (std::size_t i = 0; i < to.size(); ++i) {
        if (!valid_address(to[i])) invalid("Invalid recipient");
        if (i) raw += ",\r\n ";
        raw += to[i];
    }
    std::time_t now = std::time(nullptr); std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    std::ostringstream date; date.imbue(std::locale::classic()); date << std::put_time(&utc, "%a, %d %b %Y %H:%M:%S +0000");
    raw += "\r\nDate: " + date.str() + "\r\nMessage-ID: <" + random_hex() + "@" + from.substr(from.find('@') + 1) + ">\r\nSubject: ";
    for (std::size_t offset = 0; offset < subject.size();) {
        auto count = std::min<std::size_t>(42, subject.size() - offset);
        while (count > 0 && offset + count < subject.size() && (static_cast<unsigned char>(subject[offset + count]) & 0xc0) == 0x80) --count;
        if (count == 0) invalid("Malformed UTF-8 subject");
        if (offset) raw += "\r\n ";
        raw += "=?UTF-8?B?" + base64_encode(std::string_view(subject).substr(offset, count)) + "?="; offset += count;
    }
    raw += "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
    auto encoded = base64_encode(text);
    for (std::size_t offset = 0; offset < encoded.size(); offset += 76) raw += encoded.substr(offset, 76) + "\r\n";
    return raw;
}
}
