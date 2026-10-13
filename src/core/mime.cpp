#include "postplus/mime.hpp"
#include "postplus/core.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <locale>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#else
#include <iconv.h>
#endif

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
std::string parse_parameter(std::string_view value, std::string_view name) {
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
// Rendering has its own bound even when a caller constructs Part directly.
// Every supported encoding expands by at most four bytes per input byte.
constexpr std::size_t max_display_bytes = 64 * 1024 * 1024;
void check_text_size(std::string_view input) {
    if (input.size() > max_display_bytes / 4) invalid("MIME display text too large");
}
void append_display(std::string& out, std::string_view value) {
    if (value.size() > max_display_bytes - out.size()) invalid("MIME display text too large");
    out.append(value);
}
void append_scalar(std::string& out, std::uint32_t cp) {
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) cp = 0xfffd;
    char bytes[4]; std::size_t count = 0;
    if (cp < 0x80) bytes[count++] = static_cast<char>(cp);
    else if (cp < 0x800) {
        bytes[count++] = static_cast<char>(0xc0 | (cp >> 6));
        bytes[count++] = static_cast<char>(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
        bytes[count++] = static_cast<char>(0xe0 | (cp >> 12));
        bytes[count++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        bytes[count++] = static_cast<char>(0x80 | (cp & 0x3f));
    } else {
        bytes[count++] = static_cast<char>(0xf0 | (cp >> 18));
        bytes[count++] = static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
        bytes[count++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        bytes[count++] = static_cast<char>(0x80 | (cp & 0x3f));
    }
    append_display(out, std::string_view(bytes, count));
}
std::size_t utf8_sequence(std::string_view input, std::size_t at) {
    auto byte = [&](std::size_t i) { return static_cast<unsigned char>(input[i]); };
    const auto first = byte(at);
    if (first < 0x80) return 1;
    const std::size_t count = first >= 0xc2 && first <= 0xdf ? 2 :
        first >= 0xe0 && first <= 0xef ? 3 : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
    if (!count || count > input.size() - at) return 0;
    for (std::size_t i = 1; i < count; ++i) if ((byte(at + i) & 0xc0) != 0x80) return 0;
    if ((first == 0xe0 && byte(at + 1) < 0xa0) || (first == 0xed && byte(at + 1) >= 0xa0) ||
        (first == 0xf0 && byte(at + 1) < 0x90) || (first == 0xf4 && byte(at + 1) >= 0x90)) return 0;
    return count;
}
bool valid_utf8(std::string_view input) {
    for (std::size_t at = 0; at < input.size();) {
        auto count = utf8_sequence(input, at); if (!count) return false; at += count;
    }
    return true;
}
std::string utf8_text(std::string_view input) {
    if (input.starts_with("\xef\xbb\xbf")) input.remove_prefix(3);
    std::string out; out.reserve(input.size());
    for (std::size_t at = 0; at < input.size();) {
        auto count = utf8_sequence(input, at);
        if (count) { append_display(out, input.substr(at, count)); at += count; }
        else { append_scalar(out, 0xfffd); ++at; }
    }
    return out;
}
std::string single_byte_text(std::string_view input, bool windows1252) {
    constexpr std::array<std::uint32_t, 32> c1 = {
        0x20ac, 0xfffd, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
        0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0xfffd, 0x017d, 0xfffd,
        0xfffd, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
        0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0xfffd, 0x017e, 0x0178
    };
    std::string out; out.reserve(input.size());
    for (unsigned char ch : input) append_scalar(out, windows1252 && ch >= 0x80 && ch <= 0x9f ? c1[ch - 0x80] : ch);
    return out;
}
// Preserve undeclared UTF-8, otherwise use the common Western mail encoding.
// This deterministic fallback never tries to infer a Chinese charset.
std::string display_fallback(std::string_view input) {
    return valid_utf8(input) ? utf8_text(input) : single_byte_text(input, true);
}
std::string utf16_text(std::string_view input, bool little) {
    std::size_t at = 0;
    if (input.starts_with("\xff\xfe")) { little = true; at = 2; }
    else if (input.starts_with("\xfe\xff")) { little = false; at = 2; }
    auto unit = [&](std::size_t i) {
        auto a = static_cast<unsigned char>(input[i]), b = static_cast<unsigned char>(input[i + 1]);
        return static_cast<std::uint32_t>(little ? a | (b << 8) : (a << 8) | b);
    };
    std::string out; out.reserve(input.size());
    while (input.size() - at >= 2) {
        auto cp = unit(at); at += 2;
        if (cp >= 0xd800 && cp <= 0xdbff && input.size() - at >= 2) {
            auto next = unit(at);
            if (next >= 0xdc00 && next <= 0xdfff) { cp = 0x10000 + ((cp - 0xd800) << 10) + next - 0xdc00; at += 2; }
        }
        append_scalar(out, cp);
    }
    if (at != input.size()) append_scalar(out, 0xfffd);
    return out;
}
std::string utf32_text(std::string_view input, bool little) {
    std::size_t at = 0;
    if (input.size() >= 4 && input.substr(0, 4) == std::string_view("\xff\xfe\0\0", 4)) { little = true; at = 4; }
    else if (input.size() >= 4 && input.substr(0, 4) == std::string_view("\0\0\xfe\xff", 4)) { little = false; at = 4; }
    std::string out; out.reserve(input.size());
    while (input.size() - at >= 4) {
        std::uint32_t cp = 0;
        for (std::size_t i = 0; i < 4; ++i) cp = (cp << 8) | static_cast<unsigned char>(input[at + (little ? 3 - i : i)]);
        append_scalar(out, cp); at += 4;
    }
    if (at != input.size()) append_scalar(out, 0xfffd);
    return out;
}
enum class TextEncoding { unknown, utf8, ascii, latin1, windows1252, utf16le, utf16be, utf32le, utf32be, system };
struct Charset { TextEncoding encoding = TextEncoding::unknown; const char* name = ""; unsigned int codepage = 0; };
Charset charset_info(std::string_view label) {
    std::string key;
    if (label.size() > 80) return {};
    for (unsigned char ch : trim(std::string(label))) {
        if (ch == '-' || ch == '_') continue;
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))) return {};
        key += static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
    }
    if (key == "utf8" || key == "unicode11utf8") return {TextEncoding::utf8};
    if (key == "usascii" || key == "ascii") return {TextEncoding::ascii};
    if (key == "iso88591" || key == "latin1" || key == "l1" || key == "cp819" || key == "ibm819") return {TextEncoding::latin1};
    if (key == "windows1252" || key == "cp1252") return {TextEncoding::windows1252};
    if (key == "utf16le" || key == "unicode") return {TextEncoding::utf16le};
    if (key == "utf16be" || key == "utf16") return {TextEncoding::utf16be};
    if (key == "utf32le") return {TextEncoding::utf32le};
    if (key == "utf32be" || key == "utf32") return {TextEncoding::utf32be};
    struct Entry { const char* key; const char* name; unsigned int codepage; };
    constexpr Entry entries[] = {
        {"gb2312", "GBK", 936}, {"gb231280", "GBK", 936}, {"gbk", "GBK", 936}, {"cp936", "GBK", 936},
        {"gb18030", "GB18030", 54936}, {"big5", "BIG5", 950}, {"csbig5", "BIG5", 950}, {"cp950", "BIG5", 950},
        {"windows1250", "WINDOWS-1250", 1250}, {"cp1250", "WINDOWS-1250", 1250},
        {"windows1251", "WINDOWS-1251", 1251}, {"cp1251", "WINDOWS-1251", 1251},
        {"windows1253", "WINDOWS-1253", 1253}, {"cp1253", "WINDOWS-1253", 1253},
        {"windows1254", "WINDOWS-1254", 1254}, {"cp1254", "WINDOWS-1254", 1254},
        {"windows1255", "WINDOWS-1255", 1255}, {"cp1255", "WINDOWS-1255", 1255},
        {"windows1256", "WINDOWS-1256", 1256}, {"cp1256", "WINDOWS-1256", 1256},
        {"windows1257", "WINDOWS-1257", 1257}, {"cp1257", "WINDOWS-1257", 1257},
        {"windows1258", "WINDOWS-1258", 1258}, {"cp1258", "WINDOWS-1258", 1258},
        {"iso88592", "ISO-8859-2", 28592}, {"latin2", "ISO-8859-2", 28592},
        {"iso88593", "ISO-8859-3", 28593}, {"latin3", "ISO-8859-3", 28593},
        {"iso88594", "ISO-8859-4", 28594}, {"latin4", "ISO-8859-4", 28594},
        {"iso88595", "ISO-8859-5", 28595}, {"iso88596", "ISO-8859-6", 28596},
        {"iso88597", "ISO-8859-7", 28597}, {"iso88598", "ISO-8859-8", 28598},
        {"iso88599", "ISO-8859-9", 28599}, {"latin5", "ISO-8859-9", 28599},
        {"iso885913", "ISO-8859-13", 28603}, {"iso885915", "ISO-8859-15", 28605}, {"latin9", "ISO-8859-15", 28605},
        {"shiftjis", "SHIFT_JIS", 932}, {"sjis", "SHIFT_JIS", 932}, {"cp932", "CP932", 932},
        {"eucjp", "EUC-JP", 51932}, {"euckr", "EUC-KR", 51949}, {"iso2022jp", "ISO-2022-JP", 50220}
    };
    for (const auto& entry : entries) if (key == entry.key) return {TextEncoding::system, entry.name, entry.codepage};
    return {};
}
std::string system_text(std::string_view input, const Charset& charset) {
    if (input.empty()) return {};
#ifdef _WIN32
    const auto count = static_cast<int>(input.size()); // checked by convert_text
    // NLS silently substitutes '?' for malformed GBK with flags=0. Request
    // strict conversion, then recover valid sequences and use U+FFFD instead.
    // Stateful ISO-2022-JP is the only supported codepage requiring flags=0.
    const DWORD flags = charset.codepage == 50220 ? 0 : MB_ERR_INVALID_CHARS;
    const int converted_count = MultiByteToWideChar(charset.codepage, flags, input.data(), count, nullptr, 0);
    const auto conversion_error = GetLastError();
    std::wstring wide;
    if (converted_count > 0) {
        wide.resize(static_cast<std::size_t>(converted_count));
        if (MultiByteToWideChar(charset.codepage, flags, input.data(), count, wide.data(), converted_count) != converted_count) return display_fallback(input);
    } else {
        if (conversion_error != ERROR_NO_UNICODE_TRANSLATION) return display_fallback(input);
        wide.reserve(input.size()); std::size_t at = 0;
        while (at < input.size()) {
            // Good blocks stay fast even if a different block has bad bytes.
            // Trimming at most three bytes handles a split four-byte character.
            const auto block_size = std::min<std::size_t>(4096, input.size() - at);
            const auto block_end = at + block_size;
            wchar_t buffer[4096]; bool converted = false;
            for (std::size_t tail = 0; tail < std::min<std::size_t>(4, block_size); ++tail) {
                const auto bytes = static_cast<int>(block_size - tail);
                const int units = MultiByteToWideChar(charset.codepage, flags, input.data() + at, bytes, buffer, 4096);
                if (units > 0) { wide.append(buffer, static_cast<std::size_t>(units)); at += static_cast<std::size_t>(bytes); converted = true; break; }
            }
            if (converted) continue;
            while (at < block_end) {
                if (static_cast<unsigned char>(input[at]) < 0x80) { wide += static_cast<wchar_t>(input[at++]); continue; }
                converted = false;
                for (std::size_t bytes = 1; bytes <= std::min<std::size_t>(4, input.size() - at); ++bytes) {
                    const int units = MultiByteToWideChar(charset.codepage, flags, input.data() + at, static_cast<int>(bytes), buffer, 4);
                    if (units > 0) { wide.append(buffer, static_cast<std::size_t>(units)); at += bytes; converted = true; break; }
                }
                if (!converted) { wide += static_cast<wchar_t>(0xfffd); ++at; }
            }
        }
    }
    const int wide_count = static_cast<int>(wide.size());
    const int utf8_count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), wide_count, nullptr, 0, nullptr, nullptr);
    if (utf8_count <= 0) return display_fallback(input);
    if (static_cast<std::size_t>(utf8_count) > max_display_bytes) invalid("MIME display text too large");
    std::string out(static_cast<std::size_t>(utf8_count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), wide_count, out.data(), utf8_count, nullptr, nullptr) != utf8_count) return display_fallback(input);
    return out;
#else
    const auto descriptor = iconv_open("UTF-8", charset.name);
    if (descriptor == reinterpret_cast<iconv_t>(-1)) return display_fallback(input);
    struct CloseIconv { iconv_t value; ~CloseIconv() { iconv_close(value); } } close{descriptor};
    char* source = const_cast<char*>(input.data()); std::size_t remaining = input.size();
    std::string out; out.reserve(input.size());
    while (remaining) {
        char buffer[4096]; char* destination = buffer; std::size_t available = sizeof(buffer);
        const auto result = iconv(descriptor, &source, &remaining, &destination, &available);
        const auto error = errno;
        append_display(out, std::string_view(buffer, sizeof(buffer) - available));
        if (result != static_cast<std::size_t>(-1)) continue;
        if (error == E2BIG) continue;
        if (error != EILSEQ && error != EINVAL) return display_fallback(input);
        append_scalar(out, 0xfffd);
        ++source; --remaining;
        iconv(descriptor, nullptr, nullptr, nullptr, nullptr);
    }
    return out;
#endif
}
std::string convert_text(std::string_view input, std::string_view label) {
    check_text_size(input);
    const auto charset = charset_info(label);
    switch (charset.encoding) {
        case TextEncoding::utf8: return utf8_text(input);
        case TextEncoding::latin1: return single_byte_text(input, false);
        case TextEncoding::windows1252: return single_byte_text(input, true);
        case TextEncoding::utf16le: return utf16_text(input, true);
        case TextEncoding::utf16be: return utf16_text(input, false);
        case TextEncoding::utf32le: return utf32_text(input, true);
        case TextEncoding::utf32be: return utf32_text(input, false);
        case TextEncoding::system: return system_text(input, charset);
        case TextEncoding::ascii: {
            std::string out; out.reserve(input.size());
            for (unsigned char ch : input) append_scalar(out, ch < 0x80 ? ch : 0xfffd);
            return out;
        }
        default: return display_fallback(input);
    }
}
std::string bom_charset(std::string_view input) {
    if (input.size() >= 4 && input.substr(0, 4) == std::string_view("\xff\xfe\0\0", 4)) return "UTF-32LE";
    if (input.size() >= 4 && input.substr(0, 4) == std::string_view("\0\0\xfe\xff", 4)) return "UTF-32BE";
    if (input.starts_with("\xef\xbb\xbf")) return "UTF-8";
    if (input.starts_with("\xff\xfe")) return "UTF-16LE";
    if (input.starts_with("\xfe\xff")) return "UTF-16BE";
    return {};
}
std::string html_attribute(std::string_view tag, std::string_view wanted) {
    std::size_t at = 0;
    while (at < tag.size()) {
        while (at < tag.size() && (std::isspace(static_cast<unsigned char>(tag[at])) || tag[at] == '/')) ++at;
        auto start = at;
        while (at < tag.size() && !std::isspace(static_cast<unsigned char>(tag[at])) && tag[at] != '=' && tag[at] != '/') ++at;
        auto key = lower(std::string(tag.substr(start, at - start)));
        while (at < tag.size() && std::isspace(static_cast<unsigned char>(tag[at]))) ++at;
        if (at == tag.size() || tag[at] != '=') continue;
        ++at; while (at < tag.size() && std::isspace(static_cast<unsigned char>(tag[at]))) ++at;
        std::string_view value;
        if (at < tag.size() && (tag[at] == '\'' || tag[at] == '"')) {
            auto quote = tag[at++]; start = at;
            while (at < tag.size() && tag[at] != quote) ++at;
            value = tag.substr(start, at - start); if (at < tag.size()) ++at;
        } else {
            start = at; while (at < tag.size() && !std::isspace(static_cast<unsigned char>(tag[at]))) ++at;
            value = tag.substr(start, at - start);
        }
        if (key == wanted) return std::string(value);
    }
    return {};
}
std::string html_charset(std::string_view body) {
    // A bounded declaration scan, not an inference from the body language.
    const auto prefix = body.substr(0, 16384);
    const auto folded = lower(std::string(prefix));
    std::size_t at = 0;
    while ((at = folded.find('<', at)) != std::string::npos) {
        if (folded.compare(at, 4, "<!--") == 0) {
            auto end = folded.find("-->", at + 4); if (end == std::string::npos) break; at = end + 3; continue;
        }
        auto start = ++at; while (at < prefix.size() && ((folded[at] >= 'a' && folded[at] <= 'z') || (folded[at] >= '0' && folded[at] <= '9'))) ++at;
        auto name = std::string_view(folded).substr(start, at - start);
        auto attributes = at; char quote = 0;
        for (; at < prefix.size(); ++at) {
            const auto ch = prefix[at];
            if (quote) { if (ch == quote) quote = 0; }
            else if (ch == '\'' || ch == '"') quote = ch;
            else if (ch == '>') break;
        }
        if (at == prefix.size()) break;
        const auto tag = prefix.substr(attributes, at - attributes); ++at;
        if (name == "script" || name == "style" || name == "title" || name == "textarea") {
            auto closing = folded.find("</" + std::string(name), at); if (closing == std::string::npos) break; at = closing; continue;
        }
        if (name != "meta") continue;
        auto declared = trim(html_attribute(tag, "charset")); if (!declared.empty()) return declared;
        if (lower(trim(html_attribute(tag, "http-equiv"))) == "content-type") {
            try { declared = parse_parameter(html_attribute(tag, "content"), "charset"); }
            catch (const std::invalid_argument&) { continue; }
            if (!declared.empty()) return declared;
        }
    }
    return {};
}
struct Parser {
    Limits limits;
    std::size_t part_count = 0, decoded_bytes = 0;
    Part parse_part(std::string_view raw, std::size_t depth, std::string_view default_type = "text/plain") {
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
        out.content_type = content_type.empty() ? std::string(default_type) : lower(trim(content_type.substr(0, content_type.find(';'))));
        auto encoding = lower(trim(header(out, "content-transfer-encoding")));
        if (out.content_type.rfind("multipart/", 0) == 0) {
            if (!encoding.empty() && encoding != "7bit" && encoding != "8bit" && encoding != "binary") invalid("Encoded multipart is invalid");
            auto boundary = parse_parameter(content_type, "boundary");
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
                        out.parts.push_back(parse_part(body.substr(start, part_end - start), depth + 1,
                            out.content_type == "multipart/digest" ? "message/rfc822" : "text/plain"));
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
std::string parameter(std::string_view value, std::string_view name) {
    return parse_parameter(value, lower(std::string(name)));
}
std::string decode_text(const Part& part) {
    std::string charset;
    try { charset = parse_parameter(header(part, "content-type"), "charset"); }
    catch (const std::invalid_argument&) { return convert_text(part.body, ""); }
    if (charset.empty()) charset = bom_charset(part.body);
    if (charset.empty() && part.content_type == "text/html") charset = html_charset(part.body);
    return convert_text(part.body, charset);
}
std::string decode_header(std::string_view value) {
    check_text_size(value);
    std::string out; std::size_t pos = 0; bool previous_encoded = false;
    while (pos < value.size()) {
        auto start = value.find("=?", pos);
        if (start == std::string_view::npos) { append_display(out, display_fallback(value.substr(pos))); break; }
        auto charset_end = value.find('?', start + 2);
        auto payload = charset_end == std::string_view::npos ? charset_end : value.find('?', charset_end + 1);
        auto end = payload == std::string_view::npos ? payload : value.find("?=", payload + 1);
        if (end == std::string_view::npos || payload != charset_end + 2 || charset_end == start + 2) { append_display(out, display_fallback(value.substr(pos, start + 2 - pos))); pos = start + 2; previous_encoded = false; continue; }
        auto gap = value.substr(pos, start - pos);
        bool whitespace = std::all_of(gap.begin(), gap.end(), [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
        auto mode = static_cast<char>(std::tolower(static_cast<unsigned char>(value[charset_end + 1])));
        try {
            std::string decoded;
            if (mode == 'b') decoded = decode64(value.substr(payload + 1, end - payload - 1));
            else if (mode == 'q') decoded = qp(value.substr(payload + 1, end - payload - 1), true);
            else throw std::invalid_argument("Unknown encoded word encoding");
            decoded = convert_text(decoded, value.substr(start + 2, charset_end - start - 2));
            if (!previous_encoded || !whitespace) append_display(out, display_fallback(gap));
            append_display(out, decoded); previous_encoded = true; pos = end + 2;
        } catch (const std::invalid_argument&) { append_display(out, display_fallback(value.substr(pos, end + 2 - pos))); pos = end + 2; previous_encoded = false; }
    }
    return out;
}
std::string compose(const std::string& from, const std::vector<std::string>& to, const std::string& subject, const std::string& text, bool draft) {
    if (!valid_address(from) || (!draft && to.empty()) || to.size() > 100) invalid("Invalid message addresses");
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
