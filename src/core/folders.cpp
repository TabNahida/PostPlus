#include <postplus/folders.hpp>
#include <postplus/core.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>

namespace postplus {
namespace {
constexpr std::array<std::string_view, 6> names{"INBOX", "Sent", "Trash", "Drafts", "Junk", "Archive"};
}
std::string normalize_mail_folder(std::string_view input) {
    if (input.empty() || input.size() > 255) throw std::invalid_argument("invalid folder name length");
    std::string wanted(input);
    // Names are logical data, never filesystem paths. IMAP performs modified
    // UTF-7 conversion at its wire boundary; storage and HTTP use UTF-8.
    for (std::size_t at = 0; at < wanted.size();) {
        const auto first = static_cast<unsigned char>(wanted[at++]);
        std::uint32_t point = first; unsigned extra = 0;
        if (first >= 0xc2 && first <= 0xdf) { point = first & 31; extra = 1; }
        else if (first >= 0xe0 && first <= 0xef) { point = first & 15; extra = 2; }
        else if (first >= 0xf0 && first <= 0xf4) { point = first & 7; extra = 3; }
        else if (first >= 0x80) throw std::invalid_argument("invalid UTF-8 folder name");
        const auto minimum = extra == 1 ? 0x80U : extra == 2 ? 0x800U : extra == 3 ? 0x10000U : 0U;
        for (unsigned i = 0; i < extra; ++i) {
            if (at == wanted.size()) throw std::invalid_argument("invalid UTF-8 folder name");
            const auto next = static_cast<unsigned char>(wanted[at++]);
            if ((next & 0xc0) != 0x80) throw std::invalid_argument("invalid UTF-8 folder name");
            point = (point << 6) | (next & 63);
        }
        if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff) ||
            point < 32 || (point >= 127 && point <= 159)) throw std::invalid_argument("invalid folder name character");
    }
    std::size_t depth = 0;
    for (std::size_t start = 0;;) {
        const auto end = wanted.find('/', start);
        const auto part = wanted.substr(start, end == std::string::npos ? wanted.size() - start : end - start);
        if (part.empty() || part == "." || part == ".." || ++depth > 16) throw std::invalid_argument("invalid folder hierarchy");
        if (end == std::string::npos) break;
        start = end + 1;
    }
    const auto head = wanted.substr(0, wanted.find('/'));
    for (const auto name : names) if (lower(std::string(name)) == lower(head)) { wanted.replace(0, head.size(), name); break; }
    return wanted;
}
bool is_system_mail_folder(std::string_view name) {
    return std::find(names.begin(), names.end(), name) != names.end();
}
}
