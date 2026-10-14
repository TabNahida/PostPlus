#include "update_archive.hpp"
#include <zlib.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <set>

namespace postplus {
namespace {
constexpr std::uint64_t max_entry = 128ULL * 1024 * 1024;
constexpr std::uint64_t max_expanded = 1536ULL * 1024 * 1024;
[[noreturn]] void bad(const char* message) { throw UpdateError("invalid_archive", message); }
void cancelled(const std::atomic<bool>& cancel) {
    if (cancel.load()) throw UpdateError("cancelled", "Update download cancelled.", 409);
}
std::string field(std::string_view value) {
    const auto end = value.find('\0');
    if (end != value.npos && value.substr(end).find_first_not_of('\0') != value.npos) bad("Ambiguous archive name.");
    return std::string(value.substr(0, end));
}
std::uint64_t octal(std::string_view text) {
    if (!text.empty() && (static_cast<unsigned char>(text.front()) & 128)) bad("Binary tar sizes are unsupported.");
    const auto begin = text.find_first_not_of(" \0", 0, 2);
    if (begin == text.npos) return 0;
    const auto end = text.find_first_of(" \0", begin, 2);
    const auto digits = text.substr(begin, end == text.npos ? text.size() - begin : end - begin);
    if (end != text.npos && text.substr(end).find_first_not_of(" \0", 0, 2) != text.npos) bad("Malformed tar number.");
    std::uint64_t value = 0;
    const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), value, 8);
    if (result.ec != std::errc{} || result.ptr != digits.data() + digits.size()) bad("Malformed tar number.");
    return value;
}
class Inventory {
public:
    Inventory(const std::string& version, const Json& files, const std::atomic<bool>& cancel,
        const std::function<void(const Json&, std::string_view)>& accept)
        : prefix_("postplus-" + version + "/"), cancel_(cancel), accept_(accept) {
        for (const auto& file : files) wanted_.emplace(file.at("path").get<std::string>(), file);
    }
    const Json* entry(const std::string& name, std::uint64_t size, bool directory) {
        cancelled(cancel_);
        if (++count_ > 8192 || size > max_entry || total_ > max_expanded - size) bad("Archive exceeds extraction limits.");
        total_ += size;
        auto path = name;
        if (directory && path.ends_with('/')) path.pop_back();
        if (path.empty() || path.find_first_of("\\:\r\n") != path.npos || path.find('\0') != path.npos ||
            (path + "/").substr(0, prefix_.size()) != prefix_) bad("Archive path is outside its release directory.");
        std::size_t begin = 0;
        while (begin <= path.size()) {
            const auto end = path.find('/', begin);
            const auto part = path.substr(begin, end == path.npos ? path.size() - begin : end - begin);
            if (part.empty() || part == "." || part == "..") bad("Unsafe archive path component.");
            if (end == path.npos) break;
            begin = end + 1;
        }
        if (!seen_.insert(path).second) bad("Duplicate archive member.");
        if (directory) { if (size) bad("Archive directory contains data."); return nullptr; }
        if (!path.starts_with(prefix_)) bad("Archive file is outside its release directory.");
        const auto relative = path.substr(prefix_.size());
        const auto found = wanted_.find(relative);
        if (found == wanted_.end()) return nullptr;
        if (found->second.at("size").get<std::uint64_t>() != size) bad("Archive module size differs from its manifest.");
        return &found->second;
    }
    void accept(const Json* file, std::string_view bytes) {
        if (!file) return;
        cancelled(cancel_); accept_(*file, bytes); received_.insert(file->at("path").get<std::string>());
    }
    void finish() const { if (received_.size() != wanted_.size()) bad("Archive omits a changed module."); }
    void tick() const { cancelled(cancel_); }
private:
    std::string prefix_;
    std::map<std::string, Json> wanted_;
    std::set<std::string> seen_, received_;
    const std::atomic<bool>& cancel_;
    const std::function<void(const Json&, std::string_view)>& accept_;
    std::uint64_t total_ = 0;
    unsigned count_ = 0;
};
// A bounded inflater feeds the tar parser incrementally; full packages never
// expand into a second package-sized buffer and never enter the live install.
void inflate_bytes(std::string_view input, int window, std::uint64_t maximum,
    const std::function<void(std::string_view)>& consume, Inventory& inventory) {
    if (input.size() > std::numeric_limits<uInt>::max()) bad("Compressed archive is too large.");
    z_stream stream{};
    if (inflateInit2(&stream, window) != Z_OK) bad("Cannot initialize archive decompression.");
    struct Cleanup { z_stream* stream; ~Cleanup() { inflateEnd(stream); } } cleanup{&stream};
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    std::array<char, 65536> buffer{};
    std::uint64_t total = 0;
    for (;;) {
        inventory.tick(); stream.next_out = reinterpret_cast<Bytef*>(buffer.data()); stream.avail_out = static_cast<uInt>(buffer.size());
        const auto status = inflate(&stream, Z_NO_FLUSH);
        const auto count = buffer.size() - stream.avail_out;
        if (count > maximum - total) bad("Archive expansion exceeds its limit.");
        total += count; consume({buffer.data(), count});
        if (status == Z_STREAM_END) { if (stream.avail_in) bad("Trailing compressed archive stream."); break; }
        if (status != Z_OK || (!count && !stream.avail_in)) bad("Truncated or corrupt compressed archive.");
    }
}
class Tar {
public:
    explicit Tar(Inventory& inventory) : inventory_(inventory) {}
    void feed(std::string_view bytes) {
        while (!bytes.empty()) {
            if (ended_) { if (bytes.find_first_not_of('\0') != bytes.npos) bad("Trailing data after tar terminator."); return; }
            if (remaining_) {
                const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, bytes.size()));
                if (selected_ || extension_) contents_.append(bytes.substr(0, count));
                remaining_ -= count; bytes.remove_prefix(count);
                if (!remaining_) {
                    if (extension_) pax(); else inventory_.accept(selected_, contents_);
                    contents_.clear(); selected_ = nullptr;
                }
            } else if (padding_) {
                const auto count = std::min(padding_, bytes.size());
                if (bytes.substr(0, count).find_first_not_of('\0') != bytes.npos) bad("Nonzero tar padding.");
                padding_ -= count; bytes.remove_prefix(count);
            } else {
                const auto count = std::min<std::size_t>(512 - header_.size(), bytes.size());
                header_.append(bytes.substr(0, count)); bytes.remove_prefix(count);
                if (header_.size() == 512) { header(); header_.clear(); }
            }
        }
    }
    void finish() { if (!ended_ || !header_.empty() || remaining_ || padding_ || !next_.empty()) bad("Truncated tar archive."); }
private:
    void pax() {
        std::size_t at = 0;
        auto& values = extension_ == 'g' ? global_ : next_;
        while (at < contents_.size()) {
            const auto space = contents_.find(' ', at); std::size_t length = 0;
            if (space == contents_.npos) bad("Malformed tar extension.");
            const auto parsed = std::from_chars(contents_.data() + at, contents_.data() + space, length);
            if (parsed.ec != std::errc{} || parsed.ptr != contents_.data() + space || length <= space - at + 2 || length > contents_.size() - at || contents_[at + length - 1] != '\n') bad("Malformed tar extension.");
            const auto record = contents_.substr(space + 1, at + length - space - 2);
            const auto equal = record.find('=');
            if (equal == record.npos || !equal) bad("Malformed tar extension.");
            const auto key = record.substr(0, equal), value = record.substr(equal + 1);
            if (key == "linkpath" || key.starts_with("GNU.sparse") || key == "SCHILY.filetype") bad("Tar links and sparse entries are forbidden.");
            if (key == "path" || key == "size") {
                if (extension_ == 'g') bad("Global tar path and size overrides are forbidden.");
                if (!values.emplace(key, value).second) bad("Duplicate tar extension field.");
            }
            at += length;
        }
        extension_ = 0;
    }
    void header() {
        if (header_.find_first_not_of('\0') == header_.npos) { if (++zeros_ == 2) ended_ = true; return; }
        if (zeros_) bad("Incomplete tar terminator.");
        std::uint64_t sum = 0;
        for (std::size_t i = 0; i < header_.size(); ++i) sum += i >= 148 && i < 156 ? 32U : static_cast<unsigned char>(header_[i]);
        if (sum != octal(std::string_view(header_).substr(148, 8))) bad("Tar header checksum mismatch.");
        auto name = field(std::string_view(header_).substr(0, 100));
        const auto prefix = field(std::string_view(header_).substr(345, 155));
        if (!prefix.empty()) name = prefix + "/" + name;
        auto size = octal(std::string_view(header_).substr(124, 12));
        const auto type = header_[156];
        if (type == 'x' || type == 'g') {
            if (!size || size > 65536 || ++extensions_ > 8192) bad("Oversized tar extension.");
            extension_ = type;
        } else {
            if (type != '\0' && type != '0' && type != '5') bad("Archive contains a link or special file.");
            if (next_.contains("path")) name = next_.at("path");
            if (next_.contains("size")) {
                const auto& text = next_.at("size");
                const auto parsed = std::from_chars(text.data(), text.data() + text.size(), size);
                if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) bad("Malformed tar extension size.");
            }
            next_.clear(); selected_ = inventory_.entry(name, size, type == '5');
        }
        remaining_ = size; padding_ = static_cast<std::size_t>((512 - size % 512) % 512);
        if (!remaining_) inventory_.accept(selected_, {});
    }
    Inventory& inventory_;
    std::string header_, contents_;
    std::map<std::string, std::string> next_, global_;
    const Json* selected_ = nullptr;
    std::uint64_t remaining_ = 0;
    std::size_t padding_ = 0;
    unsigned zeros_ = 0, extensions_ = 0;
    char extension_ = 0;
    bool ended_ = false;
};
std::uint32_t little(std::string_view bytes, std::size_t at, unsigned count) {
    if (at > bytes.size() || count > bytes.size() - at) bad("Truncated ZIP archive.");
    std::uint32_t result = 0;
    for (unsigned i = 0; i < count; ++i) result |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[at + i])) << (i * 8);
    return result;
}
void zip(std::string_view bytes, Inventory& inventory) {
    if (bytes.size() < 22) bad("Truncated ZIP archive.");
    std::size_t end = bytes.size() - 22;
    for (;;) {
        if (little(bytes, end, 4) == 0x06054b50 && end + 22 + little(bytes, end + 20, 2) == bytes.size()) break;
        if (!end || bytes.size() - end > 65557) bad("Missing ZIP directory.");
        --end;
    }
    const auto count = little(bytes, end + 10, 2), size = little(bytes, end + 12, 4), offset = little(bytes, end + 16, 4);
    if (little(bytes, end + 4, 2) || little(bytes, end + 6, 2) || little(bytes, end + 8, 2) != count || count > 8192 ||
        static_cast<std::uint64_t>(offset) + size != end) bad("Split or ZIP64 archives are unsupported.");
    std::size_t at = offset;
    std::set<std::pair<std::size_t, std::size_t>> ranges;
    for (unsigned i = 0; i < count; ++i) {
        if (little(bytes, at, 4) != 0x02014b50) bad("Malformed ZIP directory.");
        const auto flags = little(bytes, at + 8, 2), method = little(bytes, at + 10, 2), crc = little(bytes, at + 16, 4);
        const auto packed = little(bytes, at + 20, 4), expanded = little(bytes, at + 24, 4), length = little(bytes, at + 28, 2);
        const auto extra = little(bytes, at + 30, 2), comment = little(bytes, at + 32, 2), attributes = little(bytes, at + 38, 4), local = little(bytes, at + 42, 4);
        if (flags & ~0x080eU || (method != 0 && method != 8) || little(bytes, at + 34, 2) || !length || length > 1024 ||
            at + 46ULL + length + extra + comment > end || packed == 0xffffffffU || expanded == 0xffffffffU) bad("Unsupported ZIP entry.");
        const auto name = std::string(bytes.substr(at + 46, length)); const bool directory = name.ends_with('/');
        const auto kind = (attributes >> 16) & 0170000;
        if ((kind && kind != (directory ? 0040000U : 0100000U)) || ((attributes & 0x10) && !directory)) bad("ZIP contains a link or special file.");
        if (little(bytes, local, 4) != 0x04034b50 || little(bytes, local + 6, 2) != flags || little(bytes, local + 8, 2) != method || little(bytes, local + 26, 2) != length) bad("ZIP local header differs from its directory.");
        const auto begin = local + 30ULL + length + little(bytes, local + 28, 2);
        if (begin > offset || packed > offset - begin || bytes.substr(local + 30, length) != name) bad("ZIP member is outside its data area.");
        const auto range = std::pair<std::size_t, std::size_t>{local, static_cast<std::size_t>(begin + packed)};
        auto next = ranges.lower_bound(range);
        if ((next != ranges.end() && next->first < range.second) || (next != ranges.begin() && std::prev(next)->second > range.first)) bad("Overlapping ZIP members.");
        ranges.insert(range);
        const auto* selected = inventory.entry(name, expanded, directory);
        if (selected) {
            const auto compressed = bytes.substr(static_cast<std::size_t>(begin), packed); std::string body;
            if (method == 0) { if (packed != expanded) bad("Stored ZIP size mismatch."); body = compressed; }
            else inflate_bytes(compressed, -MAX_WBITS, expanded, [&](std::string_view part) { body.append(part); }, inventory);
            if (body.size() != expanded || crc32(0, reinterpret_cast<const Bytef*>(body.data()), static_cast<uInt>(body.size())) != crc) bad("ZIP module CRC or size mismatch.");
            inventory.accept(selected, body);
        }
        at += 46 + length + extra + comment;
    }
    if (at != end) bad("Unexpected ZIP directory data.");
}
}
void extract_update_modules(std::string_view bytes, const std::string& asset,
    const std::string& version, const Json& files, const std::atomic<bool>& cancel,
    const std::function<void(const Json&, std::string_view)>& accept) {
    Inventory inventory(version, files, cancel, accept);
    if (asset.ends_with(".zip")) zip(bytes, inventory);
    else if (asset.ends_with(".tar.gz")) {
        Tar tar(inventory);
        inflate_bytes(bytes, MAX_WBITS + 16, max_expanded, [&](std::string_view part) { tar.feed(part); }, inventory);
        tar.finish();
    } else bad("Unsupported release archive format.");
    inventory.finish();
}
}
