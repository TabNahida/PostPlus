#include <postplus/update.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/restart.hpp>
#include "update_archive.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <set>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace postplus {
namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
constexpr std::size_t max_module = 128 * 1024 * 1024, max_metadata = 4 * 1024 * 1024;
constexpr std::size_t max_archive = 512 * 1024 * 1024;
constexpr std::string_view repository = "TabNahida/PostPlus";
constexpr std::string_view releases_url = "https://api.github.com/repos/TabNahida/PostPlus/releases?per_page=20";
[[noreturn]] void invalid(const std::string& message, const std::string& code = "invalid_update", int status = 503) {
    throw UpdateError(code, message, status);
}
bool hex(std::string_view value, std::size_t size) {
    return value.size() == size && value.find_first_not_of("0123456789abcdef") == std::string_view::npos;
}
std::array<unsigned, 3> semver(std::string_view value) {
    std::array<unsigned, 3> result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        const auto dot = value.find('.');
        const auto part = value.substr(0, dot);
        const auto [end, error] = std::from_chars(part.data(), part.data() + part.size(), result[i]);
        if (part.empty() || (part.size() > 1 && part.front() == '0') || error != std::errc{} || end != part.data() + part.size() ||
            (i < 2 && dot == value.npos) || (i == 2 && dot != value.npos)) invalid("Only stable major.minor.patch releases are supported.");
        if (dot != value.npos) value.remove_prefix(dot + 1);
    }
    return result;
}
void plain(const fs::path& path) {
    fs::path current;
    for (const auto& component : fs::absolute(path).lexically_normal()) { current /= component; require_plain_path(current); }
}
bool safe_name(const std::string& value) {
    return !value.empty() && value.size() <= 240 && value.front() != '.' &&
        value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") == value.npos;
}
bool permitted(const std::string& path) {
    static const std::set<std::string> executables = {"postplus", "postplus-admin", "postplus-web", "postplus-auth", "postplus-storage",
        "postplus-filter", "postplus-smtp", "postplus-pop3", "postplus-imap", "postplus-delivery", "postplus-transfer",
        "postplus-ctl", "postplus-clean-data", "postplus-update"};
    auto binary = path;
#ifdef _WIN32
    if (!binary.ends_with(".exe")) binary.clear(); else binary.resize(binary.size() - 4);
#endif
    if (executables.contains(binary)) return true;
    if (!path.starts_with("web/") || !safe_name(path.substr(4))) return false;
    const auto extension = fs::path(path).extension().string();
    return extension == ".html" || extension == ".js" || extension == ".css" || extension == ".svg" || extension == ".txt";
}
UpdateOptions normalized(UpdateOptions options) {
    options.install_directory = fs::absolute(options.install_directory).lexically_normal();
    if (options.web_directory.empty()) options.web_directory = options.install_directory / "web";
    options.web_directory = fs::absolute(options.web_directory).lexically_normal();
    options.storage_directory = fs::absolute(options.storage_directory).lexically_normal();
    if (options.current_version.empty()) options.current_version = update_build_version();
    (void)semver(options.current_version);
    for (const auto& path : {options.install_directory, options.web_directory, options.storage_directory}) plain(path);
    if (!fs::is_directory(options.install_directory) || !fs::is_directory(options.web_directory)) invalid("Installation and web directories must exist.");
    return options;
}
fs::path target_path(const UpdateOptions& options, const std::string& path) {
    if (!permitted(path)) invalid("Update file is outside the native module allowlist.");
    const auto result = path.starts_with("web/") ? options.web_directory / path.substr(4) : options.install_directory / path;
    plain(result);
    return result;
}
#ifdef _WIN32
class Security {
public:
    explicit Security(bool directory = false) {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) invalid("Cannot read updater identity.");
        DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<unsigned char> user(size);
        const bool ok = GetTokenInformation(token, TokenUser, user.data(), size, &size) != 0; CloseHandle(token);
        if (!ok) invalid("Cannot read updater identity.");
        LPWSTR sid = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid)) invalid("Cannot read updater identity.");
        const std::wstring flags = directory ? L"OICI" : L"";
        const auto acl = L"D:P(A;" + flags + L";FA;;;SY)(A;" + flags + L";FA;;;" + std::wstring(sid) + L")"; LocalFree(sid);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor_, nullptr)) invalid("Cannot set private updater permissions.");
        attributes_ = {sizeof(SECURITY_ATTRIBUTES), descriptor_, FALSE};
    }
    ~Security() { LocalFree(descriptor_); }
    SECURITY_ATTRIBUTES* get() { return &attributes_; }
private:
    PSECURITY_DESCRIPTOR descriptor_ = nullptr;
    SECURITY_ATTRIBUTES attributes_{};
};
struct File { HANDLE value = INVALID_HANDLE_VALUE; ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
#else
struct File { int value = -1; ~File() { if (value >= 0) ::close(value); } };
#endif
void private_directory(const fs::path& path) {
    plain(path.parent_path());
#ifdef _WIN32
    Security security(true);
    if (!CreateDirectoryW(path.c_str(), security.get())) invalid("Cannot create private update directory.");
#else
    if (::mkdir(path.c_str(), 0700) != 0) invalid("Cannot create private update directory.");
#endif
}
void private_file(const fs::path& path, std::string_view bytes) {
    plain(path.parent_path());
    File file;
#ifdef _WIN32
    Security security;
    file.value = CreateFileW(path.c_str(), GENERIC_WRITE, 0, security.get(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file.value == INVALID_HANDLE_VALUE) invalid("Cannot create private update file.");
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        DWORD written = 0;
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 65536));
        if (!WriteFile(file.value, bytes.data() + offset, chunk, &written, nullptr) || !written) invalid("Cannot write update file.");
        offset += written;
    }
    if (!FlushFileBuffers(file.value)) invalid("Cannot synchronize update file.");
#else
    file.value = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (file.value < 0) invalid("Cannot create private update file.");
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::write(file.value, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) invalid("Cannot write update file.");
        offset += static_cast<std::size_t>(count);
    }
    if (::fsync(file.value) != 0) invalid("Cannot synchronize update file.");
#endif
}
std::string read_file(const fs::path& path, std::size_t maximum = max_metadata) {
    plain(path); File file; std::string result; std::array<char, 65536> buffer{};
#ifdef _WIN32
    const auto deadline = Clock::now() + std::chrono::milliseconds(250);
    do {
        file.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file.value != INVALID_HANDLE_VALUE) break;
        const auto error = GetLastError();
        if ((error != ERROR_ACCESS_DENIED && error != ERROR_SHARING_VIOLATION && error != ERROR_DELETE_PENDING && error != ERROR_FILE_NOT_FOUND) || Clock::now() >= deadline)
            invalid("Cannot read update file.");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } while (true);
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(file.value) != FILE_TYPE_DISK || !GetFileInformationByHandle(file.value, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || info.nNumberOfLinks != 1 ||
        ((static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow) > maximum) invalid("Update input must be a bounded, unlinked regular file.");
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) invalid("Cannot read update file.");
        if (!count) break;
        if (count > maximum - result.size()) invalid("Update input exceeds its size limit.");
        result.append(buffer.data(), count);
    }
#else
    file.value = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat info{};
    if (file.value < 0 || ::fstat(file.value, &info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1 || info.st_size < 0 ||
        static_cast<std::uintmax_t>(info.st_size) > maximum) invalid("Update input must be a bounded, unlinked regular file.");
    for (;;) {
        const auto count = ::read(file.value, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) invalid("Cannot read update file.");
        if (!count) break;
        if (static_cast<std::size_t>(count) > maximum - result.size()) invalid("Update input exceeds its size limit.");
        result.append(buffer.data(), static_cast<std::size_t>(count));
    }
#endif
    return result;
}
std::string sha256(std::string_view bytes) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{}; unsigned size = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1) invalid("Cannot calculate update checksum.");
    constexpr char digits[] = "0123456789abcdef"; std::string result;
    for (unsigned i = 0; i < size; ++i) { result += digits[digest[i] >> 4]; result += digits[digest[i] & 15]; }
    return result;
}
std::string current_hash(const fs::path& path) {
    plain(path);
    if (!fs::exists(path)) return "";
    return sha256(read_file(path, max_module));
}
void replace(const fs::path& source, const fs::path& destination) {
    plain(source); plain(destination);
#ifdef _WIN32
    const auto deadline = Clock::now() + std::chrono::milliseconds(500);
    while (!MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        if ((error != ERROR_ACCESS_DENIED && error != ERROR_SHARING_VIOLATION && error != ERROR_DELETE_PENDING) || Clock::now() >= deadline)
            invalid("Cannot replace update module; stop its owning process first.", "module_in_use");
        std::this_thread::sleep_for(std::chrono::milliseconds(5)); plain(destination);
    }
#else
    fs::rename(source, destination);
    File directory; directory.value = ::open(destination.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory.value < 0 || ::fsync(directory.value) != 0) invalid("Cannot synchronize installed module.");
#endif
}
void atomic_file(const fs::path& destination, std::string_view bytes, fs::perms permissions = fs::perms::owner_read | fs::perms::owner_write) {
    const auto temporary = destination.parent_path() / (".update-" + random_hex(16));
    try {
        private_file(temporary, bytes);
#ifndef _WIN32
        fs::permissions(temporary, permissions);
#else
        (void)permissions;
#endif
        replace(temporary, destination);
    } catch (...) { std::error_code ignored; fs::remove(temporary, ignored); throw; }
}
fs::path job_path(const UpdateOptions& options, const std::string& id) {
    if (!hex(id, 32)) invalid("Invalid update job identifier.", "invalid_job", 400);
    const auto result = options.storage_directory / id; plain(result); return result;
}
struct Lease {
    fs::path path;
    File file;
    explicit Lease(const UpdateOptions& options) : path(options.storage_directory / ".lock") {
        if (!fs::exists(options.storage_directory)) private_directory(options.storage_directory);
        if (!fs::exists(path)) {
            try { private_file(path, ""); } catch (...) { if (!fs::is_regular_file(path)) throw; }
        }
        plain(path);
#ifdef _WIN32
        file.value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION info{}; OVERLAPPED overlap{};
        if (file.value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(file.value, &info) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || info.nNumberOfLinks != 1)
            invalid("Unsafe updater transaction lock.");
        if (!LockFileEx(file.value, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap))
            invalid("Another update transaction is active.", "update_busy", 409);
#else
        file.value = ::open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        struct stat info{};
        if (file.value < 0 || ::fstat(file.value, &info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1)
            invalid("Unsafe updater transaction lock.");
        if (::flock(file.value, LOCK_EX | LOCK_NB) != 0) invalid("Another update transaction is active.", "update_busy", 409);
#endif
    }
};
Json load_job(const UpdateOptions& options, const std::string& id) {
    const auto directory = job_path(options, id);
    if (!fs::exists(directory / "job.json")) invalid("Update job not found.", "job_not_found", 404);
    auto job = Json::parse(read_file(directory / "job.json"));
    if (job.value("schema", 0) != 1 || job.value("job_id", "") != id ||
        job.value("install_directory", "") != options.install_directory.string() ||
        job.value("web_directory", "") != options.web_directory.string()) invalid("Update plan does not match this installation.");
    if (!job.at("files").is_array() || job.at("files").size() > 128) invalid("Invalid update file inventory.");
    std::set<std::string> paths;
    for (const auto& file : job.at("files")) {
        const auto path = file.at("path").get<std::string>();
        const auto old = file.at("old_sha256").get<std::string>();
        if (!permitted(path) || !paths.insert(path).second || !hex(file.at("sha256").get<std::string>(), 64) ||
            !hex(file.at("id").get<std::string>(), 64) || file.at("id") != sha256(path) ||
            (!old.empty() && !hex(old, 64)) || !file.at("size").get<std::uint64_t>() ||
            file.at("size").get<std::uint64_t>() > max_module || !file.at("executable").is_boolean() ||
            file.at("executable").get<bool>() != !path.starts_with("web/") ||
            (file.contains("applied") && !file.at("applied").is_boolean())) invalid("Unsafe or malformed staged update plan.");
        (void)target_path(options, path);
    }
    return job;
}
void save_job(const UpdateOptions& options, const Json& job) {
    atomic_file(job_path(options, job.at("job_id").get<std::string>()) / "job.json", job.dump());
}
Json public_job(Json job) { job.erase("install_directory"); job.erase("web_directory"); job.erase("installation_manifest"); return job; }
struct Url { std::string host, target; };
Url trusted_url(const std::string& url) {
    if (!url.starts_with("https://") || url.find_first_of("\r\n\t \\") != url.npos || url.find('\0') != url.npos || url.find('#') != url.npos)
        invalid("Update downloads require trusted HTTPS URLs.", "untrusted_url");
    const auto slash = url.find('/', 8); if (slash == url.npos) invalid("Invalid update URL.");
    Url result{url.substr(8, slash - 8), url.substr(slash)};
    if (result.host != "api.github.com" && result.host != "github.com" && result.host != "release-assets.githubusercontent.com" && result.host != "objects.githubusercontent.com")
        invalid("Update URL is outside the official GitHub download hosts.", "untrusted_url");
    if (result.host == "api.github.com" && result.target != "/repos/TabNahida/PostPlus/releases?per_page=20") invalid("Update API repository is not trusted.", "untrusted_url");
    if (result.host == "github.com" && !result.target.starts_with("/TabNahida/PostPlus/releases/download/v")) invalid("Update download repository is not trusted.", "untrusted_url");
    return result;
}
UpdateHttpResponse native_http(const std::string& url, std::size_t maximum, Clock::time_point deadline) {
    const auto address = trusted_url(url); Connection connection(std::chrono::seconds(30)); connection.set_deadline(deadline);
    connection.connect(address.host, 443); connection.start_tls_client(address.host);
    connection.write("GET " + address.target + " HTTP/1.1\r\nHost: " + address.host +
        "\r\nUser-Agent: PostPlus-Updater/1\r\nAccept: application/octet-stream, application/vnd.github+json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
    const auto line = connection.line(4096); UpdateHttpResponse result;
    if ((!line.starts_with("HTTP/1.1 ") && !line.starts_with("HTTP/1.0 ")) || line.size() < 12) invalid("Invalid update HTTP response.");
    const auto [end, error] = std::from_chars(line.data() + 9, line.data() + 12, result.status);
    if (error != std::errc{} || end != line.data() + 12 || result.status < 200 || result.status > 599) invalid("Invalid update HTTP status.");
    std::size_t header_bytes = 0; bool complete = false;
    for (unsigned i = 0; i < 100; ++i) {
        const auto header = connection.line(8192); if (header.empty()) { complete = true; break; }
        header_bytes += header.size(); const auto colon = header.find(':');
        if (header_bytes > 32768 || colon == header.npos || !colon || header.front() == ' ' || header.front() == '\t') invalid("Invalid update HTTP headers.");
        const auto name = lower(header.substr(0, colon)), value = trim(header.substr(colon + 1));
        if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-_") != name.npos || value.find('\0') != value.npos) invalid("Unsafe update HTTP headers.");
        if (result.headers.contains(name)) {
            if (name == "content-length" || name == "transfer-encoding" || name == "location" || name == "content-encoding") invalid("Ambiguous update HTTP headers.");
            result.headers[name] += ", " + value;
        } else result.headers[name] = value;
    }
    if (!complete) invalid("Oversized update HTTP headers.");
    if (result.status >= 300 && result.status < 400) return result;
    if (result.headers.contains("content-encoding") && result.headers.at("content-encoding") != "identity") invalid("Unsupported update content encoding.");
    if (result.headers.contains("transfer-encoding")) {
        if (result.headers.contains("content-length") || lower(result.headers.at("transfer-encoding")) != "chunked") invalid("Ambiguous update response framing.");
        for (unsigned i = 0; i < 100000; ++i) {
            const auto size_line = connection.line(1024), value = size_line.substr(0, size_line.find(';')); std::size_t size = 0;
            const auto [last, issue] = std::from_chars(value.data(), value.data() + value.size(), size, 16);
            if (value.empty() || issue != std::errc{} || last != value.data() + value.size() || size > maximum - result.body.size()) invalid("Oversized update response.");
            if (!size) {
                for (unsigned j = 0; j < 32; ++j) if (connection.line(8192).empty()) return result;
                invalid("Oversized update response trailers.");
            }
            result.body += connection.read(size); if (connection.read(2) != "\r\n") invalid("Invalid update chunk framing.");
        }
        invalid("Too many update response chunks.");
    }
    if (!result.headers.contains("content-length")) invalid("Update response must have a bounded length.");
    const auto value = result.headers.at("content-length"); std::size_t size = 0;
    const auto [last, issue] = std::from_chars(value.data(), value.data() + value.size(), size);
    if (value.empty() || issue != std::errc{} || last != value.data() + value.size() || size > maximum) invalid("Oversized update response.");
    result.body = connection.read(size); return result;
}
std::string download(const UpdateOptions& options, std::string url, std::size_t maximum) {
    const auto deadline = Clock::now() + std::chrono::seconds(180);
    for (unsigned i = 0; i < 6; ++i) {
        (void)trusted_url(url);
        const auto response = options.transport ? options.transport(url, maximum, deadline) : native_http(url, maximum, deadline);
        if (response.body.size() > maximum) invalid("Update download exceeds its size limit.");
        if (response.status == 200) return response.body;
        if (response.status == 301 || response.status == 302 || response.status == 303 || response.status == 307 || response.status == 308) {
            if (!response.headers.contains("location")) invalid("Missing update redirect target.");
            url = response.headers.at("location"); continue;
        }
        if (response.status == 403 || response.status == 429) invalid("GitHub rate limit or access restriction prevented the update check. Retry later.", "github_unavailable", 502);
        invalid("GitHub update download failed (HTTP " + std::to_string(response.status) + ").", "download_failed", 502);
    }
    invalid("Too many update download redirects.");
}
std::map<std::string, std::string> checksums(const std::string& bytes) {
    std::map<std::string, std::string> result; std::istringstream lines(bytes); std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() < 67 || !hex(line.substr(0, 64), 64) || line.substr(64, 2) != "  " || !safe_name(line.substr(66)) ||
            !result.emplace(line.substr(66), line.substr(0, 64)).second) invalid("Malformed release SHA256SUMS.");
    }
    return result;
}
std::string installed_version(const UpdateOptions& options) {
    const auto path = options.install_directory / "postplus-update.json";
    if (!fs::exists(path)) return options.current_version;
    const auto metadata = Json::parse(read_file(path));
    if (metadata.value("repository", "") != repository || metadata.value("schema", 0) != 1) invalid("Installed update metadata is not owned by PostPlus.");
    const auto version = metadata.at("version").get<std::string>();
    return semver(version) > semver(options.current_version) ? version : options.current_version;
}
Json inspect_release(const UpdateOptions& options) {
    const auto releases = Json::parse(download(options, std::string(releases_url), max_metadata));
    if (!releases.is_array() || releases.size() > 20) invalid("GitHub did not return the stable release list.");
    Json release; std::array<unsigned, 3> newest{};
    for (const auto& candidate : releases) {
        if (candidate.value("draft", true) || candidate.value("prerelease", true)) continue;
        const auto tag = candidate.value("tag_name", "");
        if (!tag.starts_with('v')) continue;
        try {
            const auto version = semver(tag.substr(1));
            if (release.is_null() || version > newest) { release = candidate; newest = version; }
        } catch (const UpdateError&) { /* Unrelated/nonstable tags are not updates. */ }
    }
    if (release.is_null()) invalid("GitHub has no supported stable release.");
    const auto tag = release.at("tag_name").get<std::string>();
    if (release.value("draft", true) || release.value("prerelease", true) || !tag.starts_with('v')) invalid("GitHub did not return a stable release.");
    const auto version = tag.substr(1); (void)semver(version);
    const auto current = installed_version(options);
    Json result{{"ok", true}, {"state", "checked"}, {"current_version", current}, {"version", version},
        {"release_url", "https://github.com/TabNahida/PostPlus/releases/tag/" + tag}, {"available", semver(version) > semver(current)},
        {"files", Json::array()}, {"services", Json::array()}, {"requires_launcher_restart", false}, {"download_bytes", 0}};
    std::map<std::string, std::string> assets;
    for (const auto& asset : release.at("assets")) {
        const auto name = asset.at("name").get<std::string>(), url = asset.at("browser_download_url").get<std::string>();
        if (!safe_name(name) || !assets.emplace(name, url).second) invalid("Ambiguous GitHub release asset inventory.");
        const auto expected = "https://github.com/TabNahida/PostPlus/releases/download/" + tag + "/" + name;
        if (url != expected) invalid("Release asset points outside its official version.", "untrusted_url");
    }
    if (!assets.contains("postplus-update.json") || !assets.contains("SHA256SUMS")) {
        result["supported"] = false;
        result["message"] = "This release predates verified module updates. Download its full package and follow the manual upgrade instructions.";
        return result;
    }
    const auto sums = checksums(download(options, assets.at("SHA256SUMS"), max_metadata));
    const auto bytes = download(options, assets.at("postplus-update.json"), max_metadata);
    if (!sums.contains("postplus-update.json") || sha256(bytes) != sums.at("postplus-update.json")) invalid("Release manifest checksum mismatch.", "checksum_mismatch");
    const auto manifest = Json::parse(bytes);
    if (manifest.value("schema", 0) != 1 || manifest.value("minimum_updater", 999) > 2 || manifest.value("repository", "") != repository ||
        manifest.value("version", "") != version) invalid("Unsupported updater manifest or repository.", "incompatible_release");
    Json target; unsigned matches = 0;
    for (const auto& value : manifest.at("targets")) if (value.value("platform", "") == update_platform() && value.value("arch", "") == update_architecture()) { target = value; ++matches; }
    if (matches != 1 || target.value("service_contract", 0) != 1 || semver(target.at("minimum_version").get<std::string>()) > semver(current))
        invalid("This release is not compatible with the installed platform or service contract.", "incompatible_release");
    if (!target.at("files").is_array() || target.at("files").size() > 128) invalid("Invalid release module inventory.");
    const bool archive_download = target.value("download", "modules") == "archive";
    if (!archive_download) {
#ifndef POSTPLUS_LEGACY_UPDATES
        invalid("This release uses the retired module download format.", "incompatible_release");
#endif
        if (target.value("download", "modules") != "modules") invalid("Unknown release download format.", "incompatible_release");
    }
    if (archive_download) {
        const auto archive = target.at("archive");
        const auto asset = archive.at("asset").get<std::string>();
        const auto extension = update_platform() == "windows" ? ".zip" : ".tar.gz";
        const auto expected = "postplus-" + version + "-" + update_platform() + "-" + update_architecture() + extension;
        const auto size = archive.at("size").get<std::uint64_t>();
        const auto hash = archive.at("sha256").get<std::string>();
        if (asset != expected || !size || size > max_archive || !hex(hash, 64) || !assets.contains(asset) ||
            !sums.contains(asset) || sums.at(asset) != hash) invalid("Release archive violates its package or checksum inventory.");
        result["archive"] = archive; result["archive"]["download_url"] = assets.at(asset);
    }
    result["download_format"] = archive_download ? "archive" : "modules";
    std::set<std::string> paths, services; std::uint64_t total = 0;
    Json baseline = Json::object();
    const auto installed_path = options.install_directory / "postplus-update.json";
    if (fs::exists(installed_path)) {
        const auto installed = Json::parse(read_file(installed_path));
        for (const auto& file : installed.value("files", Json::array())) baseline[file.at("path").get<std::string>()] = file;
    }
    result["component_aware"] = !baseline.empty();
    result["installation_manifest"] = Json{{"schema", 1}, {"repository", repository}, {"version", version},
        {"platform", update_platform()}, {"arch", update_architecture()}, {"files", Json::array()}};
    for (auto file : target.at("files")) {
        const auto path = file.at("path").get<std::string>(), hash = file.at("sha256").get<std::string>();
        const auto fingerprint = file.at("fingerprint").get<std::string>();
        const auto size = file.at("size").get<std::uint64_t>();
        if (!permitted(path) || !paths.insert(path).second || !hex(hash, 64) || !hex(fingerprint, 64) || !size || size > max_module ||
            !file.at("executable").is_boolean() ||
            file.at("executable").get<bool>() != !path.starts_with("web/")) invalid("Release module violates the updater allowlist or checksum inventory.");
#ifdef POSTPLUS_LEGACY_UPDATES
        if (!archive_download) {
            const auto asset = file.at("asset").get<std::string>();
            if (!safe_name(asset) || !assets.contains(asset) || !sums.contains(asset) || sums.at(asset) != hash)
                invalid("Release module violates the updater checksum inventory.");
            file["download_url"] = assets.at(asset);
        }
#endif
        const auto local = current_hash(target_path(options, path));
        auto installed_file = file;
        installed_file.erase("download_url");
        const bool same_component = baseline.contains(path) && baseline[path].value("fingerprint", "") == fingerprint &&
            baseline[path].value("sha256", "") == local && !local.empty();
        if (same_component) {
            installed_file["sha256"] = local;
            installed_file["size"] = fs::file_size(target_path(options, path));
        }
        result["installation_manifest"]["files"].push_back(std::move(installed_file));
        if (local == hash || same_component) continue;
        file["old_sha256"] = local; file["id"] = sha256(path);
        result["files"].push_back(std::move(file)); total += size;
        if (total > 1024ULL * 1024 * 1024) invalid("Release modules exceed the total download limit.");
        if (path.starts_with("web/")) { services.insert("web"); services.insert("admin"); }
        auto module = path;
#ifdef _WIN32
        if (module.ends_with(".exe")) module.resize(module.size() - 4);
#endif
        if (module == "postplus") result["requires_launcher_restart"] = true;
        else if (module.starts_with("postplus-") && std::find(supervisor_services().begin(), supervisor_services().end(), module.substr(9)) != supervisor_services().end()) services.insert(module.substr(9));
    }
    for (const auto& [path, file] : baseline.items()) {
        (void)file;
        if (!permitted(path) || !paths.contains(path))
            invalid("Release omits an installed component; file removal is not supported.", "incomplete_release");
    }
    // Legacy installations have no fingerprint baseline. Their actual native
    // modules still define the minimum inventory of a compatible release.
    for (const auto& entry : fs::directory_iterator(options.install_directory)) {
        const auto path = entry.path().filename().string();
        if (permitted(path) && !paths.contains(path))
            invalid("Release omits an installed native module.", "incomplete_release");
    }
    for (const auto& service : supervisor_services()) if (services.contains(service)) result["services"].push_back(service);
    result["supported"] = true; result["changed_bytes"] = total;
    result["download_bytes"] = archive_download && !result["files"].empty() ? result["archive"]["size"] : Json(total);
    return result;
}
void verified_contents(const Json& file, std::string_view bytes) {
    if (bytes.size() != file.at("size").get<std::size_t>() || sha256(bytes) != file.at("sha256").get<std::string>()) invalid("Downloaded module checksum or size mismatch.", "checksum_mismatch");
}
Json rollback(const UpdateOptions& options, Json job) {
    const auto directory = job_path(options, job.at("job_id").get<std::string>());
    if (job.value("metadata_applied", false)) {
        const auto destination = options.install_directory / "postplus-update.json";
        const auto current = current_hash(destination), old = job.at("old_metadata_sha256").get<std::string>();
        if (current != old && current != job.at("new_metadata_sha256").get<std::string>() && !current.empty())
            invalid("Installed update metadata changed during commit; rollback will not overwrite it.", "local_change", 409);
        if (old.empty()) { if (!current.empty()) fs::remove(destination); }
        else if (current != old) {
            const auto bytes = read_file(directory / "backup" / "installed-manifest");
            if (sha256(bytes) != old) invalid("Update metadata rollback backup checksum mismatch.", "checksum_mismatch");
            atomic_file(destination, bytes, static_cast<fs::perms>(job.at("metadata_permissions").get<unsigned>()));
        }
        job["metadata_applied"] = false; save_job(options, job);
    }
    for (auto it = job["files"].rbegin(); it != job["files"].rend(); ++it) {
        if (!it->value("applied", false)) continue;
        const auto destination = target_path(options, it->at("path").get<std::string>());
        const auto current = current_hash(destination), old = it->at("old_sha256").get<std::string>();
        if (current != old && current != it->at("sha256").get<std::string>() && !current.empty()) invalid("An installed module changed after update; rollback will not overwrite it.", "local_change", 409);
        if (old.empty()) { if (!current.empty()) fs::remove(destination); }
        else if (current != old) {
            const auto bytes = read_file(directory / "backup" / it->at("id").get<std::string>(), max_module);
            if (sha256(bytes) != old) invalid("Update rollback backup checksum mismatch.", "checksum_mismatch");
            atomic_file(destination, bytes, static_cast<fs::perms>(it->at("permissions").get<unsigned>()));
        }
        (*it)["applied"] = false; save_job(options, job);
    }
    job["state"] = "rolled_back"; job["rolled_back"] = true; save_job(options, job); return public_job(std::move(job));
}
}

std::string update_build_version() {
#ifdef POSTPLUS_VERSION
    return POSTPLUS_VERSION;
#else
    return "0.2.1";
#endif
}
std::string update_platform() {
#ifdef _WIN32
    return "windows";
#elif defined(__APPLE__)
    return "macosx";
#else
    return "linux";
#endif
}
std::string update_architecture() {
#if defined(_M_ARM64) || defined(__aarch64__)
    return "arm64";
#elif defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    return "x64";
#elif defined(__x86_64__)
    return "x86_64";
#else
    return "unsupported";
#endif
}
Json check_update(const UpdateOptions& input) { return public_job(inspect_release(normalized(input))); }
std::string installed_update_version(const UpdateOptions& input) { return installed_version(normalized(input)); }
Json stage_update(const UpdateOptions& input, const std::string& version, const std::string& id,
    const std::atomic<bool>& cancel, const UpdateProgress& progress) {
    const auto options = normalized(input); Lease lease(options); const auto directory = job_path(options, id);
    if (fs::exists(directory / "job.json")) return update_job_status(options, id);
    private_directory(directory); private_directory(directory / "modules"); private_directory(directory / "backup");
    Json job{{"ok", true}, {"schema", 1}, {"job_id", id}, {"state", "staging"}, {"version", version}, {"files", Json::array()},
        {"services", Json::array()}, {"requires_launcher_restart", false}, {"downloaded_bytes", 0},
        {"install_directory", options.install_directory.string()}, {"web_directory", options.web_directory.string()}};
    save_job(options, job);
    try {
        if (cancel.load()) invalid("Update download cancelled.", "cancelled", 409);
        auto release = inspect_release(options);
        if (release.at("version") != version) invalid("The latest release changed; check and review it again.", "release_changed", 409);
        if (!release.value("supported", false)) invalid(release.at("message").get<std::string>(), "legacy_release", 409);
        if (!release.value("available", false)) invalid("This release is not newer than the installed version.", "not_newer", 409);
        for (const auto& [key, value] : release.items()) job[key] = value;
        job["state"] = "staging"; save_job(options, job);
        if (job.value("download_format", "") == "archive" && !job["files"].empty()) {
            const auto archive = job.at("archive");
            const auto bytes = download(options, archive.at("download_url").get<std::string>(), archive.at("size").get<std::size_t>());
            verified_contents(archive, bytes);
            job["downloaded_bytes"] = bytes.size(); save_job(options, job);
            if (progress) progress(public_job(job));
            extract_update_modules(bytes, archive.at("asset").get<std::string>(), version, job.at("files"), cancel,
                [&](const Json& file, std::string_view contents) {
                    verified_contents(file, contents);
                    private_file(directory / "modules" / file.at("id").get<std::string>(), contents);
                });
            job["archive"].erase("download_url");
        }
#ifdef POSTPLUS_LEGACY_UPDATES
        else for (auto& file : job["files"]) {
            if (cancel.load()) invalid("Update download cancelled.", "cancelled", 409);
            const auto bytes = download(options, file.at("download_url").get<std::string>(), file.at("size").get<std::size_t>());
            verified_contents(file, bytes); private_file(directory / "modules" / file.at("id").get<std::string>(), bytes);
            file.erase("download_url"); job["downloaded_bytes"] = job["downloaded_bytes"].get<std::uint64_t>() + bytes.size(); save_job(options, job);
            if (progress) progress(public_job(job));
        }
#endif
        if (cancel.load()) invalid("Update download cancelled.", "cancelled", 409);
        job["state"] = "staged"; save_job(options, job); return public_job(std::move(job));
    } catch (const std::exception& error) {
        const auto* update_error = dynamic_cast<const UpdateError*>(&error);
        job["state"] = update_error && update_error->code == "cancelled" ? "cancelled" : "failed";
        job["error"] = error.what(); job["code"] = update_error ? update_error->code : "update_failed"; save_job(options, job); throw;
    }
}
Json update_job_status(const UpdateOptions& input, const std::string& id) { return public_job(load_job(normalized(input), id)); }
Json apply_staged_update(const UpdateOptions& input, const std::string& id) {
    const auto options = normalized(input); Lease lease(options); auto job = load_job(options, id);
    const auto state = job.value("state", "");
    if (state == "complete" || state == "installed") return public_job(std::move(job));
    if (state != "staged") invalid("Only a verified staged update can be installed.", "invalid_state", 409);
    const auto directory = job_path(options, id);
    // Recheck every download and every original before changing any file.
    try {
      for (auto& file : job["files"]) {
        verified_contents(file, read_file(directory / "modules" / file.at("id").get<std::string>(), max_module));
        const auto destination = target_path(options, file.at("path").get<std::string>());
        if (current_hash(destination) != file.at("old_sha256").get<std::string>()) invalid("A local module changed after staging; check again.", "local_change", 409);
        const auto permissions = fs::exists(destination) ? fs::status(destination).permissions() :
            (file.at("executable").get<bool>() ? fs::perms::owner_all : fs::perms::owner_read | fs::perms::owner_write);
        file["permissions"] = static_cast<unsigned>(permissions);
        if (fs::exists(destination)) private_file(directory / "backup" / file.at("id").get<std::string>(), read_file(destination, max_module));
      }
      const auto metadata = options.install_directory / "postplus-update.json";
      job["old_metadata_sha256"] = current_hash(metadata);
      job["metadata_applied"] = false;
      if (fs::exists(metadata)) {
          job["metadata_permissions"] = static_cast<unsigned>(fs::status(metadata).permissions());
          private_file(directory / "backup" / "installed-manifest", read_file(metadata));
      }
    } catch (const std::exception& error) {
        job["state"] = "failed"; job["error"] = error.what(); save_job(options, job); throw;
    }
    job["state"] = "applying"; save_job(options, job);
    try {
        for (auto& file : job["files"]) {
            // Journal before rename: recovery can restore either generation.
            file["applied"] = true; save_job(options, job);
            const auto bytes = read_file(directory / "modules" / file.at("id").get<std::string>(), max_module);
            atomic_file(target_path(options, file.at("path").get<std::string>()), bytes, static_cast<fs::perms>(file.at("permissions").get<unsigned>()));
        }
        job["state"] = "installed"; save_job(options, job); return public_job(std::move(job));
    } catch (const std::exception& error) {
        job["error"] = error.what(); save_job(options, job);
        try { (void)rollback(options, job); } catch (const std::exception& failure) {
            job["state"] = "failed"; job["rollback_error"] = failure.what(); save_job(options, job);
        }
        throw;
    }
}
Json rollback_staged_update(const UpdateOptions& input, const std::string& id) {
    const auto options = normalized(input); Lease lease(options); auto job = load_job(options, id);
    if (job.value("state", "") == "rolled_back") return public_job(std::move(job));
    if (job.value("state", "") == "complete") invalid("Committed updates cannot be rolled back by replaying a job.", "invalid_state", 409);
    return rollback(options, std::move(job));
}
Json commit_staged_update(const UpdateOptions& input, const std::string& id) {
    const auto options = normalized(input); Lease lease(options); auto job = load_job(options, id);
    if (job.value("state", "") == "complete") return public_job(std::move(job));
    if (job.value("state", "") != "installed") invalid("Update readiness must succeed before commit.", "invalid_state", 409);
    for (const auto& file : job["files"]) if (current_hash(target_path(options, file.at("path").get<std::string>())) != file.at("sha256").get<std::string>()) invalid("Installed module changed before commit.", "local_change", 409);
    const auto metadata = job.at("installation_manifest").dump();
    // The installed version is part of the transaction too. A crash between
    // replacing this baseline and marking completion must restore both it and
    // the old modules rather than advertise an uncommitted release.
    job["new_metadata_sha256"] = sha256(metadata); job["metadata_applied"] = true; save_job(options, job);
    atomic_file(options.install_directory / "postplus-update.json", metadata);
    job["state"] = "complete"; save_job(options, job); return public_job(std::move(job));
}
std::vector<Json> recover_interrupted_updates(const UpdateOptions& input) {
    const auto options = normalized(input);
    std::vector<Json> results;
    if (!fs::exists(options.storage_directory)) return results;
    Lease lease(options);
    const auto relaunch = pending_update_relaunch(options);
    for (const auto& entry : fs::directory_iterator(options.storage_directory)) {
        const auto id = entry.path().filename().string();
        if (!hex(id, 32) || !fs::exists(entry.path() / "job.json")) continue;
        auto job = load_job(options, id);
        if (relaunch && relaunch->at("job_id") == id) continue;
        const auto state = job.value("state", "");
        const bool changed = job.value("metadata_applied", false) || std::any_of(job.at("files").begin(), job.at("files").end(),
            [](const Json& file) { return file.value("applied", false); });
        if (state == "complete" || state == "rolled_back" ||
            (state != "applying" && state != "installed" && !(state == "failed" && changed))) continue;
        if (job.value("requires_launcher_restart", false))
            invalid("An interrupted launcher update needs its relaunch recovery handoff.", "missing_relaunch", 503);
        try {
            (void)rollback(options, job);
            job = load_job(options, id); job["state"] = "failed"; job["rolled_back"] = true;
            job["error"] = "An interrupted module update was restored before service startup.";
            save_job(options, job); results.push_back(public_job(std::move(job)));
        } catch (const std::exception& error) {
            job = load_job(options, id); job["state"] = "failed"; job["rollback_error"] = error.what(); save_job(options, job);
            throw;
        }
    }
    return results;
}
Json recover_launcher_update(const UpdateOptions& input, const fs::path& config) {
    const auto options = normalized(input);
    if (!fs::exists(options.storage_directory)) return {{"ok", true}, {"state", "idle"}};
    Lease lease(options);
    const auto record = pending_update_relaunch(options);
    if (!record) return {{"ok", true}, {"state", "idle"}};
    const auto source = fs::absolute(config).lexically_normal(); plain(source);
    if (record->at("config") != source.string()) invalid("Launcher recovery belongs to another configuration.");
    const auto id = record->at("job_id").get<std::string>();
    auto job = load_job(options, id);
    if (!job.value("requires_launcher_restart", false)) invalid("Launcher recovery handoff does not contain a launcher update.");
    const auto state = job.value("state", "");
    if (state == "complete" || state == "rolled_back") return public_job(std::move(job));
    if (state == "installed" && !job.value("boot_attempt", false)) {
        job["boot_attempt"] = true; save_job(options, job); return public_job(std::move(job));
    }
    // A loader error, immediate crash, failed start-pre, or power loss cannot
    // make systemd execute the bad generation repeatedly. Keep the handoff so
    // restored service readiness reports failure and acknowledges recovery.
    job["error"] = "Updated launcher did not acknowledge readiness; previous modules were restored before relaunch.";
    save_job(options, job);
    return rollback(options, std::move(job));
}
fs::path copy_update_helper(const UpdateOptions& input, const std::string& id) {
    const auto options = normalized(input); (void)load_job(options, id);
#ifdef _WIN32
    const std::string name = "postplus-update.exe";
#else
    const std::string name = "postplus-update";
#endif
    const auto destination = job_path(options, id) / name;
    const auto bytes = read_file(options.install_directory / name, max_module);
    if (fs::exists(destination)) { if (read_file(destination, max_module) != bytes) invalid("Existing update helper differs from the installed helper."); return destination; }
    private_file(destination, bytes);
#ifndef _WIN32
    fs::permissions(destination, fs::perms::owner_all);
#endif
    return destination;
}
Json prepare_update_relaunch(const UpdateOptions& input, const std::string& id, const fs::path& config) {
    const auto options = normalized(input); const auto job = load_job(options, id);
    const auto source = fs::absolute(config).lexically_normal(); plain(source);
    if (!job.value("requires_launcher_restart", false) || (job.value("state", "") != "staged" && job.value("state", "") != "installed"))
        invalid("Launcher takeover requires a verified launcher update.", "invalid_state", 409);
    (void)Config::from_file(source);
    Json record{{"job_id", id}, {"config", source.string()}};
    const auto path = options.storage_directory / "relaunch.json";
    if (fs::exists(path)) {
        const auto existing = Json::parse(read_file(path));
        if (existing != record) invalid("Another launcher update is awaiting recovery.", "update_busy", 409);
    } else atomic_file(path, record.dump());
    return record;
}
std::optional<Json> pending_update_relaunch(const UpdateOptions& input) {
    const auto options = normalized(input); const auto path = options.storage_directory / "relaunch.json";
    if (!fs::exists(path)) return {};
    const auto record = Json::parse(read_file(path));
    (void)load_job(options, record.at("job_id").get<std::string>());
    return record;
}
void finish_update_relaunch(const UpdateOptions& input, const std::string& id) {
    const auto options = normalized(input); const auto record = pending_update_relaunch(options);
    if (record && record->at("job_id") == id) fs::remove(options.storage_directory / "relaunch.json");
}
void mark_update_takeover_ready(const UpdateOptions& input, const std::string& id) {
    const auto options = normalized(input); (void)load_job(options, id);
    atomic_file(job_path(options, id) / "takeover.ready", Json{{"job_id", id}}.dump());
}
void fail_staged_update(const UpdateOptions& input, const std::string& id, const std::string& error) {
    const auto options = normalized(input); Lease lease(options); auto job = load_job(options, id);
    if (job.value("state", "") == "complete") return;
    job["state"] = "failed"; job["error"] = error; save_job(options, job);
}
std::uint64_t launch_update_takeover(const UpdateOptions& input, const std::string& id, const fs::path& config, std::uint64_t parent_pid) {
#ifdef _WIN32
    const auto options = normalized(input);
    if (!parent_pid || parent_pid > MAXDWORD) invalid("Invalid launcher process identifier.");
    const auto helper = copy_update_helper(options, id);
    (void)prepare_update_relaunch(options, id, config);
    const auto acknowledgement = job_path(options, id) / "takeover.ready";
    if (fs::exists(acknowledgement)) fs::remove(acknowledgement);
    auto quote = [](const std::wstring& value) {
        std::wstring result = L"\""; std::size_t slashes = 0;
        for (const auto c : value) {
            if (c == L'\\') { ++slashes; continue; }
            result.append(slashes * (c == L'\"' ? 2 : 1), L'\\'); slashes = 0;
            if (c == L'\"') result += L'\\'; result += c;
        }
        result.append(slashes * 2, L'\\'); return result + L'\"';
    };
    std::wstring command = quote(helper.native()) + L" --takeover --parent " + std::to_wstring(parent_pid) +
        L" --job " + fs::path(id).native() + L" --install " + quote(options.install_directory.native()) +
        L" --web " + quote(options.web_directory.native()) + L" --state " + quote(options.storage_directory.native()) +
        L" --config " + quote(fs::absolute(config).native());
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(helper.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, options.install_directory.c_str(), &startup, &process)) {
        finish_update_relaunch(options, id); invalid("Cannot start detached update helper.");
    }
    CloseHandle(process.hThread);
    const auto deadline = Clock::now() + std::chrono::seconds(10);
    while (Clock::now() < deadline && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
        const auto ready = job_path(options, id) / "takeover.ready";
        if (fs::exists(ready) && Json::parse(read_file(ready)).at("job_id") == id) { CloseHandle(process.hProcess); return process.dwProcessId; }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 5000); CloseHandle(process.hProcess);
    finish_update_relaunch(options, id); invalid("Update helper did not acknowledge launcher takeover.");
#else
    (void)input; (void)id; (void)config; (void)parent_pid;
    invalid("Unix launcher updates must install before the service-manager or exec relaunch.", "invalid_takeover", 409);
#endif
}
}
