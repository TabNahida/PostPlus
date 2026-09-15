#include <postplus/core.hpp>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace postplus {
namespace {
const std::array<std::string,11> services{"postplus","setup","auth","storage","filter","transfer","delivery","smtp","pop3","imap","web"};
const std::array<std::string,4> levels{"debug","info","warn","error"};
struct Settings {
    std::filesystem::path directory;
    std::string service;
    std::vector<std::string> secrets;
    std::size_t max_bytes = 5 * 1024 * 1024;
    int backups = 3;
    int threshold = 1;
};
Settings settings;
std::mutex logger_mutex;
bool known_service(const std::string& service) { return std::find(services.begin(),services.end(),service) != services.end(); }
int level_index(const std::string& level) {
    auto it = std::find(levels.begin(),levels.end(),level);
    if (it == levels.end()) throw std::invalid_argument("invalid log level");
    return static_cast<int>(it - levels.begin());
}
std::filesystem::path log_directory(const Config& config) {
    auto directory = std::filesystem::path(config.text("log_dir"));
    if (directory.empty()) directory = std::filesystem::path(config.text("data_dir","../data")) / "logs";
    if (directory.is_relative()) directory = config.source.parent_path() / directory;
    return std::filesystem::absolute(directory).lexically_normal();
}
void regular_or_absent(const std::filesystem::path& path) {
    const auto status = std::filesystem::symlink_status(path);
    if (std::filesystem::exists(status) && (!std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)))
        throw std::runtime_error("unsafe log file");
}

void create_log_directory(const std::filesystem::path& directory) {
    if (std::filesystem::is_symlink(std::filesystem::symlink_status(directory)))
        throw std::runtime_error("log directory must not be a symbolic link");
#ifdef _WIN32
    std::filesystem::create_directories(directory.parent_path());
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) throw std::runtime_error("cannot read log owner");
    DWORD size = 0;
    GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> user(size);
    const bool identified = GetTokenInformation(token,TokenUser,user.data(),size,&size) != 0;
    CloseHandle(token);
    if (!identified) throw std::runtime_error("cannot read log owner");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,&sid)) throw std::runtime_error("cannot read log owner");
    const std::wstring acl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&descriptor,nullptr))
        throw std::runtime_error("cannot create log permissions");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),descriptor,FALSE};
    const bool created = CreateDirectoryW(directory.c_str(),&attributes) != 0;
    const auto error = GetLastError();
    LocalFree(descriptor);
    if (!created && error != ERROR_ALREADY_EXISTS) throw std::runtime_error("cannot create log directory");
#else
    if (std::filesystem::create_directories(directory))
        std::filesystem::permissions(directory,std::filesystem::perms::owner_all);
#endif
    if (!std::filesystem::is_directory(directory)) throw std::runtime_error("invalid log directory");
}
class FileLock {
public:
    explicit FileLock(const std::filesystem::path& path) {
        regular_or_absent(path);
#ifdef _WIN32
        handle_ = CreateFileW(path.c_str(),GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open log lock");
        if (!LockFileEx(handle_,LOCKFILE_EXCLUSIVE_LOCK,0,1,0,&overlapped_)) {
            CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE;
            throw std::runtime_error("cannot lock log file");
        }
#else
        descriptor_ = ::open(path.c_str(),O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,0600);
        if (descriptor_ < 0) throw std::runtime_error("cannot open log lock");
        if (::flock(descriptor_,LOCK_EX) != 0) { ::close(descriptor_); descriptor_ = -1; throw std::runtime_error("cannot lock log file"); }
#endif
    }
    ~FileLock() {
#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) { UnlockFileEx(handle_,0,1,0,&overlapped_); CloseHandle(handle_); }
#else
        if (descriptor_ >= 0) { ::flock(descriptor_,LOCK_UN); ::close(descriptor_); }
#endif
    }
    FileLock(const FileLock&) = delete;
private:
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    OVERLAPPED overlapped_{};
#else
    int descriptor_ = -1;
#endif
};
std::string timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc,&seconds);
#else
    gmtime_r(&seconds,&utc);
#endif
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    std::ostringstream out;
    out << std::put_time(&utc,"%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << milliseconds << 'Z';
    return out.str();
}
std::string scrub(std::string message) {
    for (const auto& secret : settings.secrets) {
        if (secret.empty()) continue;
        std::size_t offset = 0;
        while ((offset = message.find(secret,offset)) != std::string::npos) {
            message.replace(offset,secret.size(),"[REDACTED]"); offset += 10;
        }
    }
    if (message.size() > 8192) message.resize(8192);
    // Preserve JSON escaping and keep terminal output on a single line.
    for (auto& c : message) if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' ';
    return message;
}
void append_file(const std::string& line) {
    const auto path = settings.directory / (settings.service + ".jsonl");
    FileLock lock(settings.directory / (settings.service + ".lock"));
    regular_or_absent(path);
    if (std::filesystem::exists(path) && std::filesystem::file_size(path) + line.size() > settings.max_bytes) {
        for (int index = settings.backups; index >= 1; --index) {
            const auto to = std::filesystem::path(path.string() + "." + std::to_string(index));
            const auto from = index == 1 ? path : std::filesystem::path(path.string() + "." + std::to_string(index-1));
            regular_or_absent(to); regular_or_absent(from);
            if (std::filesystem::exists(to)) std::filesystem::remove(to);
            if (std::filesystem::exists(from)) std::filesystem::rename(from,to);
        }
    }
#ifndef _WIN32
    const int file = ::open(path.c_str(),O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,0600);
    if (file < 0) throw std::runtime_error("cannot open log file");
    std::size_t offset = 0;
    while (offset < line.size()) {
        const auto written = ::write(file,line.data()+offset,line.size()-offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { ::close(file); throw std::runtime_error("cannot write log file"); }
        offset += static_cast<std::size_t>(written);
    }
    ::close(file);
#else
    std::ofstream file(path,std::ios::binary | std::ios::app);
    if (!file || !file.write(line.data(),static_cast<std::streamsize>(line.size()))) throw std::runtime_error("cannot write log file");
#endif
}
}
void configure_logging(const Config& config, const std::string& service) {
    if (!known_service(service) && service != "ctl") throw std::invalid_argument("unknown logging service");
    Settings next;
    next.directory = log_directory(config);
    next.service = service == "ctl" ? "postplus" : service;
    const auto maximum = config.number("log_max_bytes",5*1024*1024);
    next.backups = config.number("log_backups",3);
    if (maximum < 1024 || maximum > 100*1024*1024 || next.backups < 1 || next.backups > 10) throw std::invalid_argument("invalid log rotation settings");
    next.max_bytes = static_cast<std::size_t>(maximum);
    next.threshold = level_index(config.text("log_level","info"));
    try { next.secrets.push_back(config.token()); } catch (const std::exception&) {}
    const auto password_env = config.text("smarthost_password_env","POSTPLUS_SMARTHOST_PASSWORD");
    if (const char* value = std::getenv(password_env.c_str()); value && *value) next.secrets.emplace_back(value);
    create_log_directory(next.directory);
    std::lock_guard guard(logger_mutex);
    settings = std::move(next);
}
void log(const std::string& service, const std::string& message, const std::string& level) {
    std::lock_guard guard(logger_mutex);
    try {
        if (level_index(level) < settings.threshold) return;
        auto clean = scrub(message);
        const auto source = service == "ctl" ? "postplus" : service;
        const auto time = timestamp();
#ifdef _WIN32
        const auto pid = GetCurrentProcessId();
#else
        const auto pid = getpid();
#endif
        Json entry{{"timestamp",time},{"service",source},{"level",level},{"pid",pid},{"message",clean}};
        auto line = entry.dump(-1,' ',false,Json::error_handler_t::replace) + "\n";
        while (line.size() > settings.max_bytes && !clean.empty()) {
            clean.resize(clean.size()/2);
            entry["message"] = clean;
            line = entry.dump(-1,' ',false,Json::error_handler_t::replace) + "\n";
        }
        std::cerr << time << " [" << service << "] [" << level << "] " << clean << '\n';
        if (!settings.directory.empty()) append_file(line);
    } catch (const std::exception&) {
        // Logging failure must not abort a mail transaction or expose the original text.
        std::cerr << "[logging] unable to persist log entry\n";
    }
}
Json read_logs(const Config& config, const std::string& service, const std::string& level, std::size_t limit) {
    if (!service.empty() && !known_service(service)) throw std::invalid_argument("unknown log service");
    if (!level.empty()) (void)level_index(level);
    if (!limit || limit > 500) throw std::invalid_argument("log limit must be 1..500");
    const auto directory = log_directory(config);
    const auto backups = std::clamp(config.number("log_backups",3),1,10);
    std::vector<Json> entries;
    bool truncated = false;
    constexpr std::streamoff tail_bytes = 64 * 1024;
    auto newest = [](const Json& a,const Json& b) { return a.at("timestamp").get_ref<const std::string&>() > b.at("timestamp").get_ref<const std::string&>(); };
    for (const auto& name : services) {
        if (!service.empty() && name != service) continue;
        for (int part = 0; part <= backups; ++part) {
            const auto path = directory / (name + ".jsonl" + (part ? "." + std::to_string(part) : ""));
            try {
                regular_or_absent(path);
                std::ifstream file(path,std::ios::binary);
                if (!file) continue;
                file.seekg(0,std::ios::end);
                auto size = file.tellg();
                if (size < 0) continue;
                file.seekg(size > tail_bytes ? size - tail_bytes : std::streampos(0));
                std::string tail(static_cast<std::size_t>(std::min<std::streamoff>(size,tail_bytes)),'\0');
                file.read(tail.data(),static_cast<std::streamsize>(tail.size()));
                tail.resize(static_cast<std::size_t>(file.gcount()));
                std::istringstream snapshot(tail);
                std::string line;
                if (size > tail_bytes) { std::getline(snapshot,line); truncated = true; }
                while (std::getline(snapshot,line)) {
                    if (line.size() > 16384) continue;
                    auto item = Json::parse(line,nullptr,false);
                    if (!item.is_object() || !item.value("timestamp",Json()).is_string() || !item.value("message",Json()).is_string() ||
                        !item.value("service",Json()).is_string() || !item.value("level",Json()).is_string() || !item.value("pid",Json()).is_number_integer()) continue;
                    if (!level.empty() && item.at("level") != level) continue;
                    entries.push_back(std::move(item));
                    if (entries.size() >= limit * 2) {
                        std::stable_sort(entries.begin(),entries.end(),newest);
                        entries.resize(limit); truncated = true;
                    }
                }
            } catch (const std::exception&) { /* A concurrent rotation can remove a file; skip that tail. */ }
        }
    }
    std::stable_sort(entries.begin(),entries.end(),newest);
    if (entries.size() > limit) { entries.resize(limit); truncated = true; }
    return {{"ok",true},{"entries",entries},{"services",services},{"truncated",truncated}};
}
}
