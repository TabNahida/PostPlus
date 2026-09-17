#include <postplus/maintenance.hpp>
#include <postplus/data_lock.hpp>
#include <sqlite3.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace postplus {
namespace {
namespace fs = std::filesystem;
#ifdef _WIN32
class PrivateSecurity {
public:
    explicit PrivateSecurity(bool directory = false) {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw MaintenanceError("Cannot read process identity.");
        DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<unsigned char> user(size);
        const bool success = GetTokenInformation(token, TokenUser, user.data(), size, &size) != 0;
        CloseHandle(token);
        if (!success) throw MaintenanceError("Cannot read process identity.");
        LPWSTR sid = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid)) throw MaintenanceError("Cannot read process identity.");
        const auto flags = directory ? L"OICI" : L"";
        const auto acl = L"D:P(A;" + std::wstring(flags) + L";FA;;;SY)(A;" + flags + L";FA;;;" + std::wstring(sid) + L")";
        LocalFree(sid);
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor_, nullptr)) throw MaintenanceError("Cannot set private file permissions.");
        attributes_ = {sizeof(SECURITY_ATTRIBUTES), descriptor_, FALSE};
    }
    ~PrivateSecurity() { LocalFree(descriptor_); }
    SECURITY_ATTRIBUTES* get() { return &attributes_; }
private:
    PSECURITY_DESCRIPTOR descriptor_ = nullptr;
    SECURITY_ATTRIBUTES attributes_{};
};
#endif

void private_directory(const fs::path& path) {
    require_plain_path(path.parent_path());
#ifdef _WIN32
    PrivateSecurity security(true);
    if (!CreateDirectoryW(path.c_str(), security.get())) throw MaintenanceError("Cannot create private maintenance directory.");
#else
    if (::mkdir(path.c_str(), 0700) != 0) throw MaintenanceError("Cannot create private maintenance directory.");
#endif
}
void private_write(const fs::path& path, std::string_view contents) {
#ifdef _WIN32
    PrivateSecurity security;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, security.get(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw MaintenanceError("Cannot create private maintenance file.");
    DWORD written = 0;
    const bool saved = WriteFile(file, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) != 0 && written == contents.size() && FlushFileBuffers(file) != 0;
    CloseHandle(file);
    if (!saved) { DeleteFileW(path.c_str()); throw MaintenanceError("Cannot save maintenance file."); }
#else
    const int file = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0) throw MaintenanceError("Cannot create private maintenance file.");
    std::size_t offset = 0; bool saved = true;
    while (offset < contents.size()) {
        const auto count = ::write(file, contents.data() + offset, contents.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { saved = false; break; }
        offset += static_cast<std::size_t>(count);
    }
    if (::fsync(file) != 0) saved = false;
    if (::close(file) != 0) saved = false;
    if (!saved) { ::unlink(path.c_str()); throw MaintenanceError("Cannot save maintenance file."); }
#endif
}

std::string read_small(const fs::path& path, std::uintmax_t limit = 1024 * 1024) {
    require_plain_path(path);
    if (!fs::is_regular_file(path) || fs::file_size(path) > limit) throw MaintenanceError("Invalid maintenance input file.");
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw MaintenanceError("Cannot read maintenance input file.");
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

class Database {
public:
    Database(const fs::path& path, int flags) {
        require_plain_path(path);
        const auto utf8 = path.u8string();
        if (sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &db_, flags | SQLITE_OPEN_NOMUTEX, nullptr) != SQLITE_OK) {
            if (db_) sqlite3_close(db_);
            db_ = nullptr;
            throw MaintenanceError("Cannot open a database for backup.");
        }
        sqlite3_busy_timeout(db_, 5000);
    }
    ~Database() { if (db_) sqlite3_close(db_); }
    Database(const Database&) = delete;
    sqlite3* get() { return db_; }
    void exec(const char* sql) {
        if (sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) != SQLITE_OK) throw MaintenanceError("Cannot establish database backup snapshot; retry when the server is less busy.");
    }
private:
    sqlite3* db_ = nullptr;
};

void copy_database(Database& source, const fs::path& path, const std::atomic<bool>& cancel) {
    private_write(path, "");
    Database destination(path, SQLITE_OPEN_READWRITE);
    auto* backup = sqlite3_backup_init(destination.get(), "main", source.get(), "main");
    if (!backup) throw MaintenanceError("Cannot initialize database backup.");
    int result = SQLITE_OK;
    while (!cancel.load()) {
        result = sqlite3_backup_step(backup, 256);
        if (result != SQLITE_OK) break;
        std::this_thread::yield();
    }
    const int finished = sqlite3_backup_finish(backup);
    if (cancel.load()) throw MaintenanceError("Backup cancelled during server shutdown.");
    if (result != SQLITE_DONE || finished != SQLITE_OK) throw MaintenanceError("Database backup failed; check free disk space and retry.");
    // Persist a standalone database. Restoring requires no WAL or SHM files.
    destination.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;");
}

class Tar {
public:
    Tar(const fs::path& path, const std::atomic<bool>& cancel) : cancel_(cancel) {
        private_write(path, "");
        output_.open(path, std::ios::binary | std::ios::trunc);
        if (!output_) throw MaintenanceError("Cannot create backup archive.");
    }
    void bytes(const std::string& name, std::string_view contents) {
        header(name, contents.size());
        write(contents.data(), contents.size());
        padding(contents.size());
    }
    void file(const std::string& name, const fs::path& path) {
        require_plain_path(path);
        const auto size = fs::file_size(path);
        header(name, size);
        std::ifstream input(path, std::ios::binary);
        std::array<char, 65536> buffer{};
        auto remaining = size;
        while (remaining) {
            const auto count = static_cast<std::streamsize>(std::min<std::uintmax_t>(remaining, buffer.size()));
            if (!input.read(buffer.data(), count)) throw MaintenanceError("Cannot read database snapshot.");
            write(buffer.data(), static_cast<std::size_t>(count));
            remaining -= static_cast<std::uintmax_t>(count);
        }
        padding(size);
    }
    void finish() {
        std::array<char, 1024> zero{};
        write(zero.data(), zero.size());
        output_.flush();
        if (!output_) throw MaintenanceError("Cannot finish backup archive; check free disk space.");
        output_.close();
        if (!output_) throw MaintenanceError("Cannot close backup archive.");
    }
private:
    std::ofstream output_;
    const std::atomic<bool>& cancel_;
    void write(const char* data, std::size_t size) {
        if (cancel_.load()) throw MaintenanceError("Backup cancelled during server shutdown.");
        if (!output_.write(data, static_cast<std::streamsize>(size))) throw MaintenanceError("Cannot write backup archive; check free disk space.");
    }
    static void octal(char* buffer, std::size_t size, std::uint64_t value) {
        std::ostringstream text;
        text << std::oct << std::setw(static_cast<int>(size - 1)) << std::setfill('0') << value;
        const auto number = text.str();
        if (number.size() != size - 1) throw MaintenanceError("Backup archive field is too large.");
        std::memcpy(buffer, number.data(), number.size());
    }
    void header(const std::string& name, std::uint64_t size) {
        std::array<char, 512> block{};
        if (name.size() > 99) throw MaintenanceError("Backup archive path is too long.");
        std::memcpy(block.data(), name.data(), name.size());
        octal(block.data() + 100, 8, 0600);
        octal(block.data() + 108, 8, 0);
        octal(block.data() + 116, 8, 0);
        if (size < (UINT64_C(1) << 33)) octal(block.data() + 124, 12, size);
        else { // Standard GNU/base-256 tar extension, supported by BSD tar too.
            block[124] = static_cast<char>(0x80);
            auto value = size;
            for (int i = 135; i >= 128; --i) { block[static_cast<std::size_t>(i)] = static_cast<char>(value & 255); value >>= 8; }
        }
        octal(block.data() + 136, 12, static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())));
        std::fill_n(block.data() + 148, 8, ' ');
        block[156] = '0';
        std::memcpy(block.data() + 257, "ustar", 5);
        std::memcpy(block.data() + 263, "00", 2);
        unsigned sum = 0;
        for (const auto byte : block) sum += static_cast<unsigned char>(byte);
        octal(block.data() + 148, 7, sum);
        block[155] = ' ';
        write(block.data(), block.size());
    }
    void padding(std::uintmax_t size) {
        std::array<char, 512> zero{};
        write(zero.data(), static_cast<std::size_t>((512 - size % 512) % 512));
    }
};

constexpr std::string_view restore_instructions =
    "PostPlus backup, format 1\n\n"
    "This archive contains passwords hashes, mailbox contents and private keys.\n"
    "Keep it private. It is not encrypted.\n\n"
    "Restore into a NEW, empty, private directory, never over a live server.\n"
    "1. Stop PostPlus. Keep the original installation intact until verified.\n"
    "2. Extract this archive using tar into a private directory.\n"
    "3. Copy the matching PostPlus binaries and web directory from a release.\n"
    "4. Restrict access to the directory/files to the server operating-system user.\n"
    "5. Review config/postplus.json: ports, bind addresses, relay and TLS settings.\n"
    "   Paths for data, web assets, secrets and TLS files are portable.\n"
    "   Existing service-token/relay environment variables still override files.\n"
    "6. Start postplus --config config/postplus.json. Verify accounts and mail.\n\n"
    "The databases share one snapshot point. Queued deliveries may be retried;\n"
    "an external delivery completed after the snapshot can be sent again.\n"
    "Logs, executables, previous backups and ACME account registration are omitted.\n"
    "The configured TLS certificate and private key are included; expired certificates\n"
    "must be replaced. Saved settings are included; unsaved browser forms are not.\n";

void snapshot(const Config& live, const fs::path& directory, const std::atomic<bool>& cancel) {
    DataDirectoryLock data_lease(fs::path(live.text("data_dir")));
    const auto saved_bytes = read_small(live.source);
    auto saved = Config::from_file(live.source);
    auto portable = saved.values;
    portable["data_dir"] = "../data";
    portable["log_dir"] = "../data/logs";
    portable["web_root"] = "../web";
    portable["service_token_file"] = "service-token.secret";
    portable["setup_complete"] = true;
    portable.erase("setup_required");
    const auto token = saved.token();
    const auto relay = saved.relay_password();
    portable["smarthost_password_file"] = relay.empty() ? "" : "smarthost.secret";
    std::string certificate, key;
    if (!saved.text("tls_certificate").empty()) {
        certificate = read_small(saved.text("tls_certificate"));
        key = read_small(saved.text("tls_private_key"));
        portable["tls_certificate"] = "certificates/fullchain.pem";
        portable["tls_private_key"] = "certificates/private-key.pem";
    }
    const auto data = fs::path(live.text("data_dir"));
    const auto auth_path = data / "auth.sqlite3", storage_path = data / "storage.sqlite3";
    // Hold both reserved writer locks briefly while opening fixed read snapshots.
    // WAL allows normal writes again during the long copy. Account and mailbox
    // changes therefore cannot produce snapshots from different instants.
    Database storage_lock(storage_path, SQLITE_OPEN_READWRITE), auth_lock(auth_path, SQLITE_OPEN_READWRITE);
    storage_lock.exec("BEGIN IMMEDIATE");
    auth_lock.exec("BEGIN IMMEDIATE");
    Database storage_source(storage_path, SQLITE_OPEN_READONLY), auth_source(auth_path, SQLITE_OPEN_READONLY);
    storage_source.exec("BEGIN; SELECT count(*) FROM sqlite_schema;");
    auth_source.exec("BEGIN; SELECT count(*) FROM sqlite_schema;");
    auth_lock.exec("ROLLBACK");
    storage_lock.exec("ROLLBACK");
    copy_database(storage_source, directory / "storage.sqlite3", cancel);
    copy_database(auth_source, directory / "auth.sqlite3", cancel);
    storage_source.exec("ROLLBACK"); auth_source.exec("ROLLBACK");
    if (read_small(live.source) != saved_bytes) throw MaintenanceError("Configuration changed during backup; retry the backup.", 409);
    Tar archive(directory / "postplus-backup.tar", cancel);
    archive.file("data/auth.sqlite3", directory / "auth.sqlite3");
    archive.file("data/storage.sqlite3", directory / "storage.sqlite3");
    archive.bytes("config/postplus.json", portable.dump(2) + "\n");
    archive.bytes("config/service-token.secret", token);
    if (!relay.empty()) archive.bytes("config/smarthost.secret", relay);
    if (!certificate.empty()) {
        archive.bytes("config/certificates/fullchain.pem", certificate);
        archive.bytes("config/certificates/private-key.pem", key);
    }
    archive.bytes("manifest.json", Json{{"format", 1}, {"product", "PostPlus"}, {"version", "0.1.0"},
        {"created_at", std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())},
        {"snapshot", "coordinated SQLite read transactions"}, {"encrypted", false}}.dump(2) + "\n");
    archive.bytes("RESTORE.txt", restore_instructions);
    archive.finish();
    fs::remove(directory / "auth.sqlite3");
    fs::remove(directory / "storage.sqlite3");
}

void remove_owned_directory(const fs::path& directory) noexcept {
    // Only fixed files in a randomly generated directory owned by this object.
    std::error_code ignored;
    for (const auto* name : {"postplus-backup.tar", "auth.sqlite3", "storage.sqlite3", "auth.sqlite3-journal", "storage.sqlite3-journal", "auth.sqlite3-wal", "auth.sqlite3-shm", "storage.sqlite3-wal", "storage.sqlite3-shm", "shutdown.request", "shutdown.tmp", "identity.json"}) fs::remove(directory / name, ignored);
    fs::remove(directory, ignored);
}
}

struct BackupManager::Impl {
    Config config;
    mutable std::mutex mutex;
    std::thread worker;
    std::atomic<bool> cancel = false;
    std::string id, state = "idle", error;
    fs::path directory;
    std::vector<std::weak_ptr<std::ifstream>> downloads;
    explicit Impl(const Config& value) : config(value) {}
    ~Impl() {
        cancel.store(true);
        if (worker.joinable()) worker.join();
        if (!directory.empty()) remove_owned_directory(directory);
    }
};
BackupManager::BackupManager(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
BackupManager::~BackupManager() = default;
bool BackupManager::busy() const { std::lock_guard lock(impl_->mutex); return impl_->state == "running"; }
Json BackupManager::start() {
    std::lock_guard lock(impl_->mutex);
    if (impl_->state == "running") throw MaintenanceError("A backup is already running.", 409);
    std::erase_if(impl_->downloads, [](const auto& file) { return file.expired(); });
    if (!impl_->downloads.empty()) throw MaintenanceError("Wait for the current backup download to finish before starting another backup.", 409);
    if (impl_->worker.joinable()) impl_->worker.join();
    if (!impl_->directory.empty()) remove_owned_directory(impl_->directory);
    impl_->id = random_hex(16);
    impl_->directory = fs::path(impl_->config.text("data_dir")) / (".backup-" + impl_->id);
    private_directory(impl_->directory);
    impl_->state = "running"; impl_->error.clear();
    impl_->worker = std::thread([state = impl_.get()] {
        try {
            snapshot(state->config, state->directory, state->cancel);
            std::lock_guard guard(state->mutex); state->state = "complete";
            log("admin", "data backup completed");
        } catch (const std::exception& error) {
            remove_owned_directory(state->directory);
            std::lock_guard guard(state->mutex); state->state = "failed"; state->error = error.what();
            log("admin", "data backup failed", "error");
        }
    });
    return {{"ok", true}, {"job_id", impl_->id}, {"state", impl_->state}};
}
Json BackupManager::status(const std::string& id) {
    std::lock_guard lock(impl_->mutex);
    if (id.empty() || id != impl_->id) throw MaintenanceError("Backup job not found.", 404);
    Json result{{"ok", true}, {"job_id", id}, {"state", impl_->state}};
    if (impl_->state == "failed") result["error"] = impl_->error;
    if (impl_->state == "complete") result["download_url"] = "/api/admin/backup/download?job_id=" + id;
    return result;
}
HttpResponse BackupManager::download(const std::string& id) {
    std::lock_guard lock(impl_->mutex);
    if (id.empty() || id != impl_->id) throw MaintenanceError("Backup job not found.", 404);
    if (impl_->state != "complete") throw MaintenanceError("Backup is not ready.", 409);
    const auto path = impl_->directory / "postplus-backup.tar";
    require_plain_path(path);
    auto file = std::make_shared<std::ifstream>(path, std::ios::binary);
    if (!*file) throw MaintenanceError("Cannot read backup archive.");
    impl_->downloads.emplace_back(file);
    HttpResponse response;
    response.content_type = "application/x-tar";
    response.file = std::move(file);
    response.file_size = fs::file_size(path);
    response.headers["Content-Disposition"] = "attachment; filename=\"postplus-backup-" + id + ".tar\"";
    return response;
}

SupervisorControl::SupervisorControl(const Config& config) :
    directory_(fs::path(config.text("data_dir")) / (".supervisor-" + random_hex(16))), token_(random_hex(32)) {
    private_directory(directory_);
    try {
        private_write(directory_ / "identity.json", Json{{"config", config.source.string()}, {"token", token_}}.dump());
#ifdef _WIN32
        if (_wputenv_s(L"POSTPLUS_SUPERVISOR_CONTROL", directory_.c_str()) != 0) throw MaintenanceError("Cannot initialize supervisor control.");
#else
        if (setenv("POSTPLUS_SUPERVISOR_CONTROL", directory_.c_str(), 1) != 0) throw MaintenanceError("Cannot initialize supervisor control.");
#endif
    } catch (...) { remove_owned_directory(directory_); throw; }
}
SupervisorControl::~SupervisorControl() { remove_owned_directory(directory_); }
bool SupervisorControl::shutdown_requested() {
    const auto path = directory_ / "shutdown.request";
    if (!fs::exists(path)) return false;
    const auto request = Json::parse(read_small(path, 4096));
    fs::remove(path);
    if (!request.is_object() || !request.contains("token") || !request["token"].is_string() ||
        !secure_equal(request.at("token").get<std::string>(), token_)) {
        log("postplus", "rejected invalid supervisor control request", "warn");
        return false;
    }
    // Leave enough time for the admin service to finish its accepted response.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    return true;
}
void request_supervisor_shutdown(const Config& config) {
#ifdef _WIN32
    const auto* value = _wgetenv(L"POSTPLUS_SUPERVISOR_CONTROL");
#else
    const auto* value = std::getenv("POSTPLUS_SUPERVISOR_CONTROL");
#endif
    if (!value || !*value) throw MaintenanceError("Start PostPlus with the native postplus launcher to use web shutdown.");
    const auto directory = fs::path(value);
    require_plain_path(directory);
    const auto identity = Json::parse(read_small(directory / "identity.json", 4096));
    if (identity.value("config", "") != config.source.string() || identity.value("token", "").size() != 64)
        throw MaintenanceError("Supervisor control does not match this server.");
    const auto temporary = directory / "shutdown.tmp";
    private_write(temporary, Json{{"token", identity.at("token")}}.dump());
    fs::rename(temporary, directory / "shutdown.request");
}
}
