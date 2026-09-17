#include <postplus/core.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/password_policy.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <mutex>
#include <stdexcept>

namespace postplus {
namespace {
class Statement {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &value_, nullptr) != SQLITE_OK)
            throw std::runtime_error("authentication database query failed");
    }
    ~Statement() { sqlite3_finalize(value_); }
    Statement(const Statement&) = delete;
    void text(int index, const std::string& value) {
        if (sqlite3_bind_text(value_, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error("authentication database binding failed");
    }
    void bytes(int index, std::string_view value) {
        if (sqlite3_bind_blob(value_, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error("authentication database binding failed");
    }
    void integer(int index, int value) {
        if (sqlite3_bind_int(value_, index, value) != SQLITE_OK)
            throw std::runtime_error("authentication database binding failed");
    }
    void integer64(int index, std::int64_t value) {
        if (sqlite3_bind_int64(value_, index, value) != SQLITE_OK)
            throw std::runtime_error("authentication database binding failed");
    }
    int step() { return sqlite3_step(value_); }
    void done() {
        if (step() != SQLITE_DONE) throw std::runtime_error("authentication database update failed");
    }
    std::string string(int column) const {
        const auto* ptr = static_cast<const char*>(sqlite3_column_blob(value_, column));
        const int count = sqlite3_column_bytes(value_, column);
        return ptr ? std::string(ptr, static_cast<std::size_t>(count)) : std::string{};
    }
    int integer(int column) const { return sqlite3_column_int(value_, column); }
    std::int64_t integer64(int column) const { return sqlite3_column_int64(value_, column); }
private:
    sqlite3* db_;
    sqlite3_stmt* value_ = nullptr;
};

class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) {
        if (sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("cannot begin authentication database update");
    }
    ~Transaction() { if (active_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); }
    void commit() {
        if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("cannot commit authentication database update");
        active_ = false;
    }
    Transaction(const Transaction&) = delete;
private:
    sqlite3* db_;
    bool active_ = true;
};

std::string required_string(const Json& request, const char* key, std::size_t maximum) {
    if (!request.contains(key) || !request.at(key).is_string())
        throw std::invalid_argument(std::string("missing or invalid ") + key);
    auto value = request.at(key).get<std::string>();
    if (value.empty() || value.size() > maximum)
        throw std::invalid_argument(std::string("invalid ") + key + " length");
    return value;
}

std::string username_from(const Json& request) {
    auto name = lower(trim(required_string(request, "username", 254)));
    if (!valid_address(name)) throw std::invalid_argument("invalid username");
    return name;
}

std::string salt() {
    std::string result(16, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), static_cast<int>(result.size())) != 1)
        throw std::runtime_error("secure random generator failed");
    return result;
}

std::string password_hash(const std::string& password, const std::string& salt_value, int rounds) {
    std::string result(32, '\0');
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
            reinterpret_cast<const unsigned char*>(salt_value.data()), static_cast<int>(salt_value.size()),
            rounds, EVP_sha256(), static_cast<int>(result.size()),
            reinterpret_cast<unsigned char*>(result.data())) != 1)
        throw std::runtime_error("password hashing failed");
    return result;
}

class AuthStore {
public:
    explicit AuthStore(const Config& config)
        : rounds_(config.number("auth_pbkdf2_iterations", 600000)),
          max_password_(config.number("max_password_bytes", 1024)), dummy_salt_(salt()) {
        if (rounds_ < 600000 || rounds_ > 2000000)
            throw std::invalid_argument("auth_pbkdf2_iterations must be 600000..2000000");
        if (max_password_ < 12 || max_password_ > 4096)
            throw std::invalid_argument("max_password_bytes must be 12..4096");
        auto directory = std::filesystem::path(config.text("data_dir", "../data"));
        if (directory.is_relative()) directory = config.source.parent_path() / directory;
        if (std::filesystem::create_directories(directory)) {
#ifndef _WIN32
            std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
#endif
        }
        data_lock_ = std::make_unique<DataDirectoryLock>(directory);
        const auto path = (directory / "auth.sqlite3").u8string();
        if (sqlite3_open_v2(reinterpret_cast<const char*>(path.c_str()), &db_,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
            if (db_) sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("cannot open authentication database");
        }
        try {
            sqlite3_busy_timeout(db_, 5000);
            execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;");
            {
                Transaction migration(db_);
                {
                    Statement version(db_, "PRAGMA user_version");
                    if (version.step() != SQLITE_ROW || version.integer(0) > 2)
                        throw std::runtime_error("unsupported authentication database version");
                }
                execute("CREATE TABLE IF NOT EXISTS users ("
                    "username TEXT PRIMARY KEY, salt BLOB NOT NULL, password_hash BLOB NOT NULL,"
                    "iterations INTEGER NOT NULL, admin INTEGER NOT NULL CHECK(admin IN (0,1)),"
                    "created_at INTEGER NOT NULL DEFAULT (unixepoch()));"
                    "CREATE TABLE IF NOT EXISTS password_policy ("
                    "id INTEGER PRIMARY KEY CHECK(id=1), min_length INTEGER NOT NULL CHECK(min_length BETWEEN 8 AND 128),"
                    "require_uppercase INTEGER NOT NULL CHECK(require_uppercase IN (0,1)),"
                    "require_lowercase INTEGER NOT NULL CHECK(require_lowercase IN (0,1)),"
                    "require_digit INTEGER NOT NULL CHECK(require_digit IN (0,1)),"
                    "require_symbol INTEGER NOT NULL CHECK(require_symbol IN (0,1)),"
                    "revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991));"
                    "INSERT OR IGNORE INTO password_policy VALUES(1,12,0,0,0,0,1); PRAGMA user_version=2;");
                migration.commit();
            }
#ifndef _WIN32
            std::filesystem::permissions(directory / "auth.sqlite3", std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
#endif
        } catch (...) {
            sqlite3_close(db_);
            db_ = nullptr;
            throw;
        }
    }
    ~AuthStore() { if (db_) sqlite3_close(db_); }

    Json handle(const Json& request) {
        const auto operation = required_string(request, "op", 32);
        if (operation == "verify") return verify(request);
        if (operation == "password_policy_get") {
            std::lock_guard guard(mutex_);
            return policy_view();
        }
        if (operation == "password_policy_set") return save_policy(request);
        if (operation == "create" || operation == "change_password") {
            auto username = username_from(request);
            if (!request.contains("password") || !request.at("password").is_string())
                throw std::invalid_argument("missing or invalid password");
            const auto password = request.at("password").get<std::string>();
            {
                std::lock_guard guard(mutex_);
                if (const auto failure = check_password(password)) return *failure;
            }
            bool admin = false;
            if (request.contains("admin")) {
                if (!request.at("admin").is_boolean()) throw std::invalid_argument("admin must be boolean");
                admin = request.at("admin").get<bool>();
            }
            auto salt_value = salt();
            auto hash = password_hash(password, salt_value, rounds_);
            std::lock_guard guard(mutex_);
            Transaction transaction(db_);
            // A policy saved while hashing must also govern this write. The
            // transaction protects the check even if another auth process writes.
            if (const auto failure = check_password(password)) return *failure;
            if (operation == "create") {
                Statement insert(db_, "INSERT INTO users(username,salt,password_hash,iterations,admin) VALUES(?,?,?,?,?)");
                insert.text(1, username); insert.bytes(2, salt_value); insert.bytes(3, hash);
                insert.integer(4, rounds_); insert.integer(5, admin ? 1 : 0);
                const auto code = insert.step();
                if (code == SQLITE_CONSTRAINT) return {{"ok", false}, {"error", "user already exists"}};
                if (code != SQLITE_DONE) throw std::runtime_error("cannot create user");
            } else {
                Statement update(db_, "UPDATE users SET salt=?,password_hash=?,iterations=? WHERE username=?");
                update.bytes(1, salt_value); update.bytes(2, hash); update.integer(3, rounds_); update.text(4, username);
                update.done();
                if (sqlite3_changes(db_) != 1) return {{"ok", false}, {"error", "user does not exist"}};
            }
            transaction.commit();
            log("auth",(operation == "create" ? "account created: " : "password changed: ") + username);
            return {{"ok", true}, {"username", username}};
        }
        if (operation == "exists") {
            auto username = username_from(request);
            std::lock_guard guard(mutex_);
            Statement query(db_, "SELECT 1 FROM users WHERE username=?"); query.text(1, username);
            const auto code = query.step();
            if (code != SQLITE_ROW && code != SQLITE_DONE) throw std::runtime_error("cannot check user");
            return {{"ok", true}, {"exists", code == SQLITE_ROW}};
        }
        if (operation == "session_check") {
            const auto username = username_from(request);
            const auto version = required_string(request, "credential_version", 128);
            std::lock_guard guard(mutex_);
            Statement query(db_, "SELECT salt,admin FROM users WHERE username=?");
            query.text(1, username);
            const auto code = query.step();
            if (code != SQLITE_ROW && code != SQLITE_DONE) throw std::runtime_error("cannot check account session");
            return {{"ok", true}, {"valid", code == SQLITE_ROW && secure_equal(version, base64_encode(query.string(0)))},
                    {"admin", code == SQLITE_ROW && query.integer(1) != 0}};
        }
        if (operation == "list") {
            std::lock_guard guard(mutex_);
            Statement query(db_, "SELECT username,admin FROM users ORDER BY username");
            Json users = Json::array();
            for (int code; (code = query.step()) != SQLITE_DONE;) {
                if (code != SQLITE_ROW) throw std::runtime_error("cannot list users");
                users.push_back({{"username", query.string(0)}, {"admin", query.integer(1) != 0}});
            }
            return {{"ok", true}, {"users", std::move(users)}};
        }
        return {{"ok", false}, {"error", "unknown authentication operation"}};
    }
private:
    // Call only while holding mutex_; this always reads the persisted revision.
    Json policy_view() {
        Statement query(db_, "SELECT min_length,require_uppercase,require_lowercase,require_digit,require_symbol,revision "
                             "FROM password_policy WHERE id=1");
        if (query.step() != SQLITE_ROW) throw std::runtime_error("cannot read account password policy");
        PasswordPolicy policy{query.integer(0), query.integer(1) != 0, query.integer(2) != 0,
                              query.integer(3) != 0, query.integer(4) != 0};
        return {{"ok", true}, {"policy", password_policy_json(policy)}, {"revision", query.integer64(5)},
                {"max_password_bytes", max_password_}, {"length_unit", "unicode_code_points"}, {"restart_required", false}};
    }

    std::optional<Json> check_password(std::string_view password) {
        auto view = policy_view();
        auto violations = password_violations(password, parse_password_policy(view.at("policy")), static_cast<std::size_t>(max_password_));
        if (violations.empty()) return std::nullopt;
        view["ok"] = false;
        view["code"] = "password_policy_violation";
        view["error"] = "Password does not meet the account password policy.";
        view["violations"] = std::move(violations);
        return view;
    }

    Json save_policy(const Json& request) {
        auto errors = password_policy_errors(request.value("policy", Json()), max_password_);
        for (const auto& item : request.items()) {
            if (item.key() != "op" && item.key() != "revision" && item.key() != "policy")
                errors.push_back({{"field", item.key()}, {"code", "unknown_field"}});
        }
        constexpr std::int64_t max_revision = INT64_C(9007199254740991);
        if (!request.contains("revision")) errors.push_back({{"field", "revision"}, {"code", "required"}});
        else if (!request.at("revision").is_number_integer()) errors.push_back({{"field", "revision"}, {"code", "invalid_type"}});
        else if ((request.at("revision").is_number_unsigned() && request.at("revision").get<std::uint64_t>() > static_cast<std::uint64_t>(max_revision)) ||
                 request.at("revision").get<std::int64_t>() < 1 || request.at("revision").get<std::int64_t>() > max_revision)
            errors.push_back({{"field", "revision"}, {"code", "out_of_range"}, {"min", 1}, {"max", max_revision}});
        if (!errors.empty()) return {{"ok", false}, {"code", "invalid_password_policy"},
            {"error", "Check the password policy fields."}, {"errors", std::move(errors)}};
        const auto policy = parse_password_policy(request.at("policy"));
        const auto revision = request.at("revision").get<std::int64_t>();
        std::lock_guard guard(mutex_);
        Transaction transaction(db_);
        auto current = policy_view();
        if (revision != current.at("revision").get<std::int64_t>()) {
            current["ok"] = false;
            current["code"] = "password_policy_conflict";
            current["error"] = "Password policy changed. Reload it before saving again.";
            return current;
        }
        // An unchanged save is idempotent and does not advance the revision.
        if (current.at("policy") == request.at("policy")) return current;
        if (revision == max_revision) throw std::runtime_error("account password policy revision exhausted");
        Statement update(db_, "UPDATE password_policy SET min_length=?,require_uppercase=?,require_lowercase=?,require_digit=?,require_symbol=?,"
                              "revision=revision+1 WHERE id=1 AND revision=?");
        update.integer(1, policy.min_length); update.integer(2, policy.require_uppercase ? 1 : 0);
        update.integer(3, policy.require_lowercase ? 1 : 0); update.integer(4, policy.require_digit ? 1 : 0);
        update.integer(5, policy.require_symbol ? 1 : 0); update.integer64(6, revision); update.done();
        if (sqlite3_changes(db_) != 1) throw std::runtime_error("cannot save account password policy");
        current = policy_view();
        transaction.commit();
        log("auth", "account password policy changed to revision " + std::to_string(revision + 1));
        return current;
    }

    Json verify(const Json& request) {
        const auto username = username_from(request);
        const auto password = required_string(request, "password", static_cast<std::size_t>(max_password_));
        {
            // Shared across SMTP/POP3/IMAP/Web, with bounded state and hash work.
            std::lock_guard guard(rate_mutex_);
            const auto now = std::chrono::steady_clock::now();
            std::erase_if(attempts_, [now](const auto& item) { return item.second.expires <= now; });
            if (global_attempts_.expires <= now) global_attempts_ = {now + std::chrono::minutes(1), 0};
            if (global_attempts_.count >= 600 || (!attempts_.contains(username) && attempts_.size() >= 10000))
                return {{"ok",false},{"error","authentication rate limit"}};
            auto& rate = attempts_[username];
            if (rate.expires <= now) rate = {now + std::chrono::minutes(1), 0};
            if (rate.count >= 30) return {{"ok",false},{"error","authentication rate limit"}};
            ++rate.count;
            ++global_attempts_.count;
        }
        std::string salt_value = dummy_salt_, expected(32, '\0');
        int iterations = rounds_;
        bool found = false, admin = false;
        {
            std::lock_guard guard(mutex_);
            Statement query(db_, "SELECT salt,password_hash,iterations,admin FROM users WHERE username=?");
            query.text(1, username);
            const auto code = query.step();
            if (code == SQLITE_ROW) {
                salt_value = query.string(0); expected = query.string(1); iterations = query.integer(2);
                admin = query.integer(3) != 0; found = true;
                if (salt_value.size() != 16 || expected.size() != 32 || iterations < 600000 || iterations > 2000000)
                    throw std::runtime_error("invalid stored password record");
            } else if (code != SQLITE_DONE) throw std::runtime_error("cannot verify credentials");
        }
        const auto computed = password_hash(password, salt_value, iterations);
        const auto matches = secure_equal(computed, expected);
        if (!found || !matches) {
            log("auth","authentication failed: " + username,"warn");
            return {{"ok", false}, {"error", "invalid credentials"}};
        }
        if (iterations < rounds_) {
            auto new_salt = salt();
            auto new_hash = password_hash(password, new_salt, rounds_);
            std::lock_guard guard(mutex_);
            Statement update(db_, "UPDATE users SET salt=?,password_hash=?,iterations=? WHERE username=? AND password_hash=?");
            update.bytes(1, new_salt); update.bytes(2, new_hash); update.integer(3, rounds_);
            update.text(4, username); update.bytes(5, expected); update.done();
            if (sqlite3_changes(db_) == 1) salt_value = std::move(new_salt);
        }
        Json result = {{"ok", true}, {"username", username}, {"admin", admin}};
        // This version stays inside authenticated RPC and the web process.
        // Changing a password replaces the salt and revokes both web services'
        // sessions, including changes made through the command-line tool.
        if (request.value("session", false)) result["credential_version"] = base64_encode(salt_value);
        return result;
    }
    void execute(const char* sql) {
        if (sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error("authentication database initialization failed");
    }
    sqlite3* db_ = nullptr;
    std::unique_ptr<DataDirectoryLock> data_lock_;
    int rounds_, max_password_;
    std::string dummy_salt_;
    std::mutex mutex_;
    struct Rate { std::chrono::steady_clock::time_point expires; unsigned count = 0; };
    std::map<std::string, Rate> attempts_;
    Rate global_attempts_{};
    std::mutex rate_mutex_;
};
}
}

int main(int argc, char** argv) {
    return postplus::service_main("auth", argc, argv, [](const postplus::Config& config) {
        auto store = std::make_shared<postplus::AuthStore>(config);
        postplus::serve_rpc(config, "auth", [store](const postplus::Json& request) { return store->handle(request); });
    });
}
