#include <postplus/core.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/password_policy.hpp>
#include <postplus/access.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <mutex>
#include <set>
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
    bool is_null(int column) const { return sqlite3_column_type(value_, column) == SQLITE_NULL; }
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

bool valid_api_key(std::string_view value) {
    return value.size() == 67 && value.starts_with("pp_") &&
        std::all_of(value.begin() + 3, value.end(), [](unsigned char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        });
}

std::string api_key_digest(std::string_view value) {
    std::string result(32, '\0');
    unsigned int count = 0;
    if (EVP_Digest(value.data(), value.size(), reinterpret_cast<unsigned char*>(result.data()),
                   &count, EVP_sha256(), nullptr) != 1 || count != result.size())
        throw std::runtime_error("API key hashing failed");
    return result;
}

std::int64_t unix_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

class AuthStore {
public:
    explicit AuthStore(const Config& config)
        : rounds_(config.number("auth_pbkdf2_iterations", 600000)),
          max_password_(config.number("max_password_bytes", 1024)), dummy_salt_(salt()),
          domain_(lower(trim(config.text("domain", "localhost")))) {
        if (!valid_address("postmaster@" + domain_)) throw std::invalid_argument("invalid invitation domain");
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
                    if (version.step() != SQLITE_ROW || version.integer(0) > 4)
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
                    "INSERT OR IGNORE INTO password_policy VALUES(1,8,0,0,0,0,1);"
                    "CREATE TABLE IF NOT EXISTS api_keys ("
                    "id TEXT PRIMARY KEY, name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),"
                    "prefix TEXT NOT NULL, owner TEXT NOT NULL, digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32),"
                    "created_at INTEGER NOT NULL, expires_at INTEGER, last_used_at INTEGER, revoked_at INTEGER);"
                    "CREATE INDEX IF NOT EXISTS api_keys_owner ON api_keys(owner);");
                std::set<std::string> columns;
                {
                    Statement schema(db_, "PRAGMA table_info(api_keys)");
                    for (int code; (code = schema.step()) != SQLITE_DONE;) {
                        if (code != SQLITE_ROW) throw std::runtime_error("cannot inspect API key schema");
                        columns.insert(schema.string(1));
                    }
                }
                if (!columns.contains("audience")) execute("ALTER TABLE api_keys ADD COLUMN audience TEXT NOT NULL DEFAULT 'admin';");
                if (!columns.contains("permissions")) {
                    execute("ALTER TABLE api_keys ADD COLUMN permissions TEXT NOT NULL DEFAULT '[]';");
                    Statement migrate(db_, "UPDATE api_keys SET permissions=?");
                    migrate.text(1, Json(api_key_permission_ids("admin")).dump()); migrate.done();
                }
                execute("CREATE TABLE IF NOT EXISTS invitations ("
                    "id TEXT PRIMARY KEY, name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),"
                    "owner TEXT NOT NULL, digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32),"
                    "domain TEXT NOT NULL, localpart TEXT NOT NULL, created_at INTEGER NOT NULL,"
                    "expires_at INTEGER NOT NULL, max_uses INTEGER NOT NULL CHECK(max_uses BETWEEN 1 AND 100),"
                    "uses INTEGER NOT NULL DEFAULT 0 CHECK(uses>=0 AND uses<=max_uses), revoked_at INTEGER);"
                    "CREATE TABLE IF NOT EXISTS account_deletions (username TEXT PRIMARY KEY, cleanup_id TEXT NOT NULL);"
                    "PRAGMA user_version=4;");
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
        if (operation == "api_key_verify") return verify_api_key(request);
        if (operation == "api_key_list" || operation == "api_key_create" || operation == "api_key_update" || operation == "api_key_revoke")
            return manage_api_keys(request, operation);
        if (operation == "invite_create" || operation == "invite_list" || operation == "invite_revoke")
            return manage_invitations(request, operation);
        if (operation == "invite_inspect" || operation == "invite_redeem") return redeem_invitation(request, operation);
        if (operation == "user_delete" || operation == "user_delete_finish") return delete_user(request, operation);
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
                Statement pending(db_, "SELECT 1 FROM account_deletions WHERE username=?"); pending.text(1, username);
                if (pending.step() == SQLITE_ROW)
                    return {{"ok", false}, {"code", "account_cleanup_pending"}, {"error", "Finish deleting this account before reusing its address."}};
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
            Statement pending(db_, "SELECT username FROM account_deletions ORDER BY username");
            for (int code; (code = pending.step()) != SQLITE_DONE;) {
                if (code != SQLITE_ROW) throw std::runtime_error("cannot list pending account deletions");
                users.push_back({{"username", pending.string(0)}, {"admin", false}, {"deletion_pending", true}});
            }
            return {{"ok", true}, {"users", std::move(users)}};
        }
        return {{"ok", false}, {"error", "unknown authentication operation"}};
    }
private:
    Json delete_user(const Json& request, const std::string& operation) {
        const auto username = username_from(request);
        const auto actor = lower(trim(required_string(request, "actor", 254)));
        if (!valid_address(actor)) throw std::invalid_argument("invalid actor");
        std::lock_guard guard(mutex_); Transaction transaction(db_);
        Statement administrator(db_, "SELECT admin FROM users WHERE username=?"); administrator.text(1, actor);
        if (administrator.step() != SQLITE_ROW || administrator.integer(0) != 1)
            return {{"ok", false}, {"code", "administrator_required"}, {"error", "Administrator access is required."}};
        if (actor == username)
            return {{"ok", false}, {"code", "account_delete_self"}, {"error", "You cannot delete your signed-in account."}};
        Statement pending(db_, "SELECT cleanup_id FROM account_deletions WHERE username=?"); pending.text(1, username);
        if (operation == "user_delete_finish") {
            const auto cleanup_id = required_string(request, "cleanup_id", 64);
            if (pending.step() != SQLITE_ROW || !secure_equal(cleanup_id, pending.string(0)))
                return {{"ok", false}, {"code", "account_delete_conflict"}, {"error", "Account deletion changed. Refresh the account list."}};
            Statement done(db_, "DELETE FROM account_deletions WHERE username=?"); done.text(1, username); done.done();
            transaction.commit(); return {{"ok", true}, {"username", username}};
        }
        if (pending.step() == SQLITE_ROW)
            return {{"ok", true}, {"username", username}, {"cleanup_id", pending.string(0)}};
        Statement account(db_, "SELECT admin FROM users WHERE username=?"); account.text(1, username);
        if (account.step() != SQLITE_ROW)
            return {{"ok", false}, {"code", "account_not_found"}, {"error", "The account was not found. Refresh the account list."}};
        if (account.integer(0) == 1) {
            Statement count(db_, "SELECT COUNT(*) FROM users WHERE admin=1");
            if (count.step() != SQLITE_ROW) throw std::runtime_error("cannot count administrators");
            if (count.integer(0) <= 1)
                return {{"ok", false}, {"code", "account_delete_last_admin"}, {"error", "The last administrator cannot be deleted."}};
        }
        const auto cleanup_id = random_hex(16);
        Statement mark(db_, "INSERT INTO account_deletions(username,cleanup_id) VALUES(?,?)");
        mark.text(1, username); mark.text(2, cleanup_id); mark.done();
        for (const auto* sql : {"DELETE FROM api_keys WHERE owner=?", "DELETE FROM invitations WHERE owner=?", "DELETE FROM users WHERE username=?"}) {
            Statement remove(db_, sql); remove.text(1, username); remove.done();
        }
        transaction.commit(); log("auth", "account disabled for deletion: " + username);
        return {{"ok", true}, {"username", username}, {"cleanup_id", cleanup_id}};
    }
    static constexpr int max_active_keys = 100, max_stored_keys = 1000;

    // Metadata deliberately excludes both the SHA256 digest and the usable key.
    Json api_key_view(const Statement& query, std::int64_t now) const {
        const auto expires = query.is_null(5) ? Json() : Json(query.integer64(5));
        const auto revoked = query.is_null(7) ? Json() : Json(query.integer64(7));
        const auto audience = query.string(9);
        const auto permissions = Json::parse(query.string(10));
        if (!api_permissions_valid(permissions, audience)) throw std::runtime_error("invalid stored API key permissions");
        const bool active = (audience == "mailbox" ? query.integer(8) >= 0 : query.integer(8) == 1) && revoked.is_null() &&
            (expires.is_null() || expires.get<std::int64_t>() > now);
        return {{"id", query.string(0)}, {"name", query.string(1)}, {"prefix", query.string(2)},
                {"owner", query.string(3)}, {"scope", audience}, {"audience", audience}, {"permissions", permissions}, {"created_at", query.integer64(4)},
                {"expires_at", expires}, {"last_used_at", query.is_null(6) ? Json() : Json(query.integer64(6))},
                {"revoked_at", revoked}, {"active", active}};
    }

    Json key_metadata(const std::string& id, std::int64_t now) {
        Statement query(db_, "SELECT k.id,k.name,k.prefix,k.owner,k.created_at,k.expires_at,k.last_used_at,k.revoked_at,"
                            "COALESCE(u.admin,-1),k.audience,k.permissions FROM api_keys k LEFT JOIN users u ON u.username=k.owner WHERE k.id=?");
        query.text(1, id);
        if (query.step() != SQLITE_ROW) throw std::runtime_error("cannot read API key metadata");
        return api_key_view(query, now);
    }

    Json manage_api_keys(const Json& request, const std::string& operation) {
        const auto owner = username_from(request);
        const auto audience = request.value("audience", std::string("admin"));
        if (audience != "admin" && audience != "mailbox")
            return {{"ok", false}, {"code", "invalid_api_key"}, {"field", "audience"}, {"error", "Choose an API key audience."}};
        std::string name, id;
        std::int64_t days = 0;
        Json permissions;
        if (operation == "api_key_create" || operation == "api_key_update") {
            if (!request.contains("permissions") || !api_permissions_valid(request.at("permissions"), audience))
                return {{"ok", false}, {"code", "invalid_api_key"}, {"field", "permissions"}, {"error", "Choose valid API key permissions explicitly."}};
            // Canonical storage makes permission edits and audit views stable.
            auto values = request.at("permissions").get<std::vector<std::string>>();
            std::sort(values.begin(), values.end()); permissions = values;
        }
        if (operation == "api_key_create") {
            if (!request.contains("name") || !request.at("name").is_string())
                return {{"ok", false}, {"code", "invalid_api_key"}, {"field", "name"}, {"error", "Enter a name for the API key."}};
            name = trim(request.at("name").get<std::string>());
            if (name.empty() || name.size() > 80 || std::any_of(name.begin(), name.end(), [](unsigned char ch) { return ch < 32 || ch == 127; }))
                return {{"ok", false}, {"code", "invalid_api_key"}, {"field", "name"}, {"error", "API key names must contain 1..80 bytes without control characters."}};
            if (request.contains("expires_in_days")) {
                const auto& expiry = request.at("expires_in_days");
                if (!expiry.is_number_integer() || (expiry.is_number_unsigned() && expiry.get<std::uint64_t>() > 3650) ||
                    expiry.get<std::int64_t>() < 1 || expiry.get<std::int64_t>() > 3650)
                    return {{"ok", false}, {"code", "invalid_api_key"}, {"field", "expires_in_days"}, {"error", "API key expiry must be 1..3650 whole days."}};
                days = expiry.get<std::int64_t>();
            }
        } else if (operation == "api_key_revoke" || operation == "api_key_update") {
            id = required_string(request, "id", 32);
            if (id.size() != 32 || !std::all_of(id.begin(), id.end(), [](unsigned char ch) {
                return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
            })) return {{"ok", false}, {"code", "invalid_api_key"}, {"field", "id"}, {"error", "Invalid API key ID."}};
        }
        std::lock_guard guard(mutex_);
        Transaction transaction(db_);
        Statement administrator(db_, "SELECT admin FROM users WHERE username=?");
        administrator.text(1, owner);
        const auto account = administrator.step();
        if (account != SQLITE_ROW && account != SQLITE_DONE) throw std::runtime_error("cannot check API key administrator");
        if (account != SQLITE_ROW || (audience == "admin" && administrator.integer(0) != 1))
            return {{"ok", false}, {"code", "administrator_required"}, {"error", "Administrator access is required."}};
        const auto now = unix_seconds();
        if (operation == "api_key_list") {
            Statement query(db_, "SELECT k.id,k.name,k.prefix,k.owner,k.created_at,k.expires_at,k.last_used_at,k.revoked_at,"
                                "COALESCE(u.admin,-1),k.audience,k.permissions FROM api_keys k LEFT JOIN users u ON u.username=k.owner "
                                "WHERE k.audience=? AND (?='admin' OR k.owner=?) ORDER BY k.created_at DESC,k.id LIMIT 1000");
            query.text(1, audience); query.text(2, audience); query.text(3, owner);
            Json keys = Json::array();
            for (int code; (code = query.step()) != SQLITE_DONE;) {
                if (code != SQLITE_ROW) throw std::runtime_error("cannot list API keys");
                keys.push_back(api_key_view(query, now));
            }
            transaction.commit();
            return {{"ok", true}, {"api_keys", std::move(keys)}, {"permissions", api_key_permission_ids(audience)},
                {"audience", audience}, {"max_active_keys", max_active_keys}, {"max_stored_keys", max_stored_keys}};
        }
        if (operation == "api_key_revoke" || operation == "api_key_update") {
            Statement revoke(db_, operation == "api_key_revoke" ?
                "UPDATE api_keys SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND audience=? AND (?='admin' OR owner=?)" :
                "UPDATE api_keys SET permissions=? WHERE id=? AND audience=? AND (?='admin' OR owner=?) AND revoked_at IS NULL");
            if (operation == "api_key_revoke") revoke.integer64(1, now); else revoke.text(1, permissions.dump());
            revoke.text(2, id); revoke.text(3, audience); revoke.text(4, audience); revoke.text(5, owner); revoke.done();
            if (sqlite3_changes(db_) != 1)
                return {{"ok", false}, {"code", "api_key_not_found"}, {"error", "API key not found."}};
            const auto metadata = key_metadata(id, now);
            transaction.commit();
            log("auth", "account " + owner + (operation == "api_key_revoke" ? " revoked API key " : " updated API key permissions ") + id);
            return {{"ok", true}, {"api_key", metadata}};
        }
        Statement count(db_, "SELECT COUNT(*) FROM api_keys k JOIN users u ON u.username=k.owner "
                            "WHERE (k.audience='mailbox' OR u.admin=1) AND k.audience=? AND (?='admin' OR k.owner=?) "
                            "AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>?)");
        count.text(1, audience); count.text(2, audience); count.text(3, owner); count.integer64(4, now);
        if (count.step() != SQLITE_ROW) throw std::runtime_error("cannot count API keys");
        if (count.integer(0) >= max_active_keys)
            return {{"ok", false}, {"code", "api_key_limit"}, {"error", "Revoke an unused API key before creating another."}};
        // Retain bounded audit metadata. Only inactive keys may be pruned.
        Statement prune(db_, "DELETE FROM api_keys WHERE id IN (SELECT k.id FROM api_keys k LEFT JOIN users u ON u.username=k.owner "
                            "WHERE k.revoked_at IS NOT NULL OR k.expires_at<=? OR u.username IS NULL OR (k.audience='admin' AND u.admin=0) ORDER BY k.created_at,k.id "
                            "LIMIT MAX(0,(SELECT COUNT(*) FROM api_keys)-999))");
        prune.integer64(1, now); prune.done();
        Statement stored(db_, "SELECT COUNT(*) FROM api_keys");
        if (stored.step() != SQLITE_ROW) throw std::runtime_error("cannot count stored API keys");
        if (stored.integer(0) >= max_stored_keys)
            return {{"ok", false}, {"code", "api_key_limit"}, {"error", "The server API key limit was reached."}};
        const auto key = "pp_" + random_hex(32);
        id = random_hex(16);
        Statement insert(db_, "INSERT INTO api_keys(id,name,prefix,owner,digest,created_at,expires_at,audience,permissions) VALUES(?,?,?,?,?,?,?,?,?)");
        insert.text(1, id); insert.text(2, name); insert.text(3, key.substr(0, 11)); insert.text(4, owner);
        insert.bytes(5, api_key_digest(key)); insert.integer64(6, now);
        // Binding is initially NULL, which represents a key without expiry.
        if (days != 0) insert.integer64(7, now + days * INT64_C(86400));
        insert.text(8, audience); insert.text(9, permissions.dump());
        insert.done();
        const auto metadata = key_metadata(id, now);
        transaction.commit();
        log("auth", "account " + owner + " created " + audience + " API key " + id);
        return {{"ok", true}, {"key", key}, {"api_key", metadata}};
    }

    Json verify_api_key(const Json& request) {
        if (!request.contains("key") || !request.at("key").is_string()) return {{"ok", true}, {"valid", false}};
        const auto key = request.at("key").get<std::string>();
        if (!valid_api_key(key)) return {{"ok", true}, {"valid", false}};
        std::lock_guard guard(mutex_);
        Transaction transaction(db_);
        const auto now = unix_seconds();
        Statement query(db_, "SELECT k.id,k.owner,k.prefix,k.audience,k.permissions FROM api_keys k JOIN users u ON u.username=k.owner "
                            "WHERE k.digest=? AND (k.audience='mailbox' OR (k.audience='admin' AND u.admin=1)) "
                            "AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>?)");
        query.bytes(1, api_key_digest(key)); query.integer64(2, now);
        const auto code = query.step();
        if (code != SQLITE_ROW && code != SQLITE_DONE) throw std::runtime_error("cannot verify API key");
        if (code != SQLITE_ROW) return {{"ok", true}, {"valid", false}};
        const auto id = query.string(0), owner = query.string(1), prefix = query.string(2);
        const auto audience = query.string(3); const auto permissions = Json::parse(query.string(4));
        if (!api_permissions_valid(permissions, audience)) throw std::runtime_error("invalid stored API key permissions");
        Statement used(db_, "UPDATE api_keys SET last_used_at=? WHERE id=?");
        used.integer64(1, now); used.text(2, id); used.done();
        transaction.commit();
        return {{"ok", true}, {"valid", true}, {"username", owner}, {"admin", audience == "admin"},
                {"audience", audience}, {"permissions", permissions}, {"id", id}, {"prefix", prefix}};
    }

    static Json invitation_error(const std::string& code, const std::string& message, const std::string& field = {}) {
        Json result{{"ok", false}, {"code", code}, {"error", message}};
        if (!field.empty()) result["field"] = field;
        return result;
    }
    static bool identifier(std::string_view value) {
        return value.size() == 32 && value.find_first_not_of("0123456789abcdef") == value.npos;
    }
    bool valid_localpart(const std::string& value) const {
        return !value.empty() && value.size() <= 64 && value.find('@') == std::string::npos && valid_address(value + "@" + domain_);
    }
    Json invitation_view(const Statement& query, std::int64_t now) const {
        return {{"id", query.string(0)}, {"name", query.string(1)}, {"owner", query.string(2)},
            {"domain", query.string(3)}, {"localpart", query.string(4)}, {"created_at", query.integer64(5)},
            {"expires_at", query.integer64(6)}, {"max_uses", query.integer(7)}, {"uses", query.integer(8)},
            {"revoked_at", query.is_null(9) ? Json() : Json(query.integer64(9))},
            {"active", query.is_null(9) && query.integer64(6) > now && query.integer(8) < query.integer(7) && query.string(3) == domain_}};
    }
    Json invitation_metadata(const std::string& id, std::int64_t now) {
        Statement query(db_, "SELECT id,name,owner,domain,localpart,created_at,expires_at,max_uses,uses,revoked_at FROM invitations WHERE id=?");
        query.text(1, id);
        if (query.step() != SQLITE_ROW) throw std::runtime_error("cannot read invitation metadata");
        return invitation_view(query, now);
    }
    Json manage_invitations(const Json& request, const std::string& operation) {
        const auto owner = username_from(request);
        std::string name, localpart, id;
        std::int64_t days = 7, max_uses = 1;
        if (operation == "invite_create") {
            if (!request.contains("name") || !request.at("name").is_string())
                return invitation_error("invalid_invitation", "Enter an invitation name.", "name");
            name = trim(request.at("name").get<std::string>());
            if (name.empty() || name.size() > 80 || std::any_of(name.begin(), name.end(), [](unsigned char ch) { return ch < 32 || ch == 127; }))
                return invitation_error("invalid_invitation", "Invitation names must contain 1..80 bytes without control characters.", "name");
            for (const auto& field : {"expires_in_days", "max_uses"}) {
                if (!request.contains(field)) continue;
                const auto& value = request.at(field); const auto maximum = std::string_view(field) == "max_uses" ? 100 : 365;
                if (!value.is_number_integer() || (value.is_number_unsigned() && value.get<std::uint64_t>() > static_cast<std::uint64_t>(maximum)) ||
                    value.get<std::int64_t>() < 1 || value.get<std::int64_t>() > maximum)
                    return invitation_error("invalid_invitation", "Invitation expiration or use limit is outside its allowed range.", field);
                if (std::string_view(field) == "max_uses") max_uses = value.get<std::int64_t>(); else days = value.get<std::int64_t>();
            }
            if (request.contains("domain") && (!request.at("domain").is_string() || lower(trim(request.at("domain").get<std::string>())) != domain_))
                return invitation_error("invalid_invitation", "Invitations must use the configured mail domain.", "domain");
            if (request.contains("localpart")) {
                if (!request.at("localpart").is_string()) return invitation_error("invalid_invitation", "Enter a valid mailbox name.", "localpart");
                localpart = lower(trim(request.at("localpart").get<std::string>()));
                if (!localpart.empty() && !valid_localpart(localpart)) return invitation_error("invalid_invitation", "Enter a valid mailbox name.", "localpart");
            }
            if (!localpart.empty() && max_uses != 1)
                return invitation_error("invalid_invitation", "A fixed mailbox invitation can be used only once.", "max_uses");
        } else if (operation == "invite_revoke") {
            if (!request.contains("id") || !request.at("id").is_string() || !identifier(request.at("id").get<std::string>()))
                return invitation_error("invalid_invitation", "Invalid invitation ID.", "id");
            id = request.at("id").get<std::string>();
        }
        std::lock_guard guard(mutex_); Transaction transaction(db_);
        Statement administrator(db_, "SELECT admin FROM users WHERE username=?"); administrator.text(1, owner);
        const auto account = administrator.step();
        if (account != SQLITE_ROW && account != SQLITE_DONE) throw std::runtime_error("cannot check invitation administrator");
        if (account != SQLITE_ROW || administrator.integer(0) != 1)
            return invitation_error("administrator_required", "Administrator access is required.");
        const auto now = unix_seconds();
        if (operation == "invite_list") {
            Statement query(db_, "SELECT id,name,owner,domain,localpart,created_at,expires_at,max_uses,uses,revoked_at "
                                 "FROM invitations ORDER BY created_at DESC,id LIMIT 1000");
            Json invitations = Json::array();
            for (int code; (code = query.step()) != SQLITE_DONE;) {
                if (code != SQLITE_ROW) throw std::runtime_error("cannot list invitations");
                invitations.push_back(invitation_view(query, now));
            }
            transaction.commit();
            return {{"ok", true}, {"invitations", invitations}, {"domain", domain_}, {"max_active_invitations", 100}, {"max_stored_invitations", 1000}};
        }
        if (operation == "invite_revoke") {
            Statement revoke(db_, "UPDATE invitations SET revoked_at=COALESCE(revoked_at,?) WHERE id=?");
            revoke.integer64(1, now); revoke.text(2, id); revoke.done();
            if (sqlite3_changes(db_) != 1) return invitation_error("invitation_not_found", "Invitation not found.");
            auto metadata = invitation_metadata(id, now); transaction.commit();
            log("auth", "administrator " + owner + " revoked invitation " + id);
            return {{"ok", true}, {"invitation", metadata}};
        }
        if (!localpart.empty()) {
            Statement exists(db_, "SELECT 1 FROM users WHERE username=?"); exists.text(1, localpart + "@" + domain_);
            if (exists.step() == SQLITE_ROW) return invitation_error("user_exists", "This mailbox already exists.", "localpart");
        }
        Statement count(db_, "SELECT COUNT(*) FROM invitations WHERE revoked_at IS NULL AND expires_at>? AND uses<max_uses");
        count.integer64(1, now);
        if (count.step() != SQLITE_ROW) throw std::runtime_error("cannot count invitations");
        if (count.integer(0) >= 100) return invitation_error("invitation_limit", "Revoke an unused invitation before creating another.");
        Statement prune(db_, "DELETE FROM invitations WHERE id IN (SELECT id FROM invitations "
            "WHERE revoked_at IS NOT NULL OR expires_at<=? OR uses>=max_uses ORDER BY created_at,id "
            "LIMIT MAX(0,(SELECT COUNT(*) FROM invitations)-999))"); prune.integer64(1, now); prune.done();
        Statement stored(db_, "SELECT COUNT(*) FROM invitations");
        if (stored.step() != SQLITE_ROW) throw std::runtime_error("cannot count stored invitations");
        if (stored.integer(0) >= 1000) return invitation_error("invitation_limit", "The server invitation limit was reached.");
        const auto token = "pp_inv_" + random_hex(32); id = random_hex(16);
        Statement insert(db_, "INSERT INTO invitations(id,name,owner,digest,domain,localpart,created_at,expires_at,max_uses) VALUES(?,?,?,?,?,?,?,?,?)");
        insert.text(1, id); insert.text(2, name); insert.text(3, owner); insert.bytes(4, api_key_digest(token));
        insert.text(5, domain_); insert.text(6, localpart); insert.integer64(7, now); insert.integer64(8, now + days * INT64_C(86400));
        insert.integer64(9, max_uses); insert.done();
        auto metadata = invitation_metadata(id, now); transaction.commit();
        log("auth", "administrator " + owner + " created invitation " + id);
        return {{"ok", true}, {"token", token}, {"invitation", metadata}};
    }
    std::optional<Json> invitation_for_token(const std::string& token) {
        Statement query(db_, "SELECT id,name,owner,domain,localpart,created_at,expires_at,max_uses,uses,revoked_at FROM invitations WHERE digest=?");
        query.bytes(1, api_key_digest(token)); const auto code = query.step();
        if (code != SQLITE_ROW && code != SQLITE_DONE) throw std::runtime_error("cannot inspect invitation");
        if (code != SQLITE_ROW) return {};
        auto view = invitation_view(query, unix_seconds());
        if (!view.at("active").get<bool>()) return {};
        return view;
    }
    Json redeem_invitation(const Json& request, const std::string& operation) {
        const auto unavailable = invitation_error("invitation_unavailable", "This invitation is invalid, expired, revoked, or fully used.");
        if (!request.contains("token") || !request.at("token").is_string()) return unavailable;
        const auto token = request.at("token").get<std::string>();
        if (token.size() != 71 || !token.starts_with("pp_inv_") || token.find_first_not_of("0123456789abcdef", 7) != token.npos) return unavailable;
        {
            std::lock_guard guard(rate_mutex_);
            const auto now = std::chrono::steady_clock::now();
            if (invitation_attempts_.expires <= now) invitation_attempts_ = {now + std::chrono::minutes(1), 0};
            if (++invitation_attempts_.count > 600) return invitation_error("rate_limit", "Invitation request rate limit reached.");
        }
        std::string localpart, password;
        {
            std::lock_guard guard(mutex_);
            const auto invite = invitation_for_token(token); if (!invite) return unavailable;
            if (operation == "invite_inspect") {
                auto view = policy_view(); view["domain"] = domain_; view["localpart"] = invite->at("localpart");
                view["expires_at"] = invite->at("expires_at"); return view;
            }
            if (request.contains("admin")) return invitation_error("invalid_invitation", "Invitations create ordinary mailboxes only.");
            if (!request.contains("password") || !request.at("password").is_string())
                return invitation_error("invalid_invitation", "Enter an account password.", "password");
            password = request.at("password").get<std::string>();
            if (const auto failure = check_password(password)) return *failure;
            if (request.contains("localpart")) {
                if (!request.at("localpart").is_string()) return invitation_error("invalid_invitation", "Enter a valid mailbox name.", "localpart");
                localpart = lower(trim(request.at("localpart").get<std::string>()));
            }
            const auto fixed = invite->at("localpart").get<std::string>();
            if (!fixed.empty()) {
                if (!localpart.empty() && localpart != fixed) return invitation_error("invalid_invitation", "Use the mailbox name assigned to this invitation.", "localpart");
                localpart = fixed;
            }
            if (!valid_localpart(localpart)) return invitation_error("invalid_invitation", "Enter a valid mailbox name.", "localpart");
        }
        auto salt_value = salt(); auto hash = password_hash(password, salt_value, rounds_);
        std::lock_guard guard(mutex_); Transaction transaction(db_);
        const auto invite = invitation_for_token(token); if (!invite) return unavailable;
        if (const auto failure = check_password(password)) return *failure;
        const auto username = localpart + "@" + domain_;
        Statement pending(db_, "SELECT 1 FROM account_deletions WHERE username=?"); pending.text(1, username);
        if (pending.step() == SQLITE_ROW)
            return invitation_error("account_cleanup_pending", "Finish deleting this account before reusing its address.", "localpart");
        Statement insert(db_, "INSERT INTO users(username,salt,password_hash,iterations,admin) VALUES(?,?,?,?,0)");
        insert.text(1, username); insert.bytes(2, salt_value); insert.bytes(3, hash); insert.integer(4, rounds_);
        const auto inserted = insert.step();
        if (inserted == SQLITE_CONSTRAINT) return invitation_error("user_exists", "This mailbox already exists.", "localpart");
        if (inserted != SQLITE_DONE) throw std::runtime_error("cannot create invited mailbox");
        Statement consume(db_, "UPDATE invitations SET uses=uses+1 WHERE id=? AND revoked_at IS NULL AND expires_at>? AND uses<max_uses");
        consume.text(1, invite->at("id").get<std::string>()); consume.integer64(2, unix_seconds()); consume.done();
        if (sqlite3_changes(db_) != 1) return unavailable;
        transaction.commit();
        log("auth", "invited account created: " + username);
        return {{"ok", true}, {"username", username}, {"admin", false}};
    }

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
    std::string dummy_salt_, domain_;
    std::mutex mutex_;
    struct Rate { std::chrono::steady_clock::time_point expires; unsigned count = 0; };
    std::map<std::string, Rate> attempts_;
    Rate global_attempts_{};
    Rate invitation_attempts_{};
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
