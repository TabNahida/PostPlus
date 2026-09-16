#include <postplus/core.hpp>
#include <postplus/mime.hpp>
#include <postplus/data_lock.hpp>
#include <sqlite3.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>

namespace postplus {
namespace {
class Statement {
public:
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &value_, nullptr) != SQLITE_OK)
            throw std::runtime_error("storage query preparation failed");
    }
    ~Statement() { sqlite3_finalize(value_); }
    Statement(const Statement&) = delete;
    void text(int index, const std::string& value) {
        check(sqlite3_bind_text(value_, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT));
    }
    void blob(int index, const std::string& value) {
        check(sqlite3_bind_blob(value_, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT));
    }
    void integer(int index, std::int64_t value) { check(sqlite3_bind_int64(value_, index, value)); }
    bool row() {
        const auto result = sqlite3_step(value_);
        if (result != SQLITE_ROW && result != SQLITE_DONE) throw std::runtime_error("storage query failed");
        return result == SQLITE_ROW;
    }
    void done() {
        if (sqlite3_step(value_) != SQLITE_DONE) throw std::runtime_error("storage update failed");
    }
    std::string string(int column) const {
        const auto* data = static_cast<const char*>(sqlite3_column_blob(value_, column));
        const auto bytes = static_cast<std::size_t>(sqlite3_column_bytes(value_, column));
        return data ? std::string(data, bytes) : std::string{};
    }
    std::int64_t integer(int column) const { return sqlite3_column_int64(value_, column); }
    bool null(int column) const { return sqlite3_column_type(value_, column) == SQLITE_NULL; }
    void null_parameter(int index) { check(sqlite3_bind_null(value_, index)); }
private:
    static void check(int result) {
        if (result != SQLITE_OK) throw std::runtime_error("storage parameter binding failed");
    }
    sqlite3_stmt* value_ = nullptr;
};

void execute(sqlite3* db, const char* sql) {
    if (sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("storage transaction failed");
}
class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) { execute(db_, "BEGIN IMMEDIATE"); }
    ~Transaction() { if (!committed_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); }
    void commit() { execute(db_, "COMMIT"); committed_ = true; }
private:
    sqlite3* db_;
    bool committed_ = false;
};

std::string field(const Json& request, const char* key, std::size_t maximum, bool empty = false) {
    if (!request.contains(key) || !request.at(key).is_string())
        throw std::invalid_argument(std::string("missing or invalid ") + key);
    auto value = request.at(key).get<std::string>();
    if ((!empty && value.empty()) || value.size() > maximum || value.find('\0') != std::string::npos)
        throw std::invalid_argument(std::string("invalid ") + key + " length or content");
    return value;
}
std::int64_t integer_field(const Json& request, const char* key, std::int64_t fallback,
                           std::int64_t minimum, std::int64_t maximum) {
    if (!request.contains(key)) return fallback;
    if (!request.at(key).is_number_integer()) throw std::invalid_argument(std::string("invalid ") + key);
    if (request.at(key).is_number_unsigned() && request.at(key).get<std::uint64_t>() > static_cast<std::uint64_t>(maximum))
        throw std::invalid_argument(std::string("out of range ") + key);
    const auto value = request.at(key).get<std::int64_t>();
    if (value < minimum || value > maximum) throw std::invalid_argument(std::string("out of range ") + key);
    return value;
}
std::string address(const Json& request, const char* key, bool empty = false) {
    auto value = lower(trim(field(request, key, 254, empty)));
    if (!(empty && value.empty()) && !valid_address(value))
        throw std::invalid_argument(std::string("invalid ") + key);
    return value;
}
std::string identifier(const Json& request, const char* key) {
    auto value = field(request, key, 128);
    if (!std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ':';
    })) throw std::invalid_argument(std::string("invalid ") + key);
    return value;
}
std::int64_t now() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
constexpr std::array<const char*, 6> folder_names{"INBOX", "Sent", "Trash", "Drafts", "Junk", "Archive"};
constexpr std::int64_t maximum_quota_bytes = 1LL << 50;
std::string folder(const Json& request, const char* key = "folder") {
    const auto wanted = request.contains(key) ? lower(field(request, key, 32)) : "inbox";
    for (const auto* name : folder_names) if (lower(name) == wanted) return name;
    throw std::invalid_argument("unknown mail folder");
}
std::set<std::string> message_ids(const Json& request) {
    if (!request.contains("ids") || !request.at("ids").is_array() || request.at("ids").size() > 10000)
        throw std::invalid_argument("ids must be an array of at most 10000 IDs");
    std::set<std::string> ids;
    for (const auto& id : request.at("ids")) ids.insert(identifier(Json{{"id", id}}, "id"));
    return ids;
}
std::string fingerprint(const std::string& value) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
    unsigned int size = 0;
    if (EVP_Digest(value.data(), value.size(), bytes.data(), &size, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("submission digest failed");
    std::string result;
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned int i = 0; i < size; ++i) { result += digits[bytes[i] >> 4]; result += digits[bytes[i] & 15]; }
    return result;
}

Json envelope(std::string_view headers) {
    Json result = Json::object();
    std::string current_name, current_value;
    auto save = [&] {
        if ((current_name == "subject" || current_name == "from" || current_name == "to" || current_name == "date") && !result.contains(current_name)) {
            std::string decoded;
            try { decoded = mime::decode_header(current_value); }
            catch (const std::exception&) { decoded = current_value; }
            // UI summary fields have independent bounds; full originals remain
            // available via get. Rendering clients must display these as text.
            if (decoded.size() > 1024) decoded.resize(1024);
            result[current_name] = std::move(decoded);
        }
    };
    for (std::size_t position = 0; position < headers.size();) {
        const auto end = headers.find('\n', position);
        if (end == std::string_view::npos) break;
        auto line = headers.substr(position, end - position);
        position = end + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) { save(); return result; }
        if (line.front() == ' ' || line.front() == '\t') {
            if (!current_name.empty() && current_value.size() < 4096) {
                current_value += ' '; current_value += trim(std::string(line));
                if (current_value.size() > 4096) current_value.resize(4096);
            }
            continue;
        }
        save(); current_name.clear(); current_value.clear();
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        current_name = lower(std::string(line.substr(0, colon)));
        if (current_name == "subject" || current_name == "from" || current_name == "to" || current_name == "date")
            current_value = trim(std::string(line.substr(colon + 1, 4096)));
    }
    save();
    return result;
}

class Storage {
public:
    explicit Storage(const Config& config)
        : max_message_(integer_field(config.values, "max_message_bytes", 10485760, 1, 104857600)),
          max_queue_bytes_(integer_field(config.values, "max_queue_bytes", 1073741824, 1, maximum_quota_bytes)),
          max_queue_messages_(integer_field(config.values, "max_queue_messages", 100000, 1, 1000000)),
          max_mailbox_bytes_(integer_field(config.values, "max_mailbox_bytes", 1073741824, 1, maximum_quota_bytes)),
          max_mailbox_messages_(integer_field(config.values, "max_mailbox_messages", 10000, 1, 100000)) {
        if (max_message_ < 1 || max_message_ > 100 * 1024 * 1024 || max_queue_bytes_ < max_message_ ||
            max_mailbox_bytes_ < max_message_ || max_queue_messages_ < 1 || max_queue_messages_ > 1000000 ||
            max_mailbox_messages_ < 1 || max_mailbox_messages_ > 100000)
            throw std::invalid_argument("invalid storage limits");
        auto directory = std::filesystem::path(config.text("data_dir", "../data"));
        if (directory.is_relative()) directory = config.source.parent_path() / directory;
        if (std::filesystem::create_directories(directory)) {
#ifndef _WIN32
            std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
#endif
        }
        data_lock_ = std::make_unique<DataDirectoryLock>(directory);
        const auto path = (directory / "storage.sqlite3").u8string();
        if (sqlite3_open_v2(reinterpret_cast<const char*>(path.c_str()), &db_,
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
            if (db_) sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("cannot open storage database");
        }
        try {
            sqlite3_busy_timeout(db_, 5000);
            execute(db_, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;");
            std::int64_t version = 0;
            {
                Statement query(db_, "PRAGMA user_version");
                if (!query.row() || query.integer(0) > 2) throw std::runtime_error("unsupported storage database version");
                version = query.integer(0);
            }
            Transaction transaction(db_);
            execute(db_, "CREATE TABLE IF NOT EXISTS mailboxes("
                "username TEXT PRIMARY KEY, uidvalidity INTEGER NOT NULL CHECK(uidvalidity > 0),"
                "uidnext INTEGER NOT NULL CHECK(uidnext > 0));"
                "CREATE TABLE IF NOT EXISTS messages("
                "id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES mailboxes(username),"
                "uid INTEGER NOT NULL CHECK(uid > 0), raw BLOB NOT NULL, size INTEGER NOT NULL,"
                "seen INTEGER NOT NULL DEFAULT 0 CHECK(seen IN(0,1)), created_at INTEGER NOT NULL,"
                "UNIQUE(username,uid));"
                "CREATE TABLE IF NOT EXISTS deliveries("
                "username TEXT NOT NULL, delivery_id TEXT NOT NULL, message_id TEXT NOT NULL,"
                "PRIMARY KEY(username,delivery_id));"
                "CREATE TABLE IF NOT EXISTS queue("
                "id TEXT PRIMARY KEY, submission_id TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL,"
                "raw BLOB NOT NULL, size INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,"
                "next_attempt INTEGER NOT NULL, created_at INTEGER NOT NULL,"
                "state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','quarantined')),"
                "last_error TEXT NOT NULL DEFAULT '');"
                "CREATE INDEX IF NOT EXISTS queue_due ON queue(state,next_attempt,created_at);");
            if (version < 2) execute(db_,
                "ALTER TABLE messages ADD COLUMN folder TEXT NOT NULL DEFAULT 'INBOX' "
                "CHECK(folder IN('INBOX','Sent','Trash','Drafts','Junk','Archive'));"
                "ALTER TABLE mailboxes ADD COLUMN quota_bytes INTEGER CHECK(quota_bytes > 0);"
                "ALTER TABLE mailboxes ADD COLUMN quota_messages INTEGER CHECK(quota_messages > 0);");
            execute(db_,
                "CREATE INDEX IF NOT EXISTS messages_folder ON messages(username,folder,uid);"
                "CREATE TABLE IF NOT EXISTS submissions("
                "username TEXT NOT NULL, request_id TEXT NOT NULL, fingerprint TEXT NOT NULL,"
                "submission_id TEXT NOT NULL, sent_id TEXT NOT NULL, PRIMARY KEY(username,request_id));"
                "PRAGMA user_version=2;");
            transaction.commit();
#ifndef _WIN32
            std::filesystem::permissions(directory / "storage.sqlite3", std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
#endif
        } catch (...) {
            sqlite3_close(db_); db_ = nullptr; throw;
        }
    }
    ~Storage() { if (db_) sqlite3_close(db_); }

    Json handle(const Json& request) {
        const auto op = field(request, "op", 32);
        std::lock_guard guard(mutex_);
        if (op == "enqueue") return enqueue(request);
        if (op == "deliver") return deliver(request);
        if (op == "list") return list(request);
        if (op == "folders") return folders(request);
        if (op == "quota_get") return quota_get(request);
        if (op == "quota_set") return quota_set(request);
        if (op == "draft_save") return draft_save(request);
        if (op == "move") return move(request);
        if (op == "get") {
            auto username = address(request, "username"); auto id = identifier(request, "id");
            Statement query(db_, "SELECT raw,folder,seen,uid FROM messages WHERE username=? AND id=?");
            query.text(1, username); query.text(2, id);
            if (!query.row()) return {{"ok", false}, {"error", "message does not exist"}};
            if (request.contains("folder") && query.string(1) != folder(request))
                return {{"ok", false}, {"error", "message does not exist in folder"}};
            if (request.contains("uid") && query.integer(3) != integer_field(request, "uid", 0, 1, 0xffffffffLL))
                return {{"ok", false}, {"error", "message has changed"}};
            return {{"ok", true}, {"raw", query.string(0)}, {"folder", query.string(1)},
                {"seen", query.integer(2) != 0}, {"uid", query.integer(3)}};
        }
        if (op == "delete") return remove(request);
        if (op == "flags") {
            auto username = address(request, "username"); auto id = identifier(request, "id");
            if (!request.contains("seen") || !request.at("seen").is_boolean()) throw std::invalid_argument("seen must be boolean");
            const auto expected_uid = integer_field(request, "uid", 0, 1, 0xffffffffLL);
            Statement update(db_, "UPDATE messages SET seen=? WHERE username=? AND id=? AND (?=0 OR uid=?)");
            update.integer(1, request.at("seen").get<bool>() ? 1 : 0); update.text(2, username); update.text(3, id);
            update.integer(4, expected_uid); update.integer(5, expected_uid); update.done();
            if (sqlite3_changes(db_) != 1) return {{"ok", false}, {"error", "message does not exist"}};
            return {{"ok", true}};
        }
        if (op == "queue_list") return queue_list(request);
        if (op == "queue_inspect") return queue_inspect(request);
        if (op == "queue_finish") {
            auto id = identifier(request, "id");
            Statement update(db_, "DELETE FROM queue WHERE id=?"); update.text(1, id); update.done();
            return {{"ok", true}};
        }
        if (op == "queue_retry" || op == "queue_reject") {
            auto id = identifier(request, "id"); auto error = field(request, "error", 1024, true);
            if (op == "queue_retry") {
                const auto delay = integer_field(request, "delay", 60, 1, 604800);
                Statement update(db_, "UPDATE queue SET attempts=attempts+1,next_attempt=?,last_error=? WHERE id=? AND state='pending'");
                update.integer(1, now() + delay); update.text(2, error); update.text(3, id); update.done();
            } else {
                Statement update(db_, "UPDATE queue SET state='quarantined',attempts=attempts+1,last_error=? WHERE id=? AND state='pending'");
                update.text(1, error); update.text(2, id); update.done();
            }
            if (sqlite3_changes(db_) != 1) return {{"ok", false}, {"error", "pending queue job does not exist"}};
            return {{"ok", true}};
        }
        if (op == "stats") {
            Statement mail(db_, "SELECT COUNT(*),COALESCE(SUM(size),0) FROM messages"); mail.row();
            Statement queue(db_, "SELECT COUNT(*),COALESCE(SUM(size),0),COALESCE(SUM(state='quarantined'),0) FROM queue"); queue.row();
            return {{"ok", true}, {"messages", mail.integer(0)}, {"bytes", mail.integer(1)},
                {"queued", queue.integer(0) - queue.integer(2)}, {"queued_bytes", queue.integer(1)}, {"quarantined", queue.integer(2)}};
        }
        return {{"ok", false}, {"error", "unknown storage operation"}};
    }
private:
    Json enqueue(const Json& request) {
        auto sender = address(request, "sender", true);
        auto raw = field(request, "raw", static_cast<std::size_t>(max_message_));
        if (!request.contains("recipients") || !request.at("recipients").is_array() ||
            request.at("recipients").empty() || request.at("recipients").size() > 100)
            throw std::invalid_argument("recipients must contain 1..100 addresses");
        std::set<std::string> recipients;
        for (const auto& recipient : request.at("recipients")) {
            if (!recipient.is_string()) throw std::invalid_argument("invalid recipient");
            Json wrapped = {{"recipient", recipient}};
            recipients.insert(address(wrapped, "recipient"));
        }
        // Only authenticated submission callers pass sent_username. Inbound SMTP
        // never writes into a mailbox named by an untrusted envelope sender.
        const auto sent_username = request.contains("sent_username") ? address(request, "sent_username") : std::string{};
        const auto draft_id = request.contains("draft_id") ? identifier(request, "draft_id") : std::string{};
        if (!draft_id.empty() && sent_username.empty()) throw std::invalid_argument("draft requires Sent owner");
        const auto request_id = request.contains("submission_id") ? identifier(request, "submission_id") : random_hex(16);
        if (request.contains("submission_id") && sent_username.empty())
            throw std::invalid_argument("submission_id requires Sent owner");
        const auto digest = sent_username.empty() ? std::string{} : fingerprint(Json{
            {"sender", sender}, {"recipients", recipients}, {"raw_sha256", fingerprint(raw)}, {"draft_id", draft_id}}.dump());
        const auto submission = random_hex(16);
        Transaction transaction(db_);
        if (!sent_username.empty()) {
            Statement previous(db_, "SELECT fingerprint,submission_id,sent_id FROM submissions WHERE username=? AND request_id=?");
            previous.text(1, sent_username); previous.text(2, request_id);
            if (previous.row()) {
                if (previous.string(0) != digest) return {{"ok", false}, {"error", "submission_id already used for different content"}};
                return {{"ok", true}, {"id", previous.string(1)}, {"sent_id", previous.string(2)}, {"duplicate", true}};
            }
        }
        {
            Statement query(db_, "SELECT COUNT(*),COALESCE(SUM(size),0) FROM queue"); query.row();
            if (static_cast<std::int64_t>(recipients.size()) > max_queue_messages_ - query.integer(0) ||
                static_cast<std::int64_t>(raw.size()) * static_cast<std::int64_t>(recipients.size()) > max_queue_bytes_ - query.integer(1))
                return {{"ok", false}, {"error", "mail queue quota exceeded"}};
        }
        std::string sent_id;
        if (!sent_username.empty()) {
            ensure_mailbox(sent_username);
            std::int64_t old_size = 0;
            if (!draft_id.empty()) {
                Statement draft(db_, "SELECT size FROM messages WHERE username=? AND id=? AND folder='Drafts'");
                draft.text(1, sent_username); draft.text(2, draft_id);
                if (!draft.row()) return {{"ok", false}, {"error", "draft does not exist"}};
                old_size = draft.integer(0);
            }
            if (!fits_quota(sent_username, static_cast<std::int64_t>(raw.size()) - old_size, draft_id.empty() ? 1 : 0))
                return {{"ok", false}, {"error", "mailbox quota exceeded"}};
            const auto uid = allocate_uid(sent_username);
            sent_id = draft_id.empty() ? random_hex(16) : draft_id;
            if (draft_id.empty()) insert_message(sent_username, sent_id, uid, raw, "Sent", true);
            else {
                Statement update(db_, "UPDATE messages SET folder='Sent',uid=?,raw=?,size=?,seen=1,created_at=? WHERE username=? AND id=?");
                update.integer(1, uid); update.blob(2, raw); update.integer(3, static_cast<std::int64_t>(raw.size()));
                update.integer(4, now()); update.text(5, sent_username); update.text(6, draft_id); update.done();
            }
            Statement receipt(db_, "INSERT INTO submissions(username,request_id,fingerprint,submission_id,sent_id) VALUES(?,?,?,?,?)");
            receipt.text(1, sent_username); receipt.text(2, request_id); receipt.text(3, digest);
            receipt.text(4, submission); receipt.text(5, sent_id); receipt.done();
        }
        const auto created = now();
        for (const auto& recipient : recipients) {
            Statement insert(db_, "INSERT INTO queue(id,submission_id,sender,recipient,raw,size,next_attempt,created_at) VALUES(?,?,?,?,?,?,?,?)");
            insert.text(1, random_hex(16)); insert.text(2, submission); insert.text(3, sender); insert.text(4, recipient);
            insert.blob(5, raw); insert.integer(6, static_cast<std::int64_t>(raw.size())); insert.integer(7, created); insert.integer(8, created); insert.done();
        }
        transaction.commit();
        Json result{{"ok", true}, {"id", submission}};
        if (!sent_id.empty()) result["sent_id"] = sent_id;
        return result;
    }
    void ensure_mailbox(const std::string& username) {
        Statement query(db_, "SELECT 1 FROM mailboxes WHERE username=?"); query.text(1, username);
        if (query.row()) return;
        // UIDVALIDITY and UIDNEXT are persisted independently of the message rows.
        const auto validity = (std::stoull(random_hex(4), nullptr, 16) % 0xffffffffULL) + 1;
        Statement insert(db_, "INSERT INTO mailboxes(username,uidvalidity,uidnext) VALUES(?,?,1)");
        insert.text(1, username); insert.integer(2, static_cast<std::int64_t>(validity)); insert.done();
    }
    std::int64_t allocate_uid(const std::string& username) {
        Statement query(db_, "SELECT uidnext FROM mailboxes WHERE username=?"); query.text(1, username); query.row();
        const auto uid = query.integer(0);
        if (uid >= 0xffffffffLL) throw std::runtime_error("mailbox UID range exhausted");
        Statement update(db_, "UPDATE mailboxes SET uidnext=uidnext+1 WHERE username=?");
        update.text(1, username); update.done();
        return uid;
    }
    Json usage(const std::string& username) {
        Statement quota(db_, "SELECT quota_bytes,quota_messages FROM mailboxes WHERE username=?");
        quota.text(1, username); quota.row();
        Statement used(db_, "SELECT COUNT(*),COALESCE(SUM(size),0) FROM messages WHERE username=?");
        used.text(1, username); used.row();
        return {{"bytes", used.integer(1)}, {"messages", used.integer(0)},
            {"max_bytes", quota.null(0) ? max_mailbox_bytes_ : quota.integer(0)},
            {"max_messages", quota.null(1) ? max_mailbox_messages_ : quota.integer(1)},
            {"quota_bytes", quota.null(0) ? Json(nullptr) : Json(quota.integer(0))},
            {"quota_messages", quota.null(1) ? Json(nullptr) : Json(quota.integer(1))}};
    }
    bool fits_quota(const std::string& username, std::int64_t added_bytes, std::int64_t added_messages) {
        const auto current = usage(username);
        // Reductions remain possible after an administrator lowers a quota.
        return (added_bytes <= 0 || added_bytes <= current.at("max_bytes").get<std::int64_t>() - current.at("bytes").get<std::int64_t>()) &&
            (added_messages <= 0 || added_messages <= current.at("max_messages").get<std::int64_t>() - current.at("messages").get<std::int64_t>());
    }
    void insert_message(const std::string& username, const std::string& id, std::int64_t uid,
                        const std::string& raw, const std::string& target, bool seen = false) {
        Statement insert(db_, "INSERT INTO messages(id,username,uid,raw,size,created_at,folder,seen) VALUES(?,?,?,?,?,?,?,?)");
        insert.text(1, id); insert.text(2, username); insert.integer(3, uid); insert.blob(4, raw);
        insert.integer(5, static_cast<std::int64_t>(raw.size())); insert.integer(6, now());
        insert.text(7, target); insert.integer(8, seen ? 1 : 0); insert.done();
    }
    Json deliver(const Json& request) {
        auto username = address(request, "username");
        auto raw = field(request, "raw", static_cast<std::size_t>(max_message_));
        auto delivery_id = identifier(request, "delivery_id");
        Transaction transaction(db_);
        {
            Statement existing(db_, "SELECT message_id FROM deliveries WHERE username=? AND delivery_id=?");
            existing.text(1, username); existing.text(2, delivery_id);
            if (existing.row()) return {{"ok", true}, {"id", existing.string(0)}, {"duplicate", true}};
        }
        ensure_mailbox(username);
        if (!fits_quota(username, static_cast<std::int64_t>(raw.size()), 1))
            return {{"ok", false}, {"error", "mailbox quota exceeded"}};
        const auto uid = allocate_uid(username);
        auto id = random_hex(16);
        insert_message(username, id, uid, raw, folder(request));
        {
            Statement insert(db_, "INSERT INTO deliveries(username,delivery_id,message_id) VALUES(?,?,?)");
            insert.text(1, username); insert.text(2, delivery_id); insert.text(3, id); insert.done();
        }
        transaction.commit();
        return {{"ok", true}, {"id", id}};
    }
    Json list(const Json& request) {
        auto username = address(request, "username");
        const auto selected = folder(request);
        if (request.contains("include_envelope") && !request.at("include_envelope").is_boolean())
            throw std::invalid_argument("include_envelope must be boolean");
        const auto include_envelope = request.value("include_envelope", false);
        Transaction transaction(db_);
        ensure_mailbox(username);
        Json result = {{"ok", true}, {"folder", selected}, {"messages", Json::array()}};
        {
            Statement query(db_, "SELECT uidvalidity,uidnext FROM mailboxes WHERE username=?"); query.text(1, username); query.row();
            result["uidvalidity"] = query.integer(0); result["uidnext"] = query.integer(1);
        }
        {
            Statement query(db_, "SELECT id,uid,size,seen,created_at FROM messages WHERE username=? AND folder=? ORDER BY uid");
            query.text(1, username); query.text(2, selected);
            while (query.row()) result["messages"].push_back({{"id", query.string(0)}, {"uid", query.integer(1)},
                {"size", query.integer(2)}, {"seen", query.integer(3) != 0}, {"internal_date", query.integer(4)}, {"folder", selected}});
        }
        if (include_envelope) {
            Statement query(db_, "SELECT id,substr(raw,1,16384) FROM messages WHERE username=? AND folder=? ORDER BY uid DESC LIMIT 100");
            query.text(1, username); query.text(2, selected);
            auto index = result["messages"].size();
            while (query.row() && index > 0) {
                auto& item = result["messages"][--index];
                if (item.at("id") != query.string(0)) throw std::runtime_error("inconsistent mailbox snapshot");
                const auto summary = envelope(query.string(1));
                for (const auto& [key, value] : summary.items()) item[key] = value;
            }
        }
        transaction.commit();
        return result;
    }
    Json folders(const Json& request) {
        const auto username = address(request, "username");
        Transaction transaction(db_); ensure_mailbox(username);
        Json names = Json::array();
        for (const auto* name : folder_names) {
            Statement count(db_, "SELECT COUNT(*),COALESCE(SUM(size),0),COALESCE(SUM(seen=0),0) FROM messages WHERE username=? AND folder=?");
            count.text(1, username); count.text(2, name); count.row();
            names.push_back({{"name", name}, {"messages", count.integer(0)}, {"bytes", count.integer(1)}, {"unseen", count.integer(2)}});
        }
        Json result{{"ok", true}, {"folders", std::move(names)}, {"usage", usage(username)}};
        transaction.commit(); return result;
    }
    Json quota_get(const Json& request) {
        const auto username = address(request, "username");
        Transaction transaction(db_); ensure_mailbox(username);
        auto result = usage(username); result["ok"] = true; result["username"] = username;
        transaction.commit(); return result;
    }
    Json quota_set(const Json& request) {
        const auto username = address(request, "username");
        if (!request.contains("max_bytes") && !request.contains("max_messages"))
            throw std::invalid_argument("quota update requires max_bytes or max_messages");
        // Validate every field before starting a write, including unsigned JSON
        // values which must never wrap through a signed conversion.
        for (const auto* key : {"max_bytes", "max_messages"}) {
            if (request.contains(key) && !request.at(key).is_null())
                (void)integer_field(request, key, 0, 1, std::string_view(key) == "max_bytes" ? maximum_quota_bytes : 100000);
        }
        Transaction transaction(db_); ensure_mailbox(username);
        for (const auto* key : {"max_bytes", "max_messages"}) {
            if (!request.contains(key)) continue;
            Statement update(db_, std::string_view(key) == "max_bytes" ?
                "UPDATE mailboxes SET quota_bytes=? WHERE username=?" : "UPDATE mailboxes SET quota_messages=? WHERE username=?");
            if (request.at(key).is_null()) update.null_parameter(1);
            else update.integer(1, request.at(key).get<std::int64_t>());
            update.text(2, username); update.done();
        }
        auto result = usage(username); result["ok"] = true; result["username"] = username;
        transaction.commit(); return result;
    }
    Json draft_save(const Json& request) {
        const auto username = address(request, "username");
        const auto raw = field(request, "raw", static_cast<std::size_t>(max_message_));
        const auto existing_id = request.contains("id") ? identifier(request, "id") : std::string{};
        const auto expected_uid = integer_field(request, "uid", 0, 1, 0xffffffffLL);
        Transaction transaction(db_); ensure_mailbox(username);
        std::int64_t previous_size = 0;
        if (!existing_id.empty()) {
            Statement previous(db_, "SELECT size,uid FROM messages WHERE username=? AND id=? AND folder='Drafts'");
            previous.text(1, username); previous.text(2, existing_id);
            if (!previous.row()) return {{"ok", false}, {"error", "draft does not exist"}};
            if (expected_uid && previous.integer(1) != expected_uid) return {{"ok", false}, {"error", "draft has changed"}};
            previous_size = previous.integer(0);
        }
        if (!fits_quota(username, static_cast<std::int64_t>(raw.size()) - previous_size, existing_id.empty() ? 1 : 0))
            return {{"ok", false}, {"error", "mailbox quota exceeded"}};
        const auto id = existing_id.empty() ? random_hex(16) : existing_id;
        const auto uid = allocate_uid(username);
        if (existing_id.empty()) insert_message(username, id, uid, raw, "Drafts", true);
        else {
            // A new UID is essential: IMAP promises immutable message contents
            // for a given UID, even when the Webmail editor keeps its draft ID.
            Statement update(db_, "UPDATE messages SET raw=?,size=?,uid=?,created_at=? WHERE username=? AND id=?");
            update.blob(1, raw); update.integer(2, static_cast<std::int64_t>(raw.size())); update.integer(3, uid);
            update.integer(4, now()); update.text(5, username); update.text(6, id); update.done();
        }
        transaction.commit(); return {{"ok", true}, {"id", id}, {"uid", uid}, {"folder", "Drafts"}};
    }
    void move_messages(const std::string& username, const std::set<std::string>& ids, const std::string& target) {
        for (const auto& id : ids) {
            Statement current(db_, "SELECT folder FROM messages WHERE username=? AND id=?");
            current.text(1, username); current.text(2, id);
            if (!current.row() || current.string(0) == target) continue;
            const auto uid = allocate_uid(username);
            Statement update(db_, "UPDATE messages SET folder=?,uid=? WHERE username=? AND id=?");
            update.text(1, target); update.integer(2, uid); update.text(3, username); update.text(4, id); update.done();
        }
    }
    Json move(const Json& request) {
        const auto username = address(request, "username"); const auto ids = message_ids(request);
        if (!request.contains("folder")) throw std::invalid_argument("destination folder is required");
        const auto target = folder(request);
        Transaction transaction(db_); ensure_mailbox(username);
        move_messages(username, ids, target);
        transaction.commit(); return {{"ok", true}, {"folder", target}};
    }
    Json remove(const Json& request) {
        auto username = address(request, "username");
        const auto ids = message_ids(request);
        if (request.contains("permanent") && !request.at("permanent").is_boolean())
            throw std::invalid_argument("permanent must be boolean");
        const auto selected = request.contains("folder") ? folder(request) : std::string{};
        const auto expected_uids = request.value("expected_uids", Json::object());
        if (!expected_uids.is_object()) throw std::invalid_argument("expected_uids must be an object");
        for (const auto& [id, value] : expected_uids.items()) {
            (void)identifier(Json{{"id", id}}, "id");
            (void)integer_field(Json{{"uid", value}}, "uid", 0, 1, 0xffffffffLL);
        }
        Transaction transaction(db_);
        if (request.value("permanent", false)) {
            for (const auto& id : ids) {
                // Protocol sessions delete exactly their original snapshot;
                // moving or rewriting a draft while connected must not delete
                // the replacement message or a message in another folder.
                if (request.contains("expected_uids") && !expected_uids.contains(id)) continue;
                const auto uid = expected_uids.contains(id) ? expected_uids.at(id).get<std::int64_t>() : 0;
                Statement update(db_, "DELETE FROM messages WHERE username=? AND id=? AND (?='' OR folder=?) AND (?=0 OR uid=?)");
                update.text(1, username); update.text(2, id); update.text(3, selected); update.text(4, selected);
                update.integer(5, uid); update.integer(6, uid); update.done();
            }
        } else {
            ensure_mailbox(username); move_messages(username, ids, "Trash");
        }
        // Delivery tombstones intentionally survive deletion: a retried queue job
        // must never resurrect mail the recipient already deleted.
        transaction.commit();
        return {{"ok", true}};
    }
    Json queue_list(const Json& request) {
        const auto limit = integer_field(request, "limit", 1, 1, 100);
        Statement query(db_, "SELECT id,sender,recipient,raw,attempts,size FROM queue WHERE state='pending' AND next_attempt<=? ORDER BY next_attempt,created_at,id LIMIT ?");
        query.integer(1, now()); query.integer(2, limit);
        Json jobs = Json::array();
        std::int64_t response_bytes = 0;
        while (query.row()) {
            // A batch stays within one raw-message budget. This also avoids
            // allocating N maximum-sized messages into a single HTTP reply.
            const auto size = query.integer(5);
            if (!jobs.empty() && response_bytes + size > max_message_) break;
            jobs.push_back({{"id", query.string(0)}, {"sender", query.string(1)}, {"recipient", query.string(2)},
                {"raw", query.string(3)}, {"attempts", query.integer(4)}});
            response_bytes += size;
        }
        return {{"ok", true}, {"jobs", std::move(jobs)}};
    }
    Json queue_inspect(const Json& request) {
        const auto limit = integer_field(request, "limit", 100, 1, 1000);
        const auto offset = integer_field(request, "offset", 0, 0, 1000000);
        Statement query(db_, "SELECT id,submission_id,sender,recipient,attempts,next_attempt,state,last_error,size FROM queue ORDER BY created_at,id LIMIT ? OFFSET ?");
        query.integer(1, limit); query.integer(2, offset);
        Json jobs = Json::array();
        while (query.row()) jobs.push_back({{"id", query.string(0)}, {"submission_id", query.string(1)},
            {"sender", query.string(2)}, {"recipient", query.string(3)}, {"attempts", query.integer(4)},
            {"next_attempt", query.integer(5)}, {"state", query.string(6)}, {"error", query.string(7)}, {"size", query.integer(8)}});
        return {{"ok", true}, {"jobs", std::move(jobs)}};
    }
    sqlite3* db_ = nullptr;
    std::unique_ptr<DataDirectoryLock> data_lock_;
    std::int64_t max_message_, max_queue_bytes_, max_queue_messages_, max_mailbox_bytes_, max_mailbox_messages_;
    std::mutex mutex_;
};
}
}

int main(int argc, char** argv) {
    return postplus::service_main("storage", argc, argv, [](const postplus::Config& config) {
        auto storage = std::make_shared<postplus::Storage>(config);
        postplus::serve_rpc(config, "storage", [storage](const postplus::Json& request) { return storage->handle(request); });
    });
}
