#include <postplus/core.hpp>
#include <postplus/mime.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/forwarding.hpp>
#include <postplus/folders.hpp>
#include <sqlite3.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <mutex>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

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
    void real(int index, double value) { check(sqlite3_bind_double(value_, index, value)); }
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
    double real(int column) const { return sqlite3_column_double(value_, column); }
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
std::int64_t pop3_octets(std::string_view raw) {
    // POP3 RETR uses CRLF even for LF-only imported messages and terminates an
    // unfinished final line. Transparency dots and the terminator do not count.
    auto size = static_cast<std::int64_t>(raw.size());
    for (std::size_t i = 0; i < raw.size(); ++i)
        if (raw[i] == '\n' && (i == 0 || raw[i - 1] != '\r')) ++size;
    if (!raw.empty() && raw.back() != '\n') size += 2;
    return size;
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
std::string folder_name(const Json& request, const char* key = "folder") {
    return normalize_mail_folder(request.contains(key) ? field(request, key, 255) : "INBOX");
}
bool system_folder(const std::string& name) { return is_system_mail_folder(name); }
Json keywords(const Json& input) {
    if (!input.is_array() || input.size() > 64) throw std::invalid_argument("keywords must be an array of at most 64 IMAP atoms");
    std::set<std::string> seen; Json result = Json::array();
    for (const auto& value : input) {
        if (!value.is_string()) throw std::invalid_argument("invalid IMAP keyword");
        const auto name = value.get<std::string>();
        if (name.empty() || name.size() > 64 || !std::all_of(name.begin(), name.end(), [](unsigned char ch) {
                return ch > 32 && ch < 127 && std::string_view("(){%*\"\\]").find(static_cast<char>(ch)) == std::string_view::npos;
            })) throw std::invalid_argument("invalid IMAP keyword");
        if (seen.insert(lower(name)).second) result.push_back(name);
    }
    return result;
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

// Search is a decoded projection. Raw MIME remains the source of truth and is
// never rewritten by indexing, filtering, or a search request.
struct SearchDocument { std::string from, to, recipients, subject, body, filenames; bool attachment = false; };
std::string search_html(std::string_view value) {
    std::string out; bool tag = false;
    for (std::size_t at = 0; at < value.size(); ++at) {
        if (value[at] == '<') { tag = true; out += ' '; }
        else if (value[at] == '>') tag = false;
        else if (!tag && value[at] == '&') {
            const auto end = value.find(';', at + 1);
            const auto entity = end == value.npos ? std::string_view{} : value.substr(at, end - at + 1);
            const auto decoded = entity == "&nbsp;" ? " " : entity == "&amp;" ? "&" : entity == "&lt;" ? "<" : entity == "&gt;" ? ">" : entity == "&quot;" ? "\"" : entity == "&#39;" ? "'" : "";
            if (*decoded) { out += decoded; at = end; } else out += value[at];
        } else if (!tag) out += value[at];
    }
    return out;
}
void search_parts(const mime::Part& part, SearchDocument& document) {
    const auto name = mime::attachment_filename(part);
    const bool attached = lower(mime::header(part, "content-disposition")).starts_with("attachment") || !name.empty() ||
        (part.parts.empty() && part.content_type!="text/plain" && part.content_type!="text/html" && !part.body.empty());
    if (attached) {
        document.attachment = true; document.filenames += ' ' + mime::decode_header(name);
    } else if (part.content_type == "text/plain" || part.content_type == "text/html") {
        const auto text = mime::decode_text(part);
        document.body += '\n'; document.body += part.content_type == "text/html" ? search_html(text) : text;
    }
    for (const auto& child : part.parts) search_parts(child, document);
}
SearchDocument search_document(const std::string& raw) {
    SearchDocument result;
    try {
        const auto parsed = mime::parse(raw, {.max_bytes=104857600});
        result.from = mime::decode_header(mime::header(parsed, "from"));
        result.to = mime::decode_header(mime::header(parsed, "to"));
        result.recipients=result.to;
        for(const auto* header:{"cc","bcc"}) {
            const auto additional=mime::decode_header(mime::header(parsed,header)); if(!additional.empty()) result.recipients += ", " + additional;
        }
        result.subject = mime::decode_header(mime::header(parsed, "subject"));
        search_parts(parsed, result);
    } catch (const std::exception&) {
        const auto fields = envelope(raw);
        result.from = fields.value("from", ""); result.to = fields.value("to", ""); result.subject = fields.value("subject", "");
        result.recipients=result.to;
        // Even malformed legacy messages remain searchable by visible wire text.
        mime::Part fallback; fallback.content_type="text/plain"; fallback.headers={{"content-type","text/plain; charset=utf-8"}}; fallback.body=raw.substr(0,16*1024*1024);
        result.body = mime::decode_text(fallback);
    }
    return result;
}

class Storage {
public:
    explicit Storage(const Config& config)
        : config_(config), max_message_(integer_field(config.values, "max_message_bytes", 10485760, 1, 104857600)),
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
            bool extended_folders = false;
            {
                Statement query(db_, "PRAGMA user_version");
                if (!query.row() || query.integer(0) > 2) throw std::runtime_error("unsupported storage database version");
                version = query.integer(0);
            }
            {
                Statement query(db_, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailbox_folders'");
                extended_folders = query.row();
            }
            // Rebuild the old fixed-folder table without firing dependent flag
            // cascades. The atomically-created catalog marks this compatible
            // extension; retain schema version 2 so old binaries can roll back.
            if (!extended_folders) execute(db_, "PRAGMA foreign_keys=OFF;");
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
            if (!extended_folders) execute(db_,
                "CREATE TABLE messages_v3("
                "id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES mailboxes(username),"
                "uid INTEGER NOT NULL CHECK(uid > 0), raw BLOB NOT NULL, size INTEGER NOT NULL,"
                "seen INTEGER NOT NULL DEFAULT 0 CHECK(seen IN(0,1)), created_at INTEGER NOT NULL,"
                "folder TEXT NOT NULL DEFAULT 'INBOX',UNIQUE(username,uid));"
                "INSERT INTO messages_v3(id,username,uid,raw,size,seen,created_at,folder) "
                "SELECT id,username,uid,raw,size,seen,created_at,folder FROM messages;"
                "DROP TABLE messages;ALTER TABLE messages_v3 RENAME TO messages;");
            execute(db_,
                "CREATE INDEX IF NOT EXISTS messages_folder ON messages(username,folder,uid);"
                "CREATE TABLE IF NOT EXISTS message_flags("
                "id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,"
                "answered INTEGER NOT NULL DEFAULT 0 CHECK(answered IN(0,1)),"
                "flagged INTEGER NOT NULL DEFAULT 0 CHECK(flagged IN(0,1)),"
                "draft INTEGER NOT NULL DEFAULT 0 CHECK(draft IN(0,1)),"
                "deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN(0,1)),"
                "keywords TEXT NOT NULL DEFAULT '[]');"
                "CREATE TABLE IF NOT EXISTS mailbox_folders("
                "username TEXT NOT NULL REFERENCES mailboxes(username) ON DELETE CASCADE,name TEXT NOT NULL,"
                "subscribed INTEGER NOT NULL DEFAULT 1 CHECK(subscribed IN(0,1)),"
                "selectable INTEGER NOT NULL DEFAULT 1 CHECK(selectable IN(0,1)),"
                "recent_uid INTEGER NOT NULL DEFAULT 0 CHECK(recent_uid>=0),PRIMARY KEY(username,name));"
                "CREATE TABLE IF NOT EXISTS submissions("
                "username TEXT NOT NULL, request_id TEXT NOT NULL, fingerprint TEXT NOT NULL,"
                "submission_id TEXT NOT NULL, sent_id TEXT NOT NULL, PRIMARY KEY(username,request_id));"
                "CREATE TABLE IF NOT EXISTS forwarding_rules("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,domain TEXT NOT NULL,pattern TEXT NOT NULL,"
                "destination TEXT NOT NULL,created_at INTEGER NOT NULL,UNIQUE(domain,pattern));"
                "CREATE TABLE IF NOT EXISTS queue_routes("
                "queue_id TEXT PRIMARY KEY,recipient TEXT NOT NULL,destination TEXT NOT NULL,"
                "rule_id INTEGER,pattern TEXT NOT NULL DEFAULT '');"
                "CREATE TABLE IF NOT EXISTS submission_deliveries("
                "username TEXT NOT NULL,submission_id TEXT NOT NULL,message_id TEXT NOT NULL,"
                "PRIMARY KEY(username,submission_id));"
                "CREATE TABLE IF NOT EXISTS deleted_mailboxes(username TEXT PRIMARY KEY);"
                "CREATE TABLE IF NOT EXISTS message_search("
                "id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,source_uid INTEGER NOT NULL,"
                "sender TEXT NOT NULL,recipients TEXT NOT NULL,display_to TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL,"
                "filenames TEXT NOT NULL,has_attachment INTEGER NOT NULL CHECK(has_attachment IN(0,1)));"
                "CREATE TABLE IF NOT EXISTS queue_context("
                "queue_id TEXT PRIMARY KEY,sent_username TEXT NOT NULL DEFAULT '',inbound INTEGER NOT NULL DEFAULT 1,"
                "peer_ip TEXT NOT NULL DEFAULT '',helo TEXT NOT NULL DEFAULT '');"
                "CREATE TABLE IF NOT EXISTS delivery_status("
                "queue_id TEXT NOT NULL,recipient TEXT NOT NULL,username TEXT NOT NULL,submission_id TEXT NOT NULL,sent_id TEXT NOT NULL,"
                "state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',"
                "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,next_attempt INTEGER NOT NULL DEFAULT 0,"
                "delivery_scope TEXT NOT NULL DEFAULT '',PRIMARY KEY(queue_id,recipient));"
                "CREATE INDEX IF NOT EXISTS delivery_status_owner ON delivery_status(username,sent_id,created_at);"
                "CREATE TABLE IF NOT EXISTS delivery_events("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,queue_id TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL,"
                "error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,delivery_scope TEXT NOT NULL DEFAULT '');"
                "CREATE INDEX IF NOT EXISTS delivery_events_queue ON delivery_events(queue_id,id);"
                "CREATE TABLE IF NOT EXISTS message_filter("
                "id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,action TEXT NOT NULL,score REAL NOT NULL,reasons TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS message_pop3("
                "id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,source_uid INTEGER NOT NULL,"
                "source_size INTEGER NOT NULL,octets INTEGER NOT NULL);"
                "PRAGMA user_version=2;");
            execute(db_, "INSERT OR IGNORE INTO queue_context(queue_id,sent_username,inbound) "
                "SELECT q.id,COALESCE(s.username,''),CASE WHEN s.username IS NULL THEN 1 ELSE 0 END FROM queue q "
                "LEFT JOIN submissions s ON s.submission_id=q.submission_id;"
                "INSERT OR IGNORE INTO delivery_status(queue_id,recipient,username,submission_id,sent_id,state,attempts,error,created_at,updated_at,next_attempt) "
                "SELECT q.id,q.recipient,s.username,q.submission_id,s.sent_id,CASE WHEN q.state='quarantined' THEN 'rejected' WHEN q.attempts>0 THEN 'retrying' ELSE 'queued' END,"
                "q.attempts,q.last_error,q.created_at,q.created_at,q.next_attempt FROM queue q JOIN submissions s ON s.submission_id=q.submission_id;");
            // An older executable can finish a job during updater rollback. Its
            // outcome cannot be reconstructed, and must never appear queued or
            // cause us to resend it after the newer executable returns.
            execute(db_,"INSERT INTO delivery_events(queue_id,state,attempts,error,created_at) "
                "SELECT DISTINCT queue_id,'failed',attempts,'Delivery outcome unavailable: an older server removed this queue item; no resend was attempted.',strftime('%s','now') "
                "FROM delivery_status WHERE state IN('queued','retrying') AND queue_id NOT IN(SELECT id FROM queue);"
                "UPDATE delivery_status SET state='failed',error='Delivery outcome unavailable: an older server removed this queue item; no resend was attempted.',"
                "updated_at=strftime('%s','now'),next_attempt=0,delivery_scope='' WHERE state IN('queued','retrying') AND queue_id NOT IN(SELECT id FROM queue);"
                "DELETE FROM queue_context WHERE queue_id NOT IN(SELECT id FROM queue);DELETE FROM queue_routes WHERE queue_id NOT IN(SELECT id FROM queue);");
            { Statement legacy(db_,"SELECT DISTINCT q.id,q.state,q.last_error FROM queue q JOIN delivery_status s ON s.queue_id=q.id "
                "WHERE s.state IN('queued','retrying') AND (q.attempts>s.attempts OR q.state='quarantined')");
                std::vector<std::tuple<std::string,std::string,std::string>> updates;
                while(legacy.row()) updates.emplace_back(legacy.string(0),legacy.string(1),legacy.string(2));
                for(const auto& [id,state,error]:updates) record_queue_status(id,state=="quarantined"?"rejected":"retrying",error,""); }
            bool search_display_to=false;
            { Statement columns(db_,"PRAGMA table_info(message_search)"); while(columns.row()) if(columns.string(1)=="display_to") search_display_to=true; }
            if(!search_display_to) execute(db_,"ALTER TABLE message_search ADD COLUMN display_to TEXT NOT NULL DEFAULT '';DELETE FROM message_search;");
            bool deleted_flag = false, keyword_flags = false;
            { Statement columns(db_, "PRAGMA table_info(message_flags)");
                while (columns.row()) {
                    if (columns.string(1) == "deleted") deleted_flag = true;
                    if (columns.string(1) == "keywords") keyword_flags = true;
                } }
            if (!deleted_flag) execute(db_, "ALTER TABLE message_flags ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN(0,1));");
            if (!keyword_flags) execute(db_, "ALTER TABLE message_flags ADD COLUMN keywords TEXT NOT NULL DEFAULT '[]';");
            bool recent_watermark = false;
            { Statement columns(db_, "PRAGMA table_info(mailbox_folders)");
                while (columns.row()) if (columns.string(1) == "recent_uid") recent_watermark = true; }
            if (!recent_watermark) execute(db_, "ALTER TABLE mailbox_folders ADD COLUMN recent_uid INTEGER NOT NULL DEFAULT 0 CHECK(recent_uid>=0);"
                "UPDATE mailbox_folders SET recent_uid=(SELECT uidnext-1 FROM mailboxes WHERE mailboxes.username=mailbox_folders.username);");
            { Statement check(db_, "PRAGMA foreign_key_check");
                if (check.row()) throw std::runtime_error("storage migration has invalid references"); }
            transaction.commit();
            execute(db_, "PRAGMA foreign_keys=ON;");
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
        if (op == "mailbox_delete") return delete_mailbox(request);
        if (op == "forwarding_list") return forwarding_list(request);
        if (op == "forwarding_create") return forwarding_create(request);
        if (op == "forwarding_delete") return forwarding_delete(request);
        if (op == "resolve_recipient") return resolve_recipient(request);
        if (op == "verification_candidates") return verification_candidates(request);
        if (op == "list") return list(request);
        if (op == "search") return search(request);
        if (op == "delivery_status") return delivery_status(request);
        if (op == "folders") return folders(request);
        if (op == "folder_catalog") return folder_catalog(request);
        if (op == "folder_create") return folder_create(request);
        if (op == "folder_delete") return folder_delete(request);
        if (op == "folder_rename") return folder_rename(request);
        if (op == "folder_subscribe") return folder_subscribe(request);
        if (op == "quota_get") return quota_get(request);
        if (op == "quota_set") return quota_set(request);
        if (op == "draft_save") return draft_save(request);
        if (op == "append") return append(request);
        if (op == "copy") return copy(request);
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
            Json result{{"ok", true}, {"raw", query.string(0)}, {"folder", query.string(1)},
                {"seen", query.integer(2) != 0}, {"uid", query.integer(3)}};
            Statement verdict(db_,"SELECT action,score,reasons FROM message_filter WHERE id=?"); verdict.text(1,id);
            if(verdict.row()) {
                result["filter_action"]=verdict.string(0); result["spam_score"]=verdict.real(1); result["spam_reasons"]=Json::parse(verdict.string(2));
            }
            return result;
        }
        if (op == "delete") return remove(request);
        if (op == "flags") {
            auto username = address(request, "username"); auto id = identifier(request, "id");
            const auto operation = request.contains("flags_operation") ? field(request, "flags_operation", 16) : "replace";
            if (operation != "replace" && operation != "add" && operation != "remove")
                throw std::invalid_argument("invalid flags operation");
            bool provided = request.contains("keywords");
            if (provided) (void)keywords(request.at("keywords"));
            for (const auto* name : {"seen", "answered", "flagged", "draft", "deleted"}) if (request.contains(name)) {
                provided = true; if (!request.at(name).is_boolean()) throw std::invalid_argument("message flags must be boolean");
            }
            if (!provided) throw std::invalid_argument("message flags are required");
            const auto expected_uid = integer_field(request, "uid", 0, 1, 0xffffffffLL);
            const auto selected = request.contains("folder") ? folder(request) : std::string{};
            Transaction transaction(db_);
            Statement current(db_, "SELECT m.seen,COALESCE(f.answered,0),COALESCE(f.flagged,0),COALESCE(f.draft,0),"
                "COALESCE(f.deleted,0),COALESCE(f.keywords,'[]') FROM messages m LEFT JOIN message_flags f ON f.id=m.id "
                "WHERE m.username=? AND m.id=? AND (?=0 OR m.uid=?) AND (?='' OR m.folder=?)");
            current.text(1, username); current.text(2, id); current.integer(3, expected_uid); current.integer(4, expected_uid);
            current.text(5, selected); current.text(6, selected);
            if (!current.row()) return {{"ok", false}, {"error", "message does not exist"}};
            // Read-modify-write runs inside the storage transaction, so another
            // IMAP session cannot lose flags set after the caller's snapshot.
            Json updated = Json::object();
            const std::array<const char*,5> flag_names{"seen","answered","flagged","draft","deleted"};
            for (std::size_t i = 0; i < flag_names.size(); ++i) {
                const auto* name = flag_names[i];
                bool value = current.integer(static_cast<int>(i)) != 0;
                if (operation == "replace") value = request.value(name, value);
                else if (request.value(name, false)) value = operation == "add";
                updated[name] = value;
            }
            Json labels = Json::parse(current.string(5));
            if (request.contains("keywords")) {
                const auto requested = keywords(request.at("keywords"));
                if (operation == "replace") labels = requested;
                else {
                    std::set<std::string> wanted;
                    for (const auto& label : requested) wanted.insert(lower(label.get<std::string>()));
                    Json merged = Json::array();
                    for (const auto& label : labels) {
                        const auto normalized = lower(label.get<std::string>());
                        if (operation == "add" || !wanted.contains(normalized)) merged.push_back(label);
                    }
                    if (operation == "add") {
                        std::set<std::string> seen;
                        for (const auto& label : merged) seen.insert(lower(label.get<std::string>()));
                        for (const auto& label : requested) if (seen.insert(lower(label.get<std::string>())).second) merged.push_back(label);
                    }
                    labels = keywords(merged);
                }
            }
            updated["keywords"] = std::move(labels);
            Statement update(db_, "UPDATE messages SET seen=? WHERE username=? AND id=? AND (?=0 OR uid=?)");
            update.integer(1, updated.at("seen").get<bool>() ? 1 : 0); update.text(2, username); update.text(3, id);
            update.integer(4, expected_uid); update.integer(5, expected_uid); update.done();
            save_flags(id, updated);
            transaction.commit();
            return {{"ok", true}, {"flags", std::move(updated)}};
        }
        if (op == "queue_list") return queue_list(request);
        if (op == "queue_inspect") return queue_inspect(request);
        if (op == "queue_finish") {
            return finish_queue(request);
        }
        if (op == "queue_retry" || op == "queue_reject") {
            Transaction transaction(db_);
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
            const auto state = op == "queue_retry" ? "retrying" : request.value("status",std::string("rejected"));
            if(state!="retrying" && state!="rejected" && state!="failed") throw std::invalid_argument("invalid delivery state");
            record_queue_status(id,state,error,"");
            transaction.commit();
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
    Json delete_mailbox(const Json& request) {
        const auto username = address(request, "username");
        // Auth has already removed the identity and blocked reuse. Serialize the
        // cleanup with all storage operations; retain only empty dedupe receipts
        // so a worker holding an old queue snapshot cannot restore deleted mail.
        if (mailbox_exists(username)) return {{"ok", false}, {"error", "Disable the account before deleting its mailbox."}};
        Transaction transaction(db_);
        Statement mark(db_, "INSERT OR IGNORE INTO deleted_mailboxes(username) VALUES(?)"); mark.text(1, username); mark.done();
        Statement receipts(db_, "INSERT OR IGNORE INTO deliveries(username,delivery_id,message_id) "
            "SELECT ?,q.id,'' FROM queue q LEFT JOIN queue_routes r ON r.queue_id=q.id WHERE q.recipient=? OR r.destination=?");
        receipts.text(1, username); receipts.text(2, username); receipts.text(3, username); receipts.done();
        { Statement affected(db_,"SELECT id FROM queue WHERE sender=? OR recipient=? OR id IN (SELECT queue_id FROM queue_routes WHERE destination=?)");
            affected.text(1,username); affected.text(2,username); affected.text(3,username);
            std::vector<std::string> jobs; while(affected.row()) jobs.push_back(affected.string(0));
            for(const auto& id:jobs) record_queue_status(id,"failed","A mailbox required for this delivery was deleted.",""); }
        Statement queue(db_, "DELETE FROM queue WHERE sender=? OR recipient=? OR id IN (SELECT queue_id FROM queue_routes WHERE destination=?)");
        queue.text(1, username); queue.text(2, username); queue.text(3, username); queue.done();
        execute(db_, "DELETE FROM queue_routes WHERE queue_id NOT IN (SELECT id FROM queue);");
        execute(db_, "DELETE FROM queue_context WHERE queue_id NOT IN (SELECT id FROM queue);");
        { Statement remove(db_,"DELETE FROM delivery_status WHERE username=?"); remove.text(1,username); remove.done(); }
        execute(db_,"DELETE FROM delivery_events WHERE queue_id NOT IN (SELECT queue_id FROM delivery_status);");
        for (const auto* sql : {"DELETE FROM messages WHERE username=?", "DELETE FROM mailbox_folders WHERE username=?", "DELETE FROM mailboxes WHERE username=?",
                "DELETE FROM submissions WHERE username=?", "DELETE FROM forwarding_rules WHERE destination=?",
                "UPDATE deliveries SET message_id='' WHERE username=?", "UPDATE submission_deliveries SET message_id='' WHERE username=?"}) {
            Statement remove(db_, sql); remove.text(1, username); remove.done();
        }
        transaction.commit();
        return {{"ok", true}, {"username", username}};
    }
    std::string local_domain() const { return lower(config_.text("domain", "localhost")); }
    bool local_address(const std::string& value) const { return value.substr(value.find('@') + 1) == local_domain(); }
    bool mailbox_exists(const std::string& username) const {
        const auto result = rpc(config_, "auth", {{"op", "exists"}, {"username", username}});
        if (!result.value("ok", false)) throw std::runtime_error("Recipient account service unavailable.");
        return result.value("exists", false);
    }
    Json rule_row(Statement& query) const {
        return {{"id", query.integer(0)}, {"pattern", query.string(1)}, {"destination", query.string(2)},
                {"domain", local_domain()}, {"created_at", query.integer(3)}};
    }
    Json forwarding_list(const Json& request) {
        const auto limit = integer_field(request, "limit", 100, 1, 1000);
        const auto offset = integer_field(request, "offset", 0, 0, 10000);
        Statement count(db_, "SELECT COUNT(*) FROM forwarding_rules WHERE domain=?"); count.text(1, local_domain()); count.row();
        Statement query(db_, "SELECT id,pattern,destination,created_at FROM forwarding_rules WHERE domain=? ORDER BY id LIMIT ? OFFSET ?");
        query.text(1, local_domain()); query.integer(2, limit); query.integer(3, offset);
        Json rules = Json::array(); while (query.row()) rules.push_back(rule_row(query));
        return {{"ok", true}, {"rules", std::move(rules)}, {"total", count.integer(0)}, {"domain", local_domain()}};
    }
    Json forwarding_create(const Json& request) {
        const auto pattern = forwarding_pattern(field(request, "pattern", 254), local_domain());
        const auto destination = address(request, "destination");
        if (!local_address(destination)) return {{"ok", false}, {"code", "nonlocal_destination"}, {"error", "Forwarding destination must be an existing mailbox in the configured local domain."}};
        if (!mailbox_exists(destination)) return {{"ok", false}, {"code", "unknown_destination"}, {"error", "Forwarding destination mailbox does not exist."}};
        if (pattern.find_first_of("*?") == std::string::npos && pattern + "@" + local_domain() == destination)
            return {{"ok", false}, {"code", "self_forwarding"}, {"error", "An exact forwarding rule must use a different destination mailbox."}};
        Statement duplicate(db_, "SELECT 1 FROM forwarding_rules WHERE domain=? AND pattern=?"); duplicate.text(1, local_domain()); duplicate.text(2, pattern);
        if (duplicate.row()) return {{"ok", false}, {"code", "duplicate_rule"}, {"error", "A forwarding rule for this pattern already exists."}};
        Statement count(db_, "SELECT COUNT(*) FROM forwarding_rules"); count.row();
        if (count.integer(0) >= 1000) return {{"ok", false}, {"code", "rule_limit"}, {"error", "At most 1000 forwarding rules are supported."}};
        const auto created = now();
        Statement insert(db_, "INSERT INTO forwarding_rules(domain,pattern,destination,created_at) VALUES(?,?,?,?)");
        insert.text(1, local_domain()); insert.text(2, pattern); insert.text(3, destination); insert.integer(4, created); insert.done();
        return {{"ok", true}, {"rule", {{"id", sqlite3_last_insert_rowid(db_)}, {"domain", local_domain()},
                {"pattern", pattern}, {"destination", destination}, {"created_at", created}}}};
    }
    Json forwarding_delete(const Json& request) {
        const auto id = integer_field(request, "id", 0, 1, std::numeric_limits<std::int64_t>::max());
        if (!id) throw std::invalid_argument("forwarding rule ID is required");
        Statement remove(db_, "DELETE FROM forwarding_rules WHERE domain=? AND id=?"); remove.text(1, local_domain()); remove.integer(2, id); remove.done();
        return {{"ok", true}, {"deleted", sqlite3_changes(db_) == 1}};
    }
    Json resolution(const std::string& recipient, const std::string& destination, const Json& rule = nullptr) const {
        return {{"ok", true}, {"exists", !destination.empty()}, {"recipient", recipient}, {"destination", destination},
                {"forwarded", !destination.empty() && destination != recipient}, {"rule", rule}};
    }
    void pin_route(const std::string& id, const std::string& recipient, const Json& route) {
        Statement insert(db_, "INSERT INTO queue_routes(queue_id,recipient,destination,rule_id,pattern) VALUES(?,?,?,?,?)");
        insert.text(1, id); insert.text(2, recipient); insert.text(3, route.at("destination").get<std::string>());
        const auto rule = route.value("rule", Json(nullptr));
        if (rule.is_null()) { insert.null_parameter(4); insert.text(5, ""); }
        else { insert.integer(4, rule.at("id").get<std::int64_t>()); insert.text(5, rule.value("pattern", "")); }
        insert.done();
    }
    Json resolve_recipient(const Json& request) {
        const auto recipient = address(request, "recipient");
        const auto queue_id = request.contains("queue_id") ? identifier(request, "queue_id") : std::string{};
        if (!queue_id.empty()) {
            Statement pinned(db_, "SELECT recipient,destination,rule_id,pattern FROM queue_routes WHERE queue_id=?"); pinned.text(1, queue_id);
            if (pinned.row()) {
                if (pinned.string(0) != recipient) throw std::invalid_argument("queued original recipient does not match route");
                const auto destination = pinned.string(1);
                Json rule = pinned.null(2) ? Json(nullptr) : Json{{"id", pinned.integer(2)}, {"pattern", pinned.string(3)},
                    {"destination", destination}, {"domain", local_domain()}};
                return resolution(recipient, local_address(destination) && mailbox_exists(destination) ? destination : "", rule);
            }
            Statement queued(db_, "SELECT recipient FROM queue WHERE id=?"); queued.text(1, queue_id);
            if (!queued.row() || queued.string(0) != recipient) throw std::invalid_argument("queue item does not match original recipient");
        }
        if (!local_address(recipient)) return resolution(recipient, "");
        Json result = resolution(recipient, "");
        {
            Statement query(db_, "SELECT id,pattern,destination,created_at FROM forwarding_rules WHERE domain=? ORDER BY id"); query.text(1, local_domain());
            Json selected = nullptr; std::array<unsigned, 3> best{};
            const auto prefix = recipient.substr(0, recipient.find('@'));
            while (query.row()) {
                const auto pattern = query.string(1);
                if (!forwarding_matches(pattern, prefix)) continue;
                const auto rank = forwarding_specificity(pattern);
                if (selected.is_null() || rank[0] > best[0] || (rank[0] == best[0] && rank[1] < best[1]) ||
                    (rank[0] == best[0] && rank[1] == best[1] && rank[2] < best[2])) { selected = rule_row(query); best = rank; }
            }
            // Explicit mailbox forwarding overrides ordinary inbox delivery.
            // Wildcards remain an alias fallback and cannot capture accounts.
            const auto exact = !selected.is_null() && selected.at("pattern").get<std::string>().find_first_of("*?") == std::string::npos;
            if (!exact && mailbox_exists(recipient)) result = resolution(recipient, recipient);
            else if (!selected.is_null()) {
                const auto destination = selected.at("destination").get<std::string>();
                // The resolved inbox is terminal: never run the destination
                // through this resolver again, so chained/cyclic rules cannot loop.
                result = resolution(recipient, local_address(destination) && mailbox_exists(destination) ? destination : "", selected);
            }
        }
        if (!queue_id.empty() && result.at("exists") == true) pin_route(queue_id, recipient, result);
        return result;
    }
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
        if(request.contains("inbound") && !request.at("inbound").is_boolean()) throw std::invalid_argument("inbound must be boolean");
        const bool inbound=request.value("inbound",sent_username.empty());
        const auto peer_ip=request.contains("peer_ip") ? field(request,"peer_ip",64,true) : std::string{};
        const auto helo=request.contains("helo") ? field(request,"helo",255,true) : std::string{};
        const auto draft_id = request.contains("draft_id") ? identifier(request, "draft_id") : std::string{};
        if (!draft_id.empty() && sent_username.empty()) throw std::invalid_argument("draft requires Sent owner");
        const auto request_id = request.contains("submission_id") ? identifier(request, "submission_id") : random_hex(16);
        if (request.contains("submission_id") && sent_username.empty())
            throw std::invalid_argument("submission_id requires Sent owner");
        const auto digest = sent_username.empty() ? std::string{} : fingerprint(Json{
            {"sender", sender}, {"recipients", recipients}, {"raw_sha256", fingerprint(raw)}, {"draft_id", draft_id}}.dump());
        Json routes = Json::object();
        if (request.contains("recipient_routes")) {
            const auto& supplied = request.at("recipient_routes");
            if (!supplied.is_object() || supplied.size() > recipients.size())
                throw std::invalid_argument("recipient_routes must map requested local recipients");
            for (const auto& [recipient, route] : supplied.items()) {
                if (!recipients.contains(recipient) || !local_address(recipient) || !route.is_object())
                    throw std::invalid_argument("recipient route does not match requested local recipient");
                const auto destination = address(route, "destination");
                if (!local_address(destination)) throw std::invalid_argument("recipient route destination must be local");
                const auto rule = route.value("rule", Json(nullptr));
                if (!rule.is_null()) {
                    if (!rule.is_object()) throw std::invalid_argument("recipient route rule must be an object");
                    const auto rule_id = integer_field(rule, "id", 0, 1, std::numeric_limits<std::int64_t>::max());
                    if (!rule_id) throw std::invalid_argument("recipient route rule ID is required");
                    const auto pattern = forwarding_pattern(field(rule, "pattern", 64), local_domain());
                    if (!forwarding_matches(pattern, recipient.substr(0, recipient.find('@'))))
                        throw std::invalid_argument("recipient route rule does not match original recipient");
                    routes[recipient] = resolution(recipient, destination, {{"id", rule_id}, {"pattern", pattern}});
                } else {
                    if (destination != recipient) throw std::invalid_argument("forwarded recipient requires a rule");
                    routes[recipient] = resolution(recipient, destination);
                }
            }
            for (const auto& recipient : recipients) if (local_address(recipient) && !routes.contains(recipient))
                throw std::invalid_argument("local recipient route is missing");
        }
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
        // The accepted RCPT route survives rule edits between acceptance and DATA.
        // Recheck account existence and pin it with the queue transaction. Legacy
        // internal enqueue callers can omit routes and resolve at delivery time.
        std::set<std::string> destinations, queued_recipients;
        for (const auto& recipient : recipients) {
            const auto destination = routes.contains(recipient) ? routes.at(recipient).at("destination").get<std::string>() : recipient;
            if (routes.contains(recipient) && !destinations.contains(destination) && !mailbox_exists(destination))
                return {{"ok", false}, {"code", "unknown_destination"}, {"error", "Local destination mailbox no longer exists."}};
            if (destinations.insert(destination).second) queued_recipients.insert(recipient);
        }
        {
            Statement query(db_, "SELECT COUNT(*),COALESCE(SUM(size),0) FROM queue"); query.row();
            if (static_cast<std::int64_t>(queued_recipients.size()) > max_queue_messages_ - query.integer(0) ||
                static_cast<std::int64_t>(raw.size()) * static_cast<std::int64_t>(queued_recipients.size()) > max_queue_bytes_ - query.integer(1))
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
                save_search(sent_id,uid,raw);
                save_flags(draft_id, {{"draft", false}});
            }
            Statement receipt(db_, "INSERT INTO submissions(username,request_id,fingerprint,submission_id,sent_id) VALUES(?,?,?,?,?)");
            receipt.text(1, sent_username); receipt.text(2, request_id); receipt.text(3, digest);
            receipt.text(4, submission); receipt.text(5, sent_id); receipt.done();
        }
        const auto created = now();
        std::map<std::string,std::string> destination_jobs;
        for (const auto& recipient : queued_recipients) {
            const auto queue_id = random_hex(16);
            Statement insert(db_, "INSERT INTO queue(id,submission_id,sender,recipient,raw,size,next_attempt,created_at) VALUES(?,?,?,?,?,?,?,?)");
            insert.text(1, queue_id); insert.text(2, submission); insert.text(3, sender); insert.text(4, recipient);
            insert.blob(5, raw); insert.integer(6, static_cast<std::int64_t>(raw.size())); insert.integer(7, created); insert.integer(8, created); insert.done();
            if (routes.contains(recipient)) pin_route(queue_id, recipient, routes.at(recipient));
            Statement context(db_,"INSERT INTO queue_context(queue_id,sent_username,inbound,peer_ip,helo) VALUES(?,?,?,?,?)");
            context.text(1,queue_id); context.text(2,sent_username); context.integer(3,inbound?1:0); context.text(4,peer_ip); context.text(5,helo); context.done();
            destination_jobs[routes.contains(recipient)?routes.at(recipient).at("destination").get<std::string>():recipient]=queue_id;
        }
        if(!sent_username.empty()) for(const auto& recipient:recipients) {
            const auto destination=routes.contains(recipient)?routes.at(recipient).at("destination").get<std::string>():recipient;
            const auto queue_id=destination_jobs.at(destination);
            Statement status(db_,"INSERT INTO delivery_status(queue_id,recipient,username,submission_id,sent_id,state,created_at,updated_at,next_attempt) VALUES(?,?,?,?,?,'queued',?,?,?)");
            status.text(1,queue_id); status.text(2,recipient); status.text(3,sent_username); status.text(4,submission); status.text(5,sent_id);
            status.integer(6,created); status.integer(7,created); status.integer(8,created); status.done();
        }
        if(!sent_username.empty()) for(const auto& [destination,queue_id]:destination_jobs) {
            (void)destination; Statement event(db_,"INSERT INTO delivery_events(queue_id,state,attempts,created_at) VALUES(?,'queued',0,?)");
            event.text(1,queue_id); event.integer(2,created); event.done();
        }
        transaction.commit();
        Json result{{"ok", true}, {"id", submission}};
        if (!sent_id.empty()) result["sent_id"] = sent_id;
        return result;
    }
    void ensure_mailbox(const std::string& username) {
        Statement deleted(db_, "SELECT 1 FROM deleted_mailboxes WHERE username=?"); deleted.text(1, username);
        if (deleted.row()) {
            if (!mailbox_exists(username)) throw std::invalid_argument("account has been deleted");
            Statement restore(db_, "DELETE FROM deleted_mailboxes WHERE username=?"); restore.text(1, username); restore.done();
        }
        Statement query(db_, "SELECT 1 FROM mailboxes WHERE username=?"); query.text(1, username);
        if (!query.row()) {
            // UIDVALIDITY and UIDNEXT are persisted independently of the message rows.
            const auto validity = (std::stoull(random_hex(4), nullptr, 16) % 0xffffffffULL) + 1;
            Statement insert(db_, "INSERT INTO mailboxes(username,uidvalidity,uidnext) VALUES(?,?,1)");
            insert.text(1, username); insert.integer(2, static_cast<std::int64_t>(validity)); insert.done();
        }
        for (const auto* name : folder_names) {
            Statement insert(db_, "INSERT OR IGNORE INTO mailbox_folders(username,name,recent_uid) SELECT ?,?,uidnext-1 FROM mailboxes WHERE username=?");
            insert.text(1, username); insert.text(2, name); insert.text(3, username); insert.done();
        }
    }
    std::string folder(const Json& request, const char* key = "folder") {
        const auto name = folder_name(request, key);
        if (system_folder(name)) return name;
        Statement query(db_, "SELECT selectable FROM mailbox_folders WHERE username=? AND name=?");
        query.text(1, address(request, "username")); query.text(2, name);
        if (!query.row() || !query.integer(0)) throw std::invalid_argument("unknown mail folder");
        return name;
    }
    Json folder_catalog(const Json& request) {
        const auto username = address(request, "username");
        Transaction transaction(db_); ensure_mailbox(username);
        Statement query(db_, "SELECT name,subscribed,selectable FROM mailbox_folders WHERE username=? ORDER BY name");
        query.text(1, username); Json names = Json::array();
        while (query.row()) {
            const auto name = query.string(0);
            std::string special;
            if (name == "Sent") special = "\\Sent";
            else if (name == "Trash") special = "\\Trash";
            else if (name == "Drafts") special = "\\Drafts";
            else if (name == "Junk") special = "\\Junk";
            else if (name == "Archive") special = "\\Archive";
            names.push_back({{"name", name}, {"subscribed", query.integer(1) != 0},
                {"selectable", query.integer(2) != 0}, {"special_use", special}});
        }
        transaction.commit(); return {{"ok", true}, {"folders", std::move(names)}};
    }
    void folder_parents(const std::string& username, const std::string& name) {
        for (auto slash = name.find('/'); slash != std::string::npos; slash = name.find('/', slash + 1)) {
            Statement insert(db_, "INSERT OR IGNORE INTO mailbox_folders(username,name,subscribed,selectable) VALUES(?,?,0,0)");
            insert.text(1, username); insert.text(2, name.substr(0, slash)); insert.done();
        }
    }
    void folder_limit(const std::string& username) {
        Statement count(db_, "SELECT COUNT(*) FROM mailbox_folders WHERE username=?"); count.text(1, username); count.row();
        if (count.integer(0) > 1000) throw std::invalid_argument("mailbox folder limit exceeded");
    }
    void prune_folder_parents(const std::string& username) {
        for (;;) {
            Statement remove(db_, "DELETE FROM mailbox_folders AS parent WHERE username=? AND selectable=0 AND subscribed=0 "
                "AND NOT EXISTS(SELECT 1 FROM mailbox_folders child WHERE child.username=parent.username AND instr(child.name,parent.name||'/')=1)");
            remove.text(1, username); remove.done(); if (!sqlite3_changes(db_)) return;
        }
    }
    Json folder_create(const Json& request) {
        const auto username = address(request, "username");
        if (!request.contains("folder")) throw std::invalid_argument("folder is required");
        const auto name = folder_name(request);
        Transaction transaction(db_); ensure_mailbox(username);
        Statement existing(db_, "SELECT selectable FROM mailbox_folders WHERE username=? AND name=?");
        existing.text(1, username); existing.text(2, name);
        if (existing.row() && existing.integer(0)) return {{"ok", false}, {"code", "folder_exists"}, {"error", "Mailbox already exists."}};
        folder_parents(username, name);
        Statement insert(db_, "INSERT INTO mailbox_folders(username,name) VALUES(?,?) "
            "ON CONFLICT(username,name) DO UPDATE SET selectable=1,subscribed=1");
        insert.text(1, username); insert.text(2, name); insert.done(); folder_limit(username);
        transaction.commit(); return {{"ok", true}, {"folder", name}};
    }
    Json folder_delete(const Json& request) {
        const auto username = address(request, "username"), name = folder(request);
        if (system_folder(name)) return {{"ok", false}, {"code", "protected_folder"}, {"error", "System mailboxes cannot be deleted."}};
        Transaction transaction(db_); ensure_mailbox(username);
        Statement remove(db_, "DELETE FROM messages WHERE username=? AND folder=?");
        remove.text(1, username); remove.text(2, name); remove.done();
        Statement children(db_, "SELECT 1 FROM mailbox_folders WHERE username=? AND instr(name,?)=1 LIMIT 1");
        children.text(1, username); children.text(2, name + "/"); const bool inferiors = children.row();
        Statement update(db_, inferiors ? "UPDATE mailbox_folders SET selectable=0,subscribed=0 WHERE username=? AND name=?" :
            "DELETE FROM mailbox_folders WHERE username=? AND name=?");
        update.text(1, username); update.text(2, name); update.done();
        prune_folder_parents(username);
        transaction.commit(); return {{"ok", true}, {"folder", name}};
    }
    Json folder_rename(const Json& request) {
        const auto username = address(request, "username");
        if (!request.contains("folder") || !request.contains("target")) throw std::invalid_argument("folder and target are required");
        const auto name = folder_name(request), target = folder_name(request, "target");
        if (system_folder(name) || system_folder(target)) return {{"ok", false}, {"code", "protected_folder"}, {"error", "System mailboxes cannot be renamed."}};
        if (name == target || target.starts_with(name + "/")) throw std::invalid_argument("invalid mailbox rename destination");
        Transaction transaction(db_); ensure_mailbox(username);
        Statement query(db_, "SELECT name FROM mailbox_folders WHERE username=? ORDER BY name"); query.text(1, username);
        std::set<std::string> outside; std::vector<std::pair<std::string, std::string>> moved;
        while (query.row()) {
            const auto value = query.string(0);
            if (value == name || value.starts_with(name + "/")) {
                const auto replacement = folder_name(Json{{"folder", target + value.substr(name.size())}});
                moved.emplace_back(value, replacement);
            } else outside.insert(value);
        }
        if (moved.empty() || moved.front().first != name) return {{"ok", false}, {"code", "folder_not_found"}, {"error", "Mailbox does not exist."}};
        for (const auto& [old_name, new_name] : moved) if (outside.contains(new_name))
            return {{"ok", false}, {"code", "folder_exists"}, {"error", "Destination mailbox already exists."}};
        // The destination cannot overlap the old subtree; per-row renames are
        // collision free and the transaction hides every intermediate state.
        for (const auto& [old_name, new_name] : moved) {
            Statement messages(db_, "UPDATE messages SET folder=? WHERE username=? AND folder=?");
            messages.text(1, new_name); messages.text(2, username); messages.text(3, old_name); messages.done();
            Statement update(db_, "UPDATE mailbox_folders SET name=? WHERE username=? AND name=?");
            update.text(1, new_name); update.text(2, username); update.text(3, old_name); update.done();
        }
        folder_parents(username, target); prune_folder_parents(username); folder_limit(username);
        transaction.commit(); return {{"ok", true}, {"folder", target}};
    }
    Json folder_subscribe(const Json& request) {
        const auto username = address(request, "username"), name = folder_name(request);
        if (!request.contains("folder") || !request.contains("subscribed") || !request.at("subscribed").is_boolean())
            throw std::invalid_argument("folder and subscribed flag are required");
        Transaction transaction(db_); ensure_mailbox(username);
        Statement update(db_, "UPDATE mailbox_folders SET subscribed=? WHERE username=? AND name=?");
        update.integer(1, request.at("subscribed").get<bool>() ? 1 : 0); update.text(2, username); update.text(3, name); update.done();
        if (sqlite3_changes(db_) != 1) return {{"ok", false}, {"code", "folder_not_found"}, {"error", "Mailbox does not exist."}};
        transaction.commit(); return {{"ok", true}, {"folder", name}};
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
        save_search(id,uid,raw);
    }
    void save_search(const std::string& id,std::int64_t uid,const std::string& raw) {
        save_pop3_size(id,uid,static_cast<std::int64_t>(raw.size()),pop3_octets(raw));
        const auto document=search_document(raw);
        Statement index(db_,"INSERT INTO message_search(id,source_uid,sender,recipients,subject,body,filenames,has_attachment,display_to) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET source_uid=excluded.source_uid,sender=excluded.sender,recipients=excluded.recipients,subject=excluded.subject,body=excluded.body,filenames=excluded.filenames,has_attachment=excluded.has_attachment,display_to=excluded.display_to");
        index.text(1,id); index.integer(2,uid); index.text(3,document.from); index.text(4,document.recipients); index.text(5,document.subject);
        index.text(6,document.body); index.text(7,document.filenames); index.integer(8,document.attachment?1:0); index.text(9,document.to); index.done();
    }
    void save_pop3_size(const std::string& id, std::int64_t uid, std::int64_t size, std::int64_t octets) {
        Statement save(db_, "INSERT INTO message_pop3(id,source_uid,source_size,octets) VALUES(?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET source_uid=excluded.source_uid,source_size=excluded.source_size,octets=excluded.octets");
        save.text(1,id); save.integer(2,uid); save.integer(3,size); save.integer(4,octets); save.done();
    }
    void ensure_pop3_sizes(const std::string& username, const std::string& selected) {
        // A compatible side table keeps existing databases and updater rollback
        // working. Backfill only the requested maildrop, one message at a time;
        // later logins need metadata only. UID/size guards catch older writers,
        // draft replacement and folder moves without retaining raw mail in RAM.
        std::vector<std::tuple<std::string,std::int64_t,std::int64_t,std::int64_t>> pending;
        {
            Statement missing(db_, "SELECT m.id,m.uid,m.size,m.raw FROM messages m LEFT JOIN message_pop3 p ON p.id=m.id "
                "WHERE m.username=? AND m.folder=? AND (p.id IS NULL OR p.source_uid<>m.uid OR p.source_size<>m.size)");
            missing.text(1,username); missing.text(2,selected);
            while (missing.row()) pending.emplace_back(missing.string(0),missing.integer(1),missing.integer(2),pop3_octets(missing.string(3)));
        }
        for (const auto& [id,uid,size,octets] : pending) save_pop3_size(id,uid,size,octets);
    }
    void save_flags(const std::string& id, const Json& request) {
        Statement existing(db_, "SELECT answered,flagged,draft,deleted,keywords FROM message_flags WHERE id=?");
        existing.text(1, id); const bool present=existing.row();
        Statement save(db_, "INSERT INTO message_flags(id,answered,flagged,draft,deleted,keywords) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET answered=excluded.answered,flagged=excluded.flagged,draft=excluded.draft,deleted=excluded.deleted,keywords=excluded.keywords");
        save.text(1,id);
        const std::array<const char*,4> names{"answered","flagged","draft","deleted"};
        for(std::size_t i=0;i<names.size();++i) {
            if(request.contains(names[i]) && !request.at(names[i]).is_boolean()) throw std::invalid_argument("message flags must be boolean");
            save.integer(static_cast<int>(i+2),request.value(names[i],present && existing.integer(static_cast<int>(i))!=0)?1:0);
        }
        save.text(6, request.contains("keywords") ? keywords(request.at("keywords")).dump() : present ? existing.string(4) : "[]");
        save.done();
    }
    Json append(const Json& request) {
        const auto username=address(request,"username"), target=folder(request);
        const auto raw=field(request,"raw",static_cast<std::size_t>(max_message_));
        for(const auto* name:{"seen","answered","flagged","draft","deleted"}) if(request.contains(name) && !request.at(name).is_boolean()) throw std::invalid_argument("message flags must be boolean");
        const auto date=integer_field(request,"internal_date",now(),-2208988800LL,253402300799LL);
        Transaction transaction(db_); ensure_mailbox(username);
        if(!fits_quota(username,static_cast<std::int64_t>(raw.size()),1)) return {{"ok",false},{"error","mailbox quota exceeded"}};
        const auto id=random_hex(16); const auto uid=allocate_uid(username);
        insert_message(username,id,uid,raw,target,request.value("seen",false)); save_flags(id,request);
        Statement update(db_,"UPDATE messages SET created_at=? WHERE id=?"); update.integer(1,date); update.text(2,id); update.done();
        Statement mailbox(db_,"SELECT uidvalidity FROM mailboxes WHERE username=?"); mailbox.text(1,username); mailbox.row();
        const auto validity=mailbox.integer(0); transaction.commit();
        return {{"ok",true},{"id",id},{"uid",uid},{"uidvalidity",validity}};
    }
    Json copy(const Json& request) {
        const auto username=address(request,"username"), target=folder(request), source=folder(request,"source_folder");
        const auto ids=message_ids(request); const auto expected=request.value("expected_uids",Json::object());
        if(!expected.is_object()) throw std::invalid_argument("expected_uids must be an object");
        if(request.contains("move") && !request.at("move").is_boolean()) throw std::invalid_argument("move must be boolean");
        const bool move=request.value("move",false);
        Transaction transaction(db_); ensure_mailbox(username);
        Json records=Json::array(); std::int64_t added_bytes=0;
        for(const auto& id:ids) {
            const auto uid=integer_field(expected,id.c_str(),0,1,0xffffffffLL);
            Statement query(db_,"SELECT m.size,m.uid,m.seen,m.created_at,COALESCE(f.answered,0),COALESCE(f.flagged,0),COALESCE(f.draft,0),COALESCE(f.deleted,0),COALESCE(f.keywords,'[]') "
                "FROM messages m LEFT JOIN message_flags f ON f.id=m.id WHERE m.username=? AND m.id=? AND m.folder=? AND (?=0 OR m.uid=?)");
            query.text(1,username); query.text(2,id); query.text(3,source); query.integer(4,uid); query.integer(5,uid);
            if(!query.row()) return {{"ok",false},{"error","source message has changed"}};
            added_bytes+=query.integer(0);
            records.push_back({{"id",id},{"uid",query.integer(1)},{"seen",query.integer(2)!=0},{"internal_date",query.integer(3)},
                {"answered",query.integer(4)!=0},{"flagged",query.integer(5)!=0},{"draft",query.integer(6)!=0},{"deleted",query.integer(7)!=0},
                {"keywords",Json::parse(query.string(8))}});
        }
        if(!move && !fits_quota(username,added_bytes,static_cast<std::int64_t>(records.size()))) return {{"ok",false},{"error","mailbox quota exceeded"}};
        Json mappings=Json::array();
        for(const auto& record:records) {
            const auto uid=allocate_uid(username); const auto id=move?record.at("id").get<std::string>():random_hex(16);
            if(move) {
                Statement update(db_,"UPDATE messages SET folder=?,uid=? WHERE id=? AND username=?");
                update.text(1,target); update.integer(2,uid); update.text(3,id); update.text(4,username); update.done();
            } else {
                Statement source_message(db_,"SELECT raw FROM messages WHERE id=? AND username=?");
                source_message.text(1,record.at("id").get<std::string>()); source_message.text(2,username); source_message.row();
                insert_message(username,id,uid,source_message.string(0),target,record.at("seen").get<bool>()); save_flags(id,record);
                Statement verdict(db_,"INSERT INTO message_filter(id,action,score,reasons) SELECT ?,action,score,reasons FROM message_filter WHERE id=?");
                verdict.text(1,id); verdict.text(2,record.at("id").get<std::string>()); verdict.done();
                Statement date(db_,"UPDATE messages SET created_at=? WHERE id=?"); date.integer(1,record.at("internal_date").get<std::int64_t>()); date.text(2,id); date.done();
            }
            mappings.push_back({{"source_uid",record.at("uid")},{"uid",uid}});
        }
        Statement mailbox(db_,"SELECT uidvalidity FROM mailboxes WHERE username=?"); mailbox.text(1,username); mailbox.row();
        const auto validity=mailbox.integer(0); transaction.commit();
        return {{"ok",true},{"uidvalidity",validity},{"mappings",std::move(mappings)}};
    }
    Json deliver(const Json& request) {
        auto username = address(request, "username");
        auto raw = field(request, "raw", static_cast<std::size_t>(max_message_));
        auto delivery_id = identifier(request, "delivery_id");
        const auto submission_id = request.contains("submission_id") ? identifier(request, "submission_id") : std::string{};
        Transaction transaction(db_);
        {
            Statement existing(db_, "SELECT message_id FROM deliveries WHERE username=? AND delivery_id=?");
            existing.text(1, username); existing.text(2, delivery_id);
            if (existing.row()) return {{"ok", true}, {"id", existing.string(0)}, {"duplicate", true}};
        }
        if (!submission_id.empty()) {
            Statement previous(db_, "SELECT message_id FROM submission_deliveries WHERE username=? AND submission_id=?");
            previous.text(1, username); previous.text(2, submission_id);
            if (previous.row()) {
                const auto id = previous.string(0);
                Statement receipt(db_, "INSERT INTO deliveries(username,delivery_id,message_id) VALUES(?,?,?)");
                receipt.text(1, username); receipt.text(2, delivery_id); receipt.text(3, id); receipt.done();
                transaction.commit();
                return {{"ok", true}, {"id", id}, {"duplicate", true}};
            }
        }
        ensure_mailbox(username);
        if (!fits_quota(username, static_cast<std::int64_t>(raw.size()), 1))
            return {{"ok", false}, {"error", "mailbox quota exceeded"}};
        const auto uid = allocate_uid(username);
        auto id = random_hex(16);
        insert_message(username, id, uid, raw, folder(request));
        if(request.contains("filter_action")) {
            const auto action=field(request,"filter_action",16);
            if(action!="accept" && action!="spam") throw std::invalid_argument("invalid filter verdict");
            const auto score=request.value("spam_score",Json(0)); const auto reasons=request.value("spam_reasons",Json::array());
            if(!score.is_number() || !std::isfinite(score.get<double>()) || std::abs(score.get<double>())>1000000 || !reasons.is_array() || reasons.size()>128)
                throw std::invalid_argument("invalid filter metadata");
            for(const auto& reason:reasons) (void)field(Json{{"reason",reason}},"reason",256);
            Statement verdict(db_,"INSERT INTO message_filter(id,action,score,reasons) VALUES(?,?,?,?)");
            verdict.text(1,id); verdict.text(2,action); verdict.real(3,score.get<double>()); verdict.text(4,reasons.dump()); verdict.done();
        }
        {
            Statement insert(db_, "INSERT INTO deliveries(username,delivery_id,message_id) VALUES(?,?,?)");
            insert.text(1, username); insert.text(2, delivery_id); insert.text(3, id); insert.done();
        }
        if (!submission_id.empty()) {
            Statement receipt(db_, "INSERT INTO submission_deliveries(username,submission_id,message_id) VALUES(?,?,?)");
            receipt.text(1, username); receipt.text(2, submission_id); receipt.text(3, id); receipt.done();
        }
        transaction.commit();
        return {{"ok", true}, {"id", id}};
    }
    Json verification_candidates(const Json& request) {
        const auto username = address(request, "username");
        const auto selected_folder = folder(request);
        if (selected_folder != "INBOX" && selected_folder != "Trash")
            throw std::invalid_argument("Verification codes are available only in Inbox or Trash.");
        const auto max_age = integer_field(request, "max_age_seconds", 900, 1, 86400);
        const auto limit = integer_field(request, "limit", 30, 1, 50);
        const auto current = now();
        const auto budget = std::min<std::int64_t>(10 * 1024 * 1024, max_message_);
        // Query only recent own-account mail in the selected folder; never mutate flags. Filter
        // the size before reading raw so oversized MIME cannot exhaust memory.
        Statement query(db_, "SELECT m.id,m.raw,m.created_at,m.size FROM messages m "
            "LEFT JOIN message_flags f ON f.id=m.id WHERE m.username=? AND m.folder=? "
            "AND COALESCE(f.draft,0)=0 AND m.created_at>=? AND m.created_at<=? AND m.size<=? "
            "ORDER BY m.created_at DESC,m.uid DESC LIMIT 50");
        query.text(1, username); query.text(2, selected_folder); query.integer(3, current - max_age); query.integer(4, current); query.integer(5, budget);
        Json messages = Json::array(); std::int64_t bytes = 0;
        while (query.row() && static_cast<std::int64_t>(messages.size()) < limit) {
            const auto size = query.integer(3);
            if (size > budget - bytes) continue;
            auto raw = query.string(1);
            if (static_cast<std::int64_t>(raw.size()) > budget - bytes) continue;
            bytes += static_cast<std::int64_t>(raw.size());
            messages.push_back({{"id", query.string(0)}, {"raw", std::move(raw)}, {"internal_date", query.integer(2)}});
        }
        return {{"ok", true}, {"messages", std::move(messages)}};
    }
    Json search(const Json& request) {
        const auto username=address(request,"username");
        const auto selected=request.contains("folder") && request.at("folder")!="all" ? folder(request) : std::string{};
        const auto limit=integer_field(request,"limit",50,1,100), offset=integer_field(request,"offset",0,0,100000);
        const auto after=integer_field(request,"after",-2208988800LL,-2208988800LL,253402300799LL);
        const auto before=integer_field(request,"before",253402300799LL,-2208988800LL,253402300799LL);
        if(after>=before) throw std::invalid_argument("search after must precede before");
        for(const auto* name:{"seen","has_attachment"}) if(request.contains(name) && !request.at(name).is_boolean()) throw std::invalid_argument("search flags must be boolean");
        auto text=[&](const char* name) { return request.contains(name)?field(request,name,256,true):std::string{}; };
        const auto q=text("q"), from=text("from"), to=text("to"), subject=text("subject");
        Transaction transaction(db_);
        // Incremental indexing keeps an upgraded large mailbox responsive. Each
        // successful batch is durable, and clients can retry while indexing=true.
        std::vector<std::tuple<std::string,std::int64_t,std::string>> pending_index;
        { Statement missing(db_,"SELECT m.id,m.uid,m.raw,m.size FROM messages m LEFT JOIN message_search s ON s.id=m.id "
            "WHERE m.username=? AND (s.id IS NULL OR s.source_uid<>m.uid) ORDER BY m.created_at DESC,m.uid DESC LIMIT 100");
            missing.text(1,username); std::int64_t bytes=0;
            while(missing.row()) {
                if(bytes && bytes+missing.integer(3)>16*1024*1024) break;
                pending_index.emplace_back(missing.string(0),missing.integer(1),missing.string(2)); bytes+=missing.integer(3);
            } }
        for(const auto& [id,uid,raw]:pending_index) save_search(id,uid,raw);
        const std::string conditions=" FROM messages m JOIN message_search s ON s.id=m.id "
            "WHERE m.username=? AND (?='' OR m.folder=?) AND m.created_at>=? AND m.created_at<? "
            "AND (?=-1 OR m.seen=?) AND (?=-1 OR s.has_attachment=?) "
            "AND (?='' OR instr(lower(s.sender),lower(?))>0) AND (?='' OR instr(lower(s.recipients),lower(?))>0) "
            "AND (?='' OR instr(lower(s.subject),lower(?))>0) "
            "AND (?='' OR instr(lower(s.subject||char(10)||s.sender||char(10)||s.recipients||char(10)||s.body||char(10)||s.filenames),lower(?))>0)";
        auto bind=[&](Statement& statement) {
            statement.text(1,username); statement.text(2,selected); statement.text(3,selected); statement.integer(4,after); statement.integer(5,before);
            const int seen=request.contains("seen")?(request.at("seen").get<bool>()?1:0):-1;
            const int attached=request.contains("has_attachment")?(request.at("has_attachment").get<bool>()?1:0):-1;
            statement.integer(6,seen); statement.integer(7,seen); statement.integer(8,attached); statement.integer(9,attached);
            statement.text(10,from); statement.text(11,from); statement.text(12,to); statement.text(13,to);
            statement.text(14,subject); statement.text(15,subject); statement.text(16,q); statement.text(17,q);
        };
        Statement count(db_,("SELECT COUNT(*)"+conditions).c_str()); bind(count); count.row(); const auto total=count.integer(0);
        Statement query(db_,("SELECT m.id,m.uid,m.folder,m.size,m.seen,m.created_at,s.sender,s.display_to,s.subject,s.body,s.has_attachment"+conditions+
            " ORDER BY m.created_at DESC,m.uid DESC LIMIT ? OFFSET ?").c_str());
        bind(query); query.integer(18,limit); query.integer(19,offset); Json matches=Json::array();
        while(query.row()) {
            auto snippet=query.string(9); for(auto& ch:snippet) if(static_cast<unsigned char>(ch)<32) ch=' ';
            snippet=trim(snippet); if(snippet.size()>240) { std::size_t end=240; while(end && (static_cast<unsigned char>(snippet[end])&0xc0)==0x80)--end; snippet.resize(end); }
            matches.push_back({{"id",query.string(0)},{"uid",query.integer(1)},{"folder",query.string(2)},{"size",query.integer(3)},
                {"seen",query.integer(4)!=0},{"internal_date",query.integer(5)},{"from",query.string(6)},{"to",query.string(7)},
                {"subject",query.string(8)},{"snippet",snippet},{"has_attachment",query.integer(10)!=0}});
        }
        Statement pending(db_,"SELECT COUNT(*) FROM messages m LEFT JOIN message_search s ON s.id=m.id WHERE m.username=? AND (s.id IS NULL OR s.source_uid<>m.uid)");
        pending.text(1,username); pending.row(); const auto remaining=pending.integer(0);
        transaction.commit();
        return {{"ok",true},{"messages",std::move(matches)},{"total",total},{"offset",offset},{"limit",limit},
            {"has_more",offset+limit<total},{"indexing",remaining>0},{"indexing_remaining",remaining}};
    }
    void record_queue_status(const std::string& id,const std::string& state,const std::string& error,const std::string& scope,bool success=false) {
        const auto timestamp=now();
        Statement queued(db_,"SELECT attempts,next_attempt FROM queue WHERE id=?"); queued.text(1,id);
        if(!queued.row()) return;
        const auto attempts=queued.integer(0)+(success?1:0), next=state=="retrying"?queued.integer(1):0;
        Statement update(db_,"UPDATE delivery_status SET state=?,attempts=?,error=?,updated_at=?,next_attempt=?,delivery_scope=? WHERE queue_id=?");
        update.text(1,state); update.integer(2,attempts); update.text(3,error); update.integer(4,timestamp); update.integer(5,next); update.text(6,scope); update.text(7,id); update.done();
        if(sqlite3_changes(db_)==0) return;
        Statement event(db_,"INSERT INTO delivery_events(queue_id,state,attempts,error,created_at,delivery_scope) VALUES(?,?,?,?,?,?)");
        event.text(1,id); event.text(2,state); event.integer(3,attempts); event.text(4,error); event.integer(5,timestamp); event.text(6,scope); event.done();
    }
    Json finish_queue(const Json& request) {
        const auto id=identifier(request,"id");
        const auto scope=request.contains("delivery_scope")?field(request,"delivery_scope",32):std::string("remote_mta");
        if(scope!="remote_mta" && scope!="local_mailbox") throw std::invalid_argument("invalid delivery scope");
        Transaction transaction(db_); record_queue_status(id,"delivered","",scope,true);
        Statement remove(db_,"DELETE FROM queue WHERE id=?"); remove.text(1,id); remove.done();
        Statement context(db_,"DELETE FROM queue_context WHERE queue_id=?"); context.text(1,id); context.done();
        Statement route(db_,"DELETE FROM queue_routes WHERE queue_id=?"); route.text(1,id); route.done();
        transaction.commit(); return {{"ok",true}};
    }
    Json delivery_status(const Json& request) {
        const auto username=address(request,"username"), id=identifier(request,"id");
        Statement query(db_,"SELECT queue_id,recipient,submission_id,state,attempts,error,created_at,updated_at,next_attempt,delivery_scope "
            "FROM delivery_status WHERE username=? AND sent_id=? ORDER BY recipient");
        query.text(1,username); query.text(2,id); Json recipients=Json::array(); std::string submission;
        std::size_t history_budget=192*1024;
        while(query.row()) {
            submission=query.string(2); Json history=Json::array();
            Statement events(db_,"SELECT state,attempts,error,created_at,delivery_scope FROM delivery_events WHERE queue_id=? ORDER BY id DESC LIMIT 101");
            events.text(1,query.string(0));
            bool truncated=false;
            while(events.row()) {
                if(history.size()==100) {truncated=true; break;}
                Json event{{"state",events.string(0)},{"attempts",events.integer(1)},{"error",events.string(2)},{"at",events.integer(3)},{"delivery_scope",events.string(4)}};
                const auto size=event.dump().size(); if(size>history_budget) {truncated=true; break;} history_budget-=size; history.push_back(std::move(event));
            }
            std::reverse(history.begin(),history.end());
            recipients.push_back({{"recipient",query.string(1)},{"state",query.string(3)},{"attempts",query.integer(4)},{"error",query.string(5)},
                {"created_at",query.integer(6)},{"updated_at",query.integer(7)},{"next_attempt",query.integer(8)},{"delivery_scope",query.string(9)},{"history",std::move(history)},{"history_truncated",truncated}});
        }
        if(recipients.empty()) return {{"ok",false},{"error","No delivery history is available for this message."}};
        return {{"ok",true},{"id",id},{"submission_id",submission},{"recipients",std::move(recipients)},
            {"notice","Remote acceptance confirms the receiving mail server accepted the message; it does not confirm Inbox placement or reading."}};
    }
    Json list(const Json& request) {
        auto username = address(request, "username");
        const auto selected = folder(request);
        if (request.contains("include_envelope") && !request.at("include_envelope").is_boolean())
            throw std::invalid_argument("include_envelope must be boolean");
        if (request.contains("claim_recent") && !request.at("claim_recent").is_boolean())
            throw std::invalid_argument("claim_recent must be boolean");
        if (request.contains("include_pop3_size") && !request.at("include_pop3_size").is_boolean())
            throw std::invalid_argument("include_pop3_size must be boolean");
        const auto include_envelope = request.value("include_envelope", false);
        const auto include_pop3_size = request.value("include_pop3_size", false);
        Transaction transaction(db_);
        ensure_mailbox(username);
        if (include_pop3_size) ensure_pop3_sizes(username,selected);
        Json result = {{"ok", true}, {"folder", selected}, {"messages", Json::array()}};
        {
            Statement query(db_, "SELECT uidvalidity,uidnext FROM mailboxes WHERE username=?"); query.text(1, username); query.row();
            result["uidvalidity"] = query.integer(0); result["uidnext"] = query.integer(1);
        }
        std::int64_t recent_uid = 0;
        { Statement query(db_, "SELECT recent_uid FROM mailbox_folders WHERE username=? AND name=?");
            query.text(1, username); query.text(2, selected);
            if (!query.row()) throw std::runtime_error("mailbox catalog missing folder");
            recent_uid = query.integer(0); }
        {
            Statement query(db_, "SELECT m.id,m.uid,m.size,m.seen,m.created_at,COALESCE(f.answered,0),COALESCE(f.flagged,0),COALESCE(f.draft,0),COALESCE(f.deleted,0),COALESCE(f.keywords,'[]'),p.octets "
                "FROM messages m LEFT JOIN message_flags f ON f.id=m.id LEFT JOIN message_pop3 p ON p.id=m.id AND p.source_uid=m.uid AND p.source_size=m.size "
                "WHERE m.username=? AND m.folder=? ORDER BY m.uid");
            query.text(1, username); query.text(2, selected);
            while (query.row()) {
                result["messages"].push_back({{"id", query.string(0)}, {"uid", query.integer(1)},
                    {"size", query.integer(2)}, {"seen", query.integer(3) != 0}, {"internal_date", query.integer(4)}, {"folder", selected},
                    {"answered",query.integer(5)!=0},{"flagged",query.integer(6)!=0},{"draft",query.integer(7)!=0},{"deleted",query.integer(8)!=0},
                    {"keywords",Json::parse(query.string(9))},{"recent",query.integer(1)>recent_uid}});
                if (include_pop3_size) {
                    if (query.null(10)) throw std::runtime_error("missing POP3 size metadata");
                    result["messages"].back()["pop3_size"] = query.integer(10);
                }
            }
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
        const auto upper_uid = result.at("uidnext").get<std::int64_t>() - 1;
        if (request.value("claim_recent", false) && recent_uid < upper_uid) {
            // Snapshot and claim share one transaction: only one writable IMAP
            // session can receive each arrival as newly Recent. Other readers,
            // including Webmail/EXAMINE/STATUS, never consume that status.
            Statement update(db_, "UPDATE mailbox_folders SET recent_uid=? WHERE username=? AND name=?");
            update.integer(1, upper_uid); update.text(2, username); update.text(3, selected); update.done();
        }
        transaction.commit();
        return result;
    }
    Json folders(const Json& request) {
        const auto username = address(request, "username");
        Transaction transaction(db_); ensure_mailbox(username);
        Json names = Json::array();
        std::vector<std::string> available(folder_names.begin(), folder_names.end());
        { Statement custom(db_, "SELECT name FROM mailbox_folders WHERE username=? AND selectable=1 ORDER BY name");
            custom.text(1, username); while (custom.row()) if (!system_folder(custom.string(0))) available.push_back(custom.string(0)); }
        for (const auto& name : available) {
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
            save_search(id,uid,raw);
        }
        save_flags(id,{{"draft",true}});
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
        if (request.contains("require_deleted") && !request.at("require_deleted").is_boolean())
            throw std::invalid_argument("require_deleted must be boolean");
        const bool require_deleted = request.value("require_deleted", false);
        if (require_deleted && (!request.value("permanent", false) || !request.contains("folder") || !request.contains("expected_uids")))
            throw std::invalid_argument("expunge requires permanent deletion, folder and expected UIDs");
        const auto selected = request.contains("folder") ? folder(request) : std::string{};
        const auto expected_uids = request.value("expected_uids", Json::object());
        if (!expected_uids.is_object()) throw std::invalid_argument("expected_uids must be an object");
        for (const auto& [id, value] : expected_uids.items()) {
            (void)identifier(Json{{"id", id}}, "id");
            (void)integer_field(Json{{"uid", value}}, "uid", 0, 1, 0xffffffffLL);
        }
        Transaction transaction(db_); Json deleted_ids = Json::array();
        if (request.value("permanent", false)) {
            for (const auto& id : ids) {
                // Protocol sessions delete exactly their original snapshot;
                // moving or rewriting a draft while connected must not delete
                // the replacement message or a message in another folder.
                if (request.contains("expected_uids") && !expected_uids.contains(id)) continue;
                const auto uid = expected_uids.contains(id) ? expected_uids.at(id).get<std::int64_t>() : 0;
                Statement update(db_, "DELETE FROM messages WHERE username=? AND id=? AND (?='' OR folder=?) AND (?=0 OR uid=?) "
                    "AND (?=0 OR EXISTS(SELECT 1 FROM message_flags f WHERE f.id=messages.id AND f.deleted=1))");
                update.text(1, username); update.text(2, id); update.text(3, selected); update.text(4, selected);
                update.integer(5, uid); update.integer(6, uid); update.integer(7, require_deleted ? 1 : 0); update.done();
                if (sqlite3_changes(db_)) deleted_ids.push_back(id);
            }
        } else {
            ensure_mailbox(username); move_messages(username, ids, "Trash");
        }
        // Delivery tombstones intentionally survive deletion: a retried queue job
        // must never resurrect mail the recipient already deleted.
        transaction.commit();
        return {{"ok", true}, {"deleted_ids", std::move(deleted_ids)}};
    }
    Json queue_list(const Json& request) {
        const auto limit = integer_field(request, "limit", 1, 1, 100);
        Statement query(db_, "SELECT q.id,q.sender,q.recipient,q.raw,q.attempts,q.size,q.created_at,q.submission_id,EXISTS(SELECT 1 FROM queue_routes r WHERE r.queue_id=q.id),"
            "COALESCE(c.sent_username,''),COALESCE(c.inbound,1),COALESCE(c.peer_ip,''),COALESCE(c.helo,'') FROM queue q LEFT JOIN queue_context c ON c.queue_id=q.id "
            "WHERE q.state='pending' AND q.next_attempt<=? ORDER BY q.next_attempt,q.created_at,q.id LIMIT ?");
        query.integer(1, now()); query.integer(2, limit);
        Json jobs = Json::array();
        std::int64_t response_bytes = 0;
        while (query.row()) {
            // A batch stays within one raw-message budget. This also avoids
            // allocating N maximum-sized messages into a single HTTP reply.
            const auto size = query.integer(5);
            if (!jobs.empty() && response_bytes + size > max_message_) break;
            jobs.push_back({{"id", query.string(0)}, {"sender", query.string(1)}, {"recipient", query.string(2)},
                {"raw", query.string(3)}, {"attempts", query.integer(4)}, {"created_at",query.integer(6)}, {"submission_id",query.string(7)}, {"local_route",query.integer(8)!=0},
                {"sent_username",query.string(9)},{"inbound",query.integer(10)!=0},{"peer_ip",query.string(11)},{"helo",query.string(12)}});
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
    Config config_;
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
