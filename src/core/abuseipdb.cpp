#include <postplus/abuseipdb.hpp>
#include <postplus/dns.hpp>
#include <algorithm>
#include <charconv>
#include <condition_variable>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include <sqlite3.h>
#include <openssl/sha.h>

namespace postplus {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::size_t response_limit = 8 * 1024 * 1024;
const std::vector<std::string> endpoints{"blacklist","bulk-report","bulk-check","check","check-block","clear-address","report","reports"};
std::int64_t now_seconds() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
std::string credential_id(const std::string& key) {
    unsigned char digest[SHA256_DIGEST_LENGTH];SHA256(reinterpret_cast<const unsigned char*>(key.data()),key.size(),digest);
    constexpr char hex[]="0123456789abcdef";std::string result;for(const auto ch:digest){result+=hex[ch>>4];result+=hex[ch&15];}return result;
}
// This separate connection never borrows the authentication store's mutex.
// Reservations commit before requests, so process crashes and key rotation do
// not replenish the installation's conservative UTC-day allowance.
class AutomationStore {
    sqlite3* db_=nullptr;mutable std::mutex mutex_;bool persistent_;
    void execute(const char* sql) const {if(sqlite3_exec(db_,sql,nullptr,nullptr,nullptr)!=SQLITE_OK)throw std::runtime_error("AbuseIPDB automation storage unavailable");}
    struct Query {
        sqlite3_stmt* statement=nullptr;
        Query(sqlite3* db,const char* sql){if(sqlite3_prepare_v2(db,sql,-1,&statement,nullptr)!=SQLITE_OK)throw std::runtime_error("AbuseIPDB automation storage unavailable");}
        ~Query(){sqlite3_finalize(statement);}
        void text(int index,const std::string& value){if(sqlite3_bind_text(statement,index,value.c_str(),static_cast<int>(value.size()),SQLITE_TRANSIENT)!=SQLITE_OK)throw std::runtime_error("AbuseIPDB automation storage unavailable");}
        void number(int index,std::int64_t value){sqlite3_bind_int64(statement,index,value);}
        int step(){const int code=sqlite3_step(statement);if(code!=SQLITE_ROW&&code!=SQLITE_DONE)throw std::runtime_error("AbuseIPDB automation storage unavailable");return code;}
        std::int64_t number(int index)const{return sqlite3_column_int64(statement,index);}
        std::string text(int index)const{const auto* value=sqlite3_column_text(statement,index);return value?reinterpret_cast<const char*>(value):"";}
    };
public:
    explicit AutomationStore(const std::filesystem::path& path):persistent_(!path.empty()) {
        const auto utf8=path.u8string();const std::string name=path.empty()?":memory:":std::string(reinterpret_cast<const char*>(utf8.data()),utf8.size());
        if(sqlite3_open_v2(name.c_str(),&db_,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,nullptr)!=SQLITE_OK){if(db_)sqlite3_close(db_);throw std::runtime_error("Cannot open AbuseIPDB automation storage");}
        sqlite3_busy_timeout(db_,1000);
        try {execute("PRAGMA trusted_schema=OFF; CREATE TABLE IF NOT EXISTS abuseipdb_daily_usage(day INTEGER NOT NULL,endpoint TEXT NOT NULL,reserved INTEGER NOT NULL,PRIMARY KEY(day,endpoint)); CREATE TABLE IF NOT EXISTS abuseipdb_blacklists(credential TEXT PRIMARY KEY,fetched_at INTEGER NOT NULL DEFAULT 0,attempted_at INTEGER NOT NULL DEFAULT 0,payload TEXT NOT NULL DEFAULT '[]');");}
        catch(...){sqlite3_close(db_);throw;}
    }
    ~AutomationStore(){sqlite3_close(db_);}
    std::string reserve(const std::string& endpoint,int limit,bool automated,bool scheduled,int interval,const std::string& credential) {
        std::lock_guard lock(mutex_);const auto now=now_seconds();execute("BEGIN IMMEDIATE");
        try {
            Query count(db_,"SELECT reserved FROM abuseipdb_daily_usage WHERE day=? AND endpoint=?");count.number(1,now/86400);count.text(2,endpoint);const auto used=count.step()==SQLITE_ROW?count.number(0):0;
            if(automated&&used>=limit){execute("ROLLBACK");return "daily_budget";}
            if(scheduled){Query schedule(db_,"SELECT fetched_at,attempted_at FROM abuseipdb_blacklists WHERE credential=?");schedule.text(1,credential);if(schedule.step()==SQLITE_ROW&&(schedule.number(0)+interval>now||schedule.number(1)+900>now)){execute("ROLLBACK");return "not_due";}}
            Query save(db_,"INSERT INTO abuseipdb_daily_usage VALUES(?,?,1) ON CONFLICT(day,endpoint) DO UPDATE SET reserved=MIN(reserved+1,2147483647)");save.number(1,now/86400);save.text(2,endpoint);save.step();
            if(scheduled){Query attempt(db_,"INSERT INTO abuseipdb_blacklists(credential,attempted_at) VALUES(?,?) ON CONFLICT(credential) DO UPDATE SET attempted_at=excluded.attempted_at");attempt.text(1,credential);attempt.number(2,now);attempt.step();}
            Query prune(db_,"DELETE FROM abuseipdb_daily_usage WHERE day<?");prune.number(1,now/86400-2);prune.step();Query old_cache(db_,"DELETE FROM abuseipdb_blacklists WHERE fetched_at<? AND attempted_at<?");old_cache.number(1,now-172800);old_cache.number(2,now-172800);old_cache.step();execute("COMMIT");return {};
        }catch(...){execute("ROLLBACK");throw;}
    }
    Json snapshot(const std::string& credential={},bool include_entries=false)const {
        std::lock_guard lock(mutex_);const auto now=now_seconds();Json result={{"persistent",persistent_},{"day",now/86400},{"used",Json::object()}};
        Query count(db_,"SELECT endpoint,reserved FROM abuseipdb_daily_usage WHERE day=?");count.number(1,now/86400);while(count.step()==SQLITE_ROW)result["used"][count.text(0)]=count.number(1);
        Query cache(db_,include_entries?"SELECT fetched_at,attempted_at,payload FROM abuseipdb_blacklists WHERE credential=?":"SELECT fetched_at,attempted_at,'[]' FROM abuseipdb_blacklists WHERE credential=?");cache.text(1,credential);const bool found=cache.step()==SQLITE_ROW;result["credential"]=credential;result["fetched_at"]=found?cache.number(0):0;result["attempted_at"]=found?cache.number(1):0;const auto payload=found?cache.text(2):"[]";result["entries"]=payload.size()<=response_limit?Json::parse(payload,nullptr,false):Json();result["cache_valid"]=result["entries"].is_array()&&result["entries"].size()<=10000;if(!result["cache_valid"].get<bool>())result["entries"]=Json::array();return result;
    }
    void save_blacklist(const std::string& credential,const Json& entries) {
        std::lock_guard lock(mutex_);Query save(db_,"INSERT INTO abuseipdb_blacklists(credential,fetched_at,payload) VALUES(?,?,?) ON CONFLICT(credential) DO UPDATE SET fetched_at=excluded.fetched_at,payload=excluded.payload");save.text(1,credential);save.number(2,now_seconds());save.text(3,entries.dump());save.step();
    }
};
[[noreturn]] void invalid(const std::string& field) { throw AbuseError(field, "Check the AbuseIPDB field: " + field); }
std::string string_field(const Json& input, const std::string& key, std::size_t maximum, bool required = true) {
    if (!input.contains(key)) { if (required) invalid(key); return {}; }
    if (!input.at(key).is_string()) invalid(key);
    auto value = input.at(key).get<std::string>();
    if ((required && value.empty()) || value.size() > maximum || value.find('\0') != value.npos) invalid(key);
    return value;
}
int integer(const Json& input, const std::string& key, int fallback, int minimum, int maximum) {
    if (!input.contains(key)) return fallback;
    const auto& value = input.at(key);
    if (!value.is_number_integer() || (value.is_number_unsigned() && value.get<std::uint64_t>() > static_cast<unsigned>(maximum))) invalid(key);
    const auto number = value.get<std::int64_t>();
    if (number < minimum || number > maximum) invalid(key);
    return static_cast<int>(number);
}
std::string public_ip(const std::string& text) {
    std::error_code error; auto address = ip::make_address(trim(text), error);
    if (error || !is_public_mail_address(address)) invalid("ip");
    if (address.is_v6() && address.to_v6().is_v4_mapped()) {
        const auto bytes = address.to_v6().to_bytes();
        address = ip::address_v4({bytes[12],bytes[13],bytes[14],bytes[15]});
    }
    return address.to_string();
}
std::string encode(std::string_view value) {
    constexpr char hex[] = "0123456789ABCDEF"; std::string result;
    for (const unsigned char ch : value) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~') result += static_cast<char>(ch);
        else { result += '%'; result += hex[ch >> 4]; result += hex[ch & 15]; }
    }
    return result;
}
std::string categories(const Json& input) {
    if (!input.contains("categories") || !input.at("categories").is_array() || input.at("categories").empty() || input.at("categories").size() > 23) invalid("categories");
    std::set<int> ids;
    for (const auto& value : input.at("categories")) {
        const int id = integer(Json{{"id",value}}, "id", 0, 1, 23);
        ids.insert(id);
    }
    std::string result; for (const int id : ids) { if (!result.empty()) result += ','; result += std::to_string(id); }
    return result;
}
bool safe_key(const std::string& key) {
    return key.size() <= 512 && std::all_of(key.begin(), key.end(), [](unsigned char ch) { return ch > 32 && ch < 127; });
}
std::string key_for(const Json& settings) {
    const auto env_name = settings.at("api_key_env").get<std::string>();
    if (!env_name.empty()) if (const auto* value = std::getenv(env_name.c_str())) {
        std::string key(value); return safe_key(key) ? key : std::string{};
    }
    return settings.value("api_key", std::string{});
}
std::string utc_time() {
    const auto now = std::time(nullptr); std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    char output[32]{}; std::strftime(output, sizeof(output), "%Y-%m-%dT%H:%M:%SZ", &tm); return output;
}
std::string csv_field(const std::string& value) {
    std::string result = "\""; for (const auto ch : value) { if (ch == '"') result += '"'; result += ch; } return result + '"';
}
std::optional<Json> reputation_data(const Json& result,const std::string& address) {
    try {
        if(result.value("ok",false) && result.at("data").is_object()) {
            const auto& value=result.at("data");
            if(public_ip(value.value("ipAddress",std::string{}))==address && value.value("isPublic",false) &&
                value.contains("abuseConfidenceScore") && value.at("abuseConfidenceScore").is_number_integer() &&
                value.at("abuseConfidenceScore").get<std::int64_t>()>=0 && value.at("abuseConfidenceScore").get<std::int64_t>()<=100 &&
                value.contains("totalReports") && value.at("totalReports").is_number_integer() &&
                value.at("totalReports").get<std::int64_t>()>=0)return value;
        }
    }catch(const std::exception&){}
    return {};
}
std::uint64_t unsigned_text(const std::string& text, int base = 10) {
    std::uint64_t result = 0; const auto [last,error] = std::from_chars(text.data(), text.data() + text.size(), result, base);
    if (text.empty() || error != std::errc{} || last != text.data() + text.size()) throw std::runtime_error("Invalid AbuseIPDB response");
    return result;
}
AbuseHttpResponse native_transport(const AbuseHttpRequest& request, const std::string& key, Clock::time_point deadline) {
    Connection connection(std::chrono::seconds(4)); connection.set_deadline(deadline);
    connection.connect("api.abuseipdb.com",443); connection.start_tls_client("api.abuseipdb.com");
    std::string wire = request.method + " /api/v2/" + request.target + " HTTP/1.1\r\nHost: api.abuseipdb.com\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nKey: " + key + "\r\nUser-Agent: PostPlus/" POSTPLUS_VERSION "\r\nConnection: close\r\n";
    if (!request.body.empty() || request.method == "POST" || request.method == "DELETE")
        wire += "Content-Type: " + request.content_type + "\r\nContent-Length: " + std::to_string(request.body.size()) + "\r\n";
    connection.write(wire + "\r\n" + request.body);
    const auto status = connection.line(4096);
    if ((!status.starts_with("HTTP/1.1 ") && !status.starts_with("HTTP/1.0 ")) || status.size() < 12) throw std::runtime_error("Invalid AbuseIPDB status");
    AbuseHttpResponse result; result.status = static_cast<int>(unsigned_text(status.substr(9,3)));
    if (result.status < 200 || result.status > 599) throw std::runtime_error("Invalid AbuseIPDB status");
    std::size_t header_bytes = 0; bool complete = false;
    for (int count=0; count<100; ++count) {
        const auto line = connection.line(8192); if (line.empty()) { complete = true; break; }
        header_bytes += line.size(); const auto colon = line.find(':');
        if (header_bytes > 32768 || colon == line.npos || !colon) throw std::runtime_error("Invalid AbuseIPDB headers");
        const auto name = lower(line.substr(0,colon)), value = trim(line.substr(colon+1));
        if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-_") != name.npos ||
            std::any_of(value.begin(),value.end(),[](unsigned char ch){return (ch < 32 && ch != '\t') || ch == 127;}))
            throw std::runtime_error("Invalid AbuseIPDB headers");
        if (result.headers.contains(name)) {
            if (name == "content-length" || name == "transfer-encoding" || name.starts_with("x-ratelimit-") || name == "retry-after") throw std::runtime_error("Duplicate AbuseIPDB headers");
            continue;
        }
        result.headers[name] = value;
    }
    if (!complete) throw std::runtime_error("AbuseIPDB headers exceeded limit");
    if (result.headers.contains("content-encoding") && lower(result.headers.at("content-encoding")) != "identity") throw std::runtime_error("Unsupported AbuseIPDB encoding");
    if (result.status == 204) return result;
    if (result.headers.contains("transfer-encoding")) {
        if (result.headers.contains("content-length") || lower(result.headers.at("transfer-encoding")) != "chunked") throw std::runtime_error("Invalid AbuseIPDB framing");
        for (int chunks=0; chunks<16384; ++chunks) {
            const auto line = connection.line(1024); const auto size = unsigned_text(line.substr(0,line.find(';')),16);
            if (size > response_limit-result.body.size()) throw std::runtime_error("AbuseIPDB response exceeded limit");
            if (!size) {
                std::size_t bytes = 0; for (int trailer=0; trailer<32; ++trailer) {
                    const auto text = connection.line(8192); bytes += text.size(); if (bytes > 32768) break;
                    if (text.empty()) return result;
                }
                throw std::runtime_error("Invalid AbuseIPDB trailers");
            }
            result.body += connection.read(static_cast<std::size_t>(size)); if (connection.read(2) != "\r\n") throw std::runtime_error("Invalid AbuseIPDB chunk");
        }
        throw std::runtime_error("AbuseIPDB chunks exceeded limit");
    }
    if (result.headers.contains("content-length")) {
        const auto size = unsigned_text(result.headers.at("content-length")); if (size > response_limit) throw std::runtime_error("AbuseIPDB response exceeded limit");
        result.body = connection.read(static_cast<std::size_t>(size)); return result;
    }
    while (result.body.size() <= response_limit) { try { result.body += connection.read(1); } catch (const NetworkEof&) { return result; } }
    throw std::runtime_error("AbuseIPDB response exceeded limit");
}
}

Json abuseipdb_defaults() {
    return {{"enabled",false},{"api_key_env","POSTPLUS_ABUSEIPDB_API_KEY"},{"api_key",""},{"verification_token",""},
        {"auto_ban",false},{"score_threshold",90},{"min_reports",3},{"ban_seconds",3600},{"max_age_days",30},{"cache_seconds",86400},
        {"blacklist_enabled",true},{"blacklist_refresh_seconds",21600},{"automatic_check_budget",800},{"automatic_report_budget",800},{"automatic_blacklist_budget",4},
        {"auto_report",false},{"report_threshold",10},{"report_categories",Json::array({18})},{"report_cooldown_seconds",86400}};
}
Json validate_abuseipdb_settings(const Json& current, const Json& patch) {
    if (!patch.is_object()) invalid("settings");
    const auto defaults = abuseipdb_defaults();auto result=defaults;result.update(current);
    for (const auto& [name,value] : patch.items()) {
        if (name == "clear_api_key") { if (!value.is_boolean()) invalid(name); continue; }
        if (!defaults.contains(name)) invalid(name);
        if (name == "api_key" && value.is_string() && value.get<std::string>().empty()) continue;
        result[name] = value;
    }
    for (const auto* field : {"enabled","auto_ban","auto_report","blacklist_enabled"}) if (!result.at(field).is_boolean()) invalid(field);
    const auto env_name = string_field(result,"api_key_env",128,false);
    if (env_name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != env_name.npos || (!env_name.empty() && env_name.front()>='0' && env_name.front()<='9')) invalid("api_key_env");
    const auto key = string_field(result,"api_key",512,false); if (!safe_key(key)) invalid("api_key");
    const auto token = string_field(result,"verification_token",256,false);
    if (!token.empty() && (!token.starts_with("abuseipdb-verification-") || token.size() <= std::string_view("abuseipdb-verification-").size() || token.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != token.npos)) invalid("verification_token");
    for (const auto& [name,range] : std::map<std::string,std::pair<int,int>>{{"score_threshold",{1,100}},{"min_reports",{1,1000000}},{"ban_seconds",{1,604800}},{"max_age_days",{1,365}},{"cache_seconds",{60,86400}},{"report_threshold",{2,10000}},{"report_cooldown_seconds",{900,604800}},{"blacklist_refresh_seconds",{3600,604800}},{"automatic_check_budget",{0,1000000}},{"automatic_report_budget",{0,1000000}},{"automatic_blacklist_budget",{0,1000000}}})
        (void)integer(result,name,defaults.at(name).get<int>(),range.first,range.second);
    (void)categories(Json{{"categories",result.at("report_categories")}});
    if (patch.value("clear_api_key",false)) result["api_key"] = "";
    return result;
}
AbuseHttpRequest abuseipdb_request(const std::string& endpoint, const Json& input) {
    if (!input.is_object()) invalid("input");
    AbuseHttpRequest result{"GET",endpoint,{}}; std::vector<std::pair<std::string,std::string>> parameters;
    std::set<std::string> allowed;
    auto add = [&](std::string name,std::string value) { parameters.emplace_back(std::move(name),std::move(value)); };
    auto number = [&](const char* key,int fallback,int minimum,int maximum) { add(key,std::to_string(integer(input,key,fallback,minimum,maximum))); };
    if (endpoint == "check" || endpoint == "reports") {
        allowed = {"ipAddress","maxAgeInDays","verbose","page","perPage"};
        add("ipAddress",public_ip(string_field(input,"ipAddress",64))); number("maxAgeInDays",30,1,365);
        if (endpoint == "check") {
            if (input.contains("page") || input.contains("perPage")) invalid("page");
            if (input.contains("verbose")) { if (!input.at("verbose").is_boolean()) invalid("verbose"); if (input.at("verbose").get<bool>()) add("verbose",""); }
        } else { if (input.contains("verbose")) invalid("verbose"); number("page",1,1,1000000); number("perPage",25,1,100); }
    } else if (endpoint == "blacklist") {
        allowed = {"confidenceMinimum","limit","ipVersion","onlyCountries","exceptCountries"};
        number("confidenceMinimum",100,25,100); number("limit",1000,1,10000);
        if (input.contains("ipVersion")) { const auto version=integer(input,"ipVersion",4,4,6); if (version==5) invalid("ipVersion"); add("ipVersion",std::to_string(version)); }
        for (const auto* name : {"onlyCountries","exceptCountries"}) if (input.contains(name)) {
            auto value=string_field(input,name,1000); if (value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ,") != value.npos) invalid(name); add(name,value);
        }
    } else if (endpoint == "check-block") {
        allowed = {"network","maxAgeInDays"}; const auto network=string_field(input,"network",80); const auto slash=network.find('/');
        if (slash==network.npos || network.find('/',slash+1)!=network.npos) invalid("network");
        const auto address=public_ip(network.substr(0,slash));
        const int maximum=address.find(':')==address.npos?32:128;
        std::uint64_t prefix=0; try { prefix=unsigned_text(network.substr(slash+1)); } catch(const std::exception&) {invalid("network");}
        if (prefix<static_cast<unsigned>(maximum==32?16:112) || prefix>static_cast<unsigned>(maximum)) invalid("network");
        add("network",address+"/"+std::to_string(prefix)); number("maxAgeInDays",30,1,365);
    } else if (endpoint == "report") {
        allowed = {"ip","categories","comment","timestamp"}; result.method="POST";
        add("ip",public_ip(string_field(input,"ip",64))); add("categories",categories(input));
        add("comment",string_field(input,"comment",1024));
        if (input.contains("timestamp")) add("timestamp",string_field(input,"timestamp",64));
    } else if (endpoint == "clear-address") {
        allowed = {"ipAddress"}; result.method="DELETE"; add("ipAddress",public_ip(string_field(input,"ipAddress",64)));
    } else if (endpoint == "bulk-report") {
        allowed = {"reports"}; result.method="POST";
        if (!input.contains("reports") || !input.at("reports").is_array() || input.at("reports").empty() || input.at("reports").size()>1000) invalid("reports");
        std::string csv="IP,Categories,ReportDate,Comment\r\n"; std::set<std::string> seen;
        for (const auto& row : input.at("reports")) {
            (void)abuseipdb_request("report",row); const auto address=public_ip(row.at("ip").get<std::string>());
            if (!seen.insert(address).second) invalid("reports");
            csv += csv_field(address)+","+csv_field(categories(row))+","+csv_field(row.value("timestamp",utc_time()))+","+csv_field(row.at("comment").get<std::string>())+"\r\n";
        }
        const auto boundary="postplus"+random_hex(16); result.content_type="multipart/form-data; boundary="+boundary;
        result.body="--"+boundary+"\r\nContent-Disposition: form-data; name=\"csv\"; filename=\"report.csv\"\r\nContent-Type: text/csv\r\n\r\n"+csv+"\r\n--"+boundary+"--\r\n";
    } else invalid("endpoint");
    for (const auto& [name,value] : input.items()) { (void)value; if (!allowed.contains(name)) invalid(name); }
    std::string encoded; for (const auto& [name,value] : parameters) { if (!encoded.empty()) encoded+='&'; encoded+=encode(name)+"="+encode(value); }
    if (result.method=="POST" || result.method=="DELETE") { if (endpoint!="bulk-report") result.body=encoded; }
    else if (!encoded.empty()) result.target+='?'+encoded;
    return result;
}

struct AbuseIpDb::Impl {
    mutable std::mutex mutex;
    Json config=abuseipdb_defaults(), quotas=Json::object();
    AbuseTransport transport;
    AutomationStore store;
    std::function<void(Json)> event_sink;
    unsigned active=0;
    std::map<std::string,int> pending_requests;
    std::set<std::string> quota_refresh_keys;
    Json quota_refresh={{"status","not_refreshed"},{"checked_at",nullptr},{"probes",Json::array()}};
    std::uint64_t generation=0;
    struct Cached { std::int64_t expires; std::optional<Json> data; };
    std::map<std::string,Cached> cache;
    std::map<std::string,std::int64_t> pending_checks, cooldowns;
    std::deque<Json> reports;
    std::set<std::string> blacklist;
    std::int64_t blacklist_fetched=0,blacklist_expires=0,next_blacklist_attempt=0;
    std::string blacklist_status="idle";
    bool load_blacklist=true;
    std::condition_variable wake;
    bool stopping=false;
    std::thread worker;
    void emit(Json event){std::function<void(Json)> callback;{std::lock_guard lock(mutex);callback=event_sink;}if(callback)try{callback(std::move(event));}catch(...){}}
    explicit Impl(AbuseTransport value,const std::filesystem::path& database):transport(value?std::move(value):native_transport),store(database) {
        worker=std::thread([this] {
            for (;;) {
                Json report;std::string task_key;std::uint64_t task_generation=0;
                {
                    std::unique_lock lock(mutex);wake.wait_for(lock,std::chrono::seconds(1),[&]{return stopping||load_blacklist||!reports.empty();});if(stopping)return;
                    task_key=key_for(config);task_generation=generation;
                    if(load_blacklist){load_blacklist=false;report={{"load_blacklist",true}};}
                    else if(config.at("enabled").get<bool>()&&config.at("auto_ban").get<bool>()&&config.at("blacklist_enabled").get<bool>()&&!task_key.empty()&&now_seconds()>=next_blacklist_attempt){report={{"scheduled_blacklist",true}};next_blacklist_attempt=now_seconds()+900;}
                    else if(!reports.empty()){report=std::move(reports.front());reports.pop_front();}
                    else continue;
                }
                if(report.contains("load_blacklist")) {
                    try {
                        const auto saved=store.snapshot(credential_id(task_key),true);std::set<std::string> entries;
                        bool valid=saved.at("cache_valid").get<bool>()&&saved.at("fetched_at").get<std::int64_t>()<=now_seconds()&&saved.at("fetched_at").get<std::int64_t>()+86400>now_seconds();
                        if(valid)for(const auto& row:saved.at("entries"))try{if(row.at("abuseConfidenceScore").is_number_integer()&&row.at("abuseConfidenceScore")==100)entries.insert(public_ip(row.at("ipAddress").get<std::string>()));else{valid=false;break;}}catch(...){valid=false;break;}if(!valid)entries.clear();
                        std::lock_guard lock(mutex);if(task_generation==generation){blacklist=std::move(entries);blacklist_fetched=valid?saved.at("fetched_at").get<std::int64_t>():0;blacklist_expires=blacklist_fetched?blacklist_fetched+86400:0;next_blacklist_attempt=std::max(blacklist_fetched+config.at("blacklist_refresh_seconds").get<int>(),(saved.at("attempted_at").get<std::int64_t>()<=now_seconds()?saved.at("attempted_at").get<std::int64_t>():0)+900);blacklist_status=blacklist_expires>now_seconds()?"up_to_date":"idle";}
                    }catch(...){std::lock_guard lock(mutex);blacklist_status="storage_unavailable";next_blacklist_attempt=now_seconds()+60;}
                    continue;
                }
                if(report.contains("scheduled_blacklist")) {
                    const auto result=perform("blacklist",{{"confidenceMinimum",100},{"limit",10000}},Clock::time_point::max(),false,task_key,true,true);
                    bool success=false;std::set<std::string> addresses;Json saved=Json::array();
                    if(result.value("ok",false)&&result.contains("data")&&result.at("data").is_array()&&result.at("data").size()<=10000){success=true;for(const auto& row:result.at("data"))try{const auto address=public_ip(row.at("ipAddress").get<std::string>());if(!row.at("abuseConfidenceScore").is_number_integer()||row.at("abuseConfidenceScore")!=100){success=false;break;}addresses.insert(address);saved.push_back({{"ipAddress",address},{"abuseConfidenceScore",100}});}catch(...){success=false;break;}}
                    {std::lock_guard lock(mutex);if(task_generation!=generation)success=false;}
                    if(success)try{store.save_blacklist(credential_id(task_key),saved);}catch(...){success=false;}
                    {std::lock_guard lock(mutex);if(task_generation==generation){if(success){blacklist=std::move(addresses);blacklist_fetched=now_seconds();blacklist_expires=blacklist_fetched+86400;next_blacklist_attempt=blacklist_fetched+config.at("blacklist_refresh_seconds").get<int>();blacklist_status="up_to_date";}else{blacklist_status=result.value("code",std::string("error"));next_blacklist_attempt=blacklist_status=="abuseipdb_daily_budget"||blacklist_status=="abuseipdb_headroom"?(now_seconds()/86400+1)*86400:now_seconds()+900;if(result.contains("quotas"))for(const auto& quota:result.at("quotas"))if(quota.at("endpoint")=="blacklist"&&quota.value("blocked_until",INT64_C(0))>now_seconds())next_blacklist_attempt=std::max(next_blacklist_attempt,quota.at("blocked_until").get<std::int64_t>());}}}
                    emit({{"kind","abuseipdb_blacklist"},{"reason","scheduled_blacklist_refresh"},{"outcome",success?"success":"error"},{"status",result.value("status",502)},{"cached_ips",success?saved.size():0}});continue;
                }
                if(report.contains("check_ip")) {
                    const auto address=report.at("check_ip").get<std::string>();
                    if(report.at("generation")!=task_generation)continue;
                    const auto result=perform("check",{{"ipAddress",address},{"maxAgeInDays",report.at("max_age_days")}},Clock::time_point::max(),false,task_key,true);
                    const auto data=reputation_data(result,address);
                    {std::lock_guard lock(mutex);if(report.at("generation")==generation) {
                        pending_checks.erase(address);
                        cache[address]={now_seconds()+(data?config.at("cache_seconds").get<int>():60),data};
                    }}
                    Json event={{"kind","abuseipdb_check"},{"ip",address},{"protocol",report.value("protocol",std::string{})},{"reason","automatic_reputation_check"},{"outcome",result.value("ok",false)?"success":"error"},{"status",result.value("status",502)}};if(data)event["score"]=data->at("abuseConfidenceScore");emit(std::move(event));
                    continue;
                }
                const auto protocol=report.value("protocol",std::string{});report.erase("protocol");
                const auto result=perform("report",report,Clock::time_point::max(),false,task_key,true);
                emit({{"kind","abuseipdb_report"},{"ip",report.at("ip")},{"protocol",protocol},{"reason","automatic_local_failures"},{"outcome",result.value("ok",false)?"success":"error"},{"status",result.value("status",502)}});
            }
        });
    }
    ~Impl() { {std::lock_guard lock(mutex);stopping=true;}wake.notify_all();if(worker.joinable())worker.join(); }
    Json quota_view() const {
        auto result=Json::array(); const auto now=now_seconds();
        for(const auto& endpoint:endpoints) {
            Json row={{"endpoint",endpoint},{"limit",nullptr},{"remaining",nullptr},{"used",nullptr},{"reset_at",nullptr},{"retry_after",nullptr},{"observed_at",nullptr},{"supported",endpoint!="bulk-check"}};
            if(endpoint=="bulk-check") row["mode"]="individual-check";
            if(quotas.contains(endpoint)) {
                row.update(quotas.at(endpoint));
                if(row.at("reset_at").is_number_integer() && row.at("reset_at").get<std::int64_t>()<=now) {row["remaining"]=nullptr;row["used"]=nullptr;row["retry_after"]=nullptr;}
            }
            result.push_back(std::move(row));
        }
        return result;
    }
    Json perform(const std::string& endpoint,const Json& input,Clock::time_point deadline=Clock::time_point::max(),bool quota_probe=false,const std::string& expected_key={},bool automated=false,bool scheduled=false) {
        automated=automated||quota_probe;
        if(quota_probe && endpoint!="check" && endpoint!="reports" && endpoint!="blacklist" && endpoint!="check-block")invalid("endpoint");
        if(endpoint=="bulk-check") {
            if(!input.is_object() || !input.contains("ips") || !input.at("ips").is_array() || input.at("ips").empty() || input.at("ips").size()>20) invalid("ips");
            for(const auto& [name,value]:input.items()){(void)value;if(name!="ips" && name!="maxAgeInDays")invalid(name);}
            const int days=integer(input,"maxAgeInDays",30,1,365); std::set<std::string> addresses;
            for(const auto& value:input.at("ips")){if(!value.is_string())invalid("ips");addresses.insert(public_ip(value.get<std::string>()));}
            auto results=Json::array(); bool skipped=false;std::size_t completed=0;
            deadline=std::min(deadline,Clock::now()+std::chrono::seconds(20));
            for(const auto& address:addresses) {
                if(skipped || Clock::now()>=deadline){results.push_back({{"ipAddress",address},{"ok",false},{"code","skipped"}});continue;}
                auto row=perform("check",{{"ipAddress",address},{"maxAgeInDays",days}},deadline);row["ipAddress"]=address;++completed;
                if(row.value("status",0)==429 || row.value("status",0)==503)skipped=true;
                results.push_back(std::move(row));
            }
            std::lock_guard lock(mutex);return {{"ok",true},{"endpoint",endpoint},{"mode","individual-check"},{"data",results},
                {"meta",{{"requested",addresses.size()},{"completed",completed},{"incomplete",completed<addresses.size()}}},{"quotas",quota_view()}};
        }
        const auto request=abuseipdb_request(endpoint,input);
        std::string key;int budget=1000000,interval=21600; {
            std::lock_guard lock(mutex);key=key_for(config);
            if((!quota_probe && !config.at("enabled").get<bool>()) || key.empty())return {{"ok",false},{"status",400},{"code","abuseipdb_not_configured"},{"error","Enable AbuseIPDB and configure an API key."}};
            if(!expected_key.empty() && key!=expected_key)return {{"ok",false},{"status",409},{"code","abuseipdb_settings_conflict"}};
            const std::string budget_field=endpoint=="check"?"automatic_check_budget":endpoint=="report"?"automatic_report_budget":endpoint=="blacklist"?"automatic_blacklist_budget":"";
            if(!budget_field.empty())budget=config.at(budget_field).get<int>();interval=config.at("blacklist_refresh_seconds").get<int>();
            const auto now=now_seconds();
            if(quotas.contains(endpoint)) {
                const auto& quota=quotas.at(endpoint);
                if(quota.value("blocked_until",INT64_C(0))>now)return {{"ok",false},{"status",429},{"code","abuseipdb_rate_limit"},{"error","AbuseIPDB quota is exhausted. Retry after the reset."},{"quotas",quota_view()}};
                const bool current=!quota.contains("reset_at")||quota.at("reset_at").is_null()||quota.at("reset_at").get<std::int64_t>()>now;
                if(automated&&current&&quota.at("remaining").is_number_integer()&&quota.at("limit").is_number_integer()) {
                    const auto remaining=quota.at("remaining").get<std::int64_t>(),limit=quota.at("limit").get<std::int64_t>(),reserve=std::max(INT64_C(1),(limit+4)/5);
                    if(remaining-pending_requests[endpoint]<=reserve)return {{"ok",false},{"status",429},{"code","abuseipdb_headroom"},{"error","Automatic AbuseIPDB requests stopped to preserve quota headroom."},{"quotas",quota_view()}};
                }
            }
            if(active>=2)return {{"ok",false},{"status",503},{"code","abuseipdb_busy"},{"error","AbuseIPDB requests are busy. Retry shortly."}};
            ++active;++pending_requests[endpoint];
        }
        std::string reservation;
        try {reservation=store.reserve(endpoint,budget,automated,scheduled,interval,credential_id(key));}catch(...){reservation="storage_unavailable";}
        if(!reservation.empty()) {
            std::lock_guard lock(mutex);--active;--pending_requests[endpoint];
            return {{"ok",false},{"status",reservation=="storage_unavailable"?503:429},{"code","abuseipdb_"+reservation},{"error",reservation=="storage_unavailable"?"AbuseIPDB daily usage storage is unavailable.":"Automatic AbuseIPDB request budget is exhausted or the next refresh is not due."},{"quotas",quota_view()}};
        }
        {std::lock_guard lock(mutex);if(key!=key_for(config)){--active;--pending_requests[endpoint];return {{"ok",false},{"status",409},{"code","abuseipdb_settings_conflict"}};}}
        AbuseHttpResponse response;
        try {response=transport(request,key,std::min(deadline,Clock::now()+std::chrono::seconds(4)));}
        catch(const std::exception&) {
            std::lock_guard lock(mutex);--active;--pending_requests[endpoint];
            return {{"ok",false},{"status",502},{"code","abuseipdb_unavailable"},{"error","Unable to reach AbuseIPDB over verified HTTPS."},{"quotas",quota_view()}};
        }
        std::lock_guard lock(mutex);--active;--pending_requests[endpoint];const auto now=now_seconds();
        if(key!=key_for(config))return {{"ok",false},{"status",409},{"code","abuseipdb_settings_conflict"},{"error","AbuseIPDB API key changed while the request was running."},{"quotas",quota_view()}};
        auto quota=Json{{"observed_at",now},{"limit",nullptr},{"remaining",nullptr},{"used",nullptr},{"reset_at",nullptr},{"retry_after",nullptr},{"blocked_until",0}};
        for(const auto& [header,field]:std::map<std::string,std::string>{{"x-ratelimit-limit","limit"},{"x-ratelimit-remaining","remaining"},{"x-ratelimit-reset","reset_at"},{"retry-after","retry_after"}}) {
            auto found=response.headers.find(header);if(found==response.headers.end())continue;
            try {const auto number=unsigned_text(found->second);if(number<=INT64_C(9007199254740991))quota[field]=number;}catch(const std::exception&){}
        }
        if(quota["limit"].is_number() && quota["remaining"].is_number() && quota["remaining"].get<std::uint64_t>()<=quota["limit"].get<std::uint64_t>())quota["used"]=quota["limit"].get<std::uint64_t>()-quota["remaining"].get<std::uint64_t>();
        if(response.status==429 || quota["remaining"]==0) {
            auto until=now+60;
            if(quota["reset_at"].is_number())until=std::max(until,quota["reset_at"].get<std::int64_t>());
            if(quota["retry_after"].is_number())until=std::max(until,now+quota["retry_after"].get<std::int64_t>());
            quota["blocked_until"]=until;
        }
        // An older in-flight success may finish after another request exhausted
        // the same endpoint. Preserve the active backoff instead of reopening it.
        if(quotas.contains(endpoint)) {
            const auto& previous=quotas.at(endpoint);
            const bool same_window=(quota.at("reset_at").is_number_integer()&&quota.at("reset_at")==previous.value("reset_at",Json())) ||
                (quota.at("reset_at").is_null()&&previous.value("reset_at",Json()).is_null()&&previous.value("observed_at",INT64_C(0))/86400==now/86400);
            if(same_window&&quota.at("remaining").is_number_integer()&&previous.value("remaining",Json()).is_number_integer()) {
                quota["remaining"]=std::min(quota.at("remaining").get<std::int64_t>(),previous.at("remaining").get<std::int64_t>());
                if(quota.at("limit").is_number_integer())quota["used"]=quota.at("limit").get<std::int64_t>()-quota.at("remaining").get<std::int64_t>();
            }
            if(previous.value("blocked_until",INT64_C(0))>now &&
                previous.value("blocked_until",INT64_C(0))>quota.at("blocked_until").get<std::int64_t>()) {
                quota=previous;
            }
        }
        quotas[endpoint]=std::move(quota);
        Json result{{"ok",response.status>=200 && response.status<300},{"endpoint",endpoint},{"status",response.status},{"quotas",quota_view()}};
        if(!result.at("ok").get<bool>()) {
            result["code"]=response.status==429?"abuseipdb_rate_limit":"abuseipdb_upstream_error";
            result["error"]=response.status==429?"AbuseIPDB quota is exhausted. Retry after the reset.":"AbuseIPDB rejected the request. Check the API key, subscription, and parameters.";
            return result;
        }
        try {
            if(response.body.size()>response_limit)throw std::runtime_error("response limit");
            const auto body=response.body.empty()?Json::object():Json::parse(response.body);
            if(!body.is_object() || !body.contains("data"))throw std::runtime_error("invalid data");
            result["data"]=body.at("data");if(body.contains("meta"))result["meta"]=body.at("meta");
        } catch(const std::exception&) {result["ok"]=false;result["status"]=502;result["code"]="abuseipdb_invalid_response";result["error"]="AbuseIPDB returned an invalid response.";}
        return result;
    }
};
AbuseIpDb::AbuseIpDb(AbuseTransport transport,const std::filesystem::path& database):impl_(std::make_unique<Impl>(std::move(transport),database)){}
AbuseIpDb::~AbuseIpDb()=default;
void AbuseIpDb::configure(const Json& settings) {
    const auto validated=validate_abuseipdb_settings(abuseipdb_defaults(),settings);
    std::lock_guard lock(impl_->mutex);
    if(key_for(validated)!=key_for(impl_->config)) {
        impl_->quotas=Json::object();
        impl_->quota_refresh={{"status","not_refreshed"},{"checked_at",nullptr},{"probes",Json::array()}};
    }
    impl_->config=validated;++impl_->generation;impl_->cache.clear();impl_->pending_checks.clear();impl_->reports.clear();impl_->blacklist.clear();impl_->blacklist_expires=0;impl_->blacklist_fetched=0;impl_->load_blacklist=true;impl_->wake.notify_one();
}
void AbuseIpDb::set_event_sink(std::function<void(Json)> sink){std::lock_guard lock(impl_->mutex);impl_->event_sink=std::move(sink);}
bool AbuseIpDb::blacklisted(const std::string& input)const {
    std::string address;try{address=public_ip(input);}catch(...){return false;}
    std::lock_guard lock(impl_->mutex);return impl_->config.at("enabled").get<bool>()&&impl_->config.at("auto_ban").get<bool>()&&impl_->config.at("blacklist_enabled").get<bool>()&&impl_->blacklist_expires>now_seconds()&&impl_->blacklist.contains(address);
}
Json AbuseIpDb::settings() const {std::lock_guard lock(impl_->mutex);return impl_->config;}
Json AbuseIpDb::view() const {
    Json state;try{state=impl_->store.snapshot();}catch(...){state={{"persistent",true},{"day",now_seconds()/86400},{"used",Json::object()},{"unavailable",true}};}
    std::lock_guard lock(impl_->mutex);auto settings=impl_->config;settings.erase("api_key");
    Json budgets=Json::object();for(const auto& endpoint:{"check","report","blacklist"}){const int limit=settings.at(std::string("automatic_")+endpoint+"_budget").get<int>();const auto used=state.at("used").value(endpoint,INT64_C(0));budgets[endpoint]={{"limit",limit},{"used",used},{"remaining",std::max(INT64_C(0),static_cast<std::int64_t>(limit)-used)}};}
    Json automation={{"persistent",state.at("persistent")},{"day",state.at("day")},{"storage_available",!state.value("unavailable",false)},{"budgets",budgets},{"blacklist",{{"enabled",settings.at("blacklist_enabled")},{"refresh_seconds",settings.at("blacklist_refresh_seconds")},{"last_refresh_at",impl_->blacklist_fetched?Json(impl_->blacklist_fetched):Json()},{"next_refresh_at",settings.at("enabled").get<bool>()&&settings.at("auto_ban").get<bool>()&&settings.at("blacklist_enabled").get<bool>()?Json(impl_->next_blacklist_attempt):Json()},{"expires_at",impl_->blacklist_expires?Json(impl_->blacklist_expires):Json()},{"cached_ips",impl_->blacklist_expires>now_seconds()?impl_->blacklist.size():0},{"status",impl_->blacklist_status}}}};
    return {{"ok",true},{"settings",settings},{"api_key_configured",!key_for(impl_->config).empty()},{"quotas",impl_->quota_view()},{"quota_refresh",impl_->quota_refresh},{"automation",automation},{"verification_path","/abuseipdb-verification.html"}};
}
Json AbuseIpDb::refresh_quotas(std::chrono::milliseconds budget) {
    std::string key;
    {
        std::lock_guard lock(impl_->mutex);key=key_for(impl_->config);
        if(key.empty())return {{"status","not_configured"},{"checked_at",nullptr},{"probes",Json::array()}};
        if(impl_->quota_refresh_keys.contains(key) || impl_->quota_refresh_keys.size()>=2)return {{"status","busy"},{"checked_at",nullptr},{"probes",Json::array()}};
        if(impl_->quota_refresh.at("checked_at").is_number_integer() && now_seconds()-impl_->quota_refresh.at("checked_at").get<std::int64_t>()<60) {
            auto result=impl_->quota_refresh;result["status"]="cooldown";return result;
        }
        impl_->quota_refresh_keys.insert(key);
    }
    // No account-wide quota endpoint exists. Use small documented GETs only;
    // report/bulk-report/clear-address stay unobserved until a real operation.
    Json refresh={{"status","failed"},{"checked_at",now_seconds()},{"probes",Json::array()},
        {"queried_endpoints",Json::array({"check","reports","blacklist","check-block"})}};
    const auto deadline=Clock::now()+std::clamp(budget,std::chrono::milliseconds(0),std::chrono::milliseconds(18000));
    std::size_t observed=0,busy=0;bool stop=false;
    try {
        for(const auto& [endpoint,input]:std::vector<std::pair<std::string,Json>>{
            {"check",{{"ipAddress","8.8.8.8"},{"maxAgeInDays",1}}},
            {"reports",{{"ipAddress","8.8.8.8"},{"maxAgeInDays",1},{"page",1},{"perPage",1}}},
            {"blacklist",{{"confidenceMinimum",100},{"limit",1}}},
            {"check-block",{{"network","8.8.8.8/32"},{"maxAgeInDays",1}}}}) {
            if(stop || Clock::now()>=deadline){refresh["probes"].push_back({{"endpoint",endpoint},{"ok",false},{"status",0},{"code","skipped"},{"capacity_observed",false}});continue;}
            const auto result=impl_->perform(endpoint,input,deadline,true,key);
            if(result.value("code",std::string{})=="abuseipdb_busy")++busy;
            bool capacity=false;
            if(result.contains("quotas"))for(const auto& row:result.at("quotas"))
                if(row.at("endpoint")==endpoint && row.at("limit").is_number() && row.at("observed_at").is_number_integer() &&
                    row.at("observed_at").get<std::int64_t>()>=refresh.at("checked_at").get<std::int64_t>())capacity=true;
            Json probe={{"endpoint",endpoint},{"ok",result.value("ok",false)},{"status",result.value("status",502)},{"capacity_observed",capacity}};
            if(result.contains("code"))probe["code"]=result.at("code");
            refresh["probes"].push_back(std::move(probe));if(capacity)++observed;
            stop=result.value("status",0)==401 || result.value("status",0)==409 || result.value("code",std::string{})=="abuseipdb_not_configured";
        }
        refresh["status"]=observed==4?"complete":observed?"partial":"failed";
    }catch(const std::exception&){refresh["status"]=observed?"partial":"failed";}
    std::lock_guard lock(impl_->mutex);impl_->quota_refresh_keys.erase(key);
    if(key!=key_for(impl_->config)){refresh["status"]="settings_changed";return refresh;}
    if(busy==4){refresh["status"]="busy";refresh["checked_at"]=nullptr;return refresh;}
    impl_->quota_refresh=refresh;return refresh;
}
Json AbuseIpDb::perform(const std::string& endpoint,const Json& input){return impl_->perform(endpoint,input);}
std::optional<Json> AbuseIpDb::reputation(const std::string& input,bool cached_only) {
    std::string address;try{address=public_ip(input);}catch(const std::exception&){return {};}
    Json config;const auto now=now_seconds();std::uint64_t generation=0;
    {std::lock_guard lock(impl_->mutex);config=impl_->config;
        if(!config.at("enabled").get<bool>() || !config.at("auto_ban").get<bool>())return {};
        if(const auto found=impl_->cache.find(address);found!=impl_->cache.end() && found->second.expires>now)return found->second.data;
        if(cached_only)return {};
        if(impl_->pending_checks.contains(address))return {};
        std::erase_if(impl_->cache,[&](const auto& row){return row.second.expires<=now;});
        if(impl_->cache.size()+impl_->pending_checks.size()>=10000)return {};
        impl_->pending_checks[address]=now;
        generation=impl_->generation;
    }
    const auto result=impl_->perform("check",{{"ipAddress",address},{"maxAgeInDays",config.at("max_age_days")}},Clock::time_point::max(),false,{},true);
    const auto data=reputation_data(result,address);
    {std::lock_guard lock(impl_->mutex);if(generation!=impl_->generation)return {};impl_->pending_checks.erase(address);impl_->cache[address]={now+(data?config.at("cache_seconds").get<int>():60),data};}
    return data;
}
void AbuseIpDb::observe_failures(const std::string& input,const std::string& protocol,int failures) {
    std::string address;try{address=public_ip(input);}catch(const std::exception&){return;}
    std::lock_guard lock(impl_->mutex);const auto& config=impl_->config;const auto now=now_seconds();
    if(!config.at("enabled").get<bool>() || key_for(config).empty())return;
    std::erase_if(impl_->cache,[&](const auto& row){return row.second.expires<=now;});
    if(config.at("auto_ban").get<bool>() && !impl_->cache.contains(address) && !impl_->pending_checks.contains(address) &&
        impl_->reports.size()<256 && impl_->cache.size()+impl_->pending_checks.size()<10000) {
        impl_->pending_checks[address]=now;
        impl_->reports.push_back({{"check_ip",address},{"max_age_days",config.at("max_age_days")},{"generation",impl_->generation},{"protocol",protocol}});
        impl_->wake.notify_one();
    }
    if(!config.at("auto_report").get<bool>() || failures<config.at("report_threshold").get<int>())return;
    if(const auto found=impl_->cooldowns.find(address);found!=impl_->cooldowns.end() && found->second>now)return;
    std::erase_if(impl_->cooldowns,[&](const auto& row){return row.second<=now;});
    if(impl_->reports.size()>=256 || impl_->cooldowns.size()>=10000)return;
    impl_->cooldowns[address]=now+config.at("report_cooldown_seconds").get<int>();
    impl_->reports.push_back({{"ip",address},{"categories",config.at("report_categories")},{"comment","PostPlus observed "+std::to_string(failures)+" failed authentication attempts within the local security observation window; latest protocol: "+protocol+". No account names or credentials included."},{"timestamp",utc_time()},{"protocol",protocol}});
    impl_->wake.notify_one();
}
}
