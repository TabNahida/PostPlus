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

namespace postplus {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::size_t response_limit = 8 * 1024 * 1024;
const std::vector<std::string> endpoints{"blacklist","bulk-report","bulk-check","check","check-block","clear-address","report","reports"};
std::int64_t now_seconds() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
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
    std::string wire = request.method + " /api/v2/" + request.target + " HTTP/1.1\r\nHost: api.abuseipdb.com\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nKey: " + key + "\r\nUser-Agent: PostPlus/1.2.0\r\nConnection: close\r\n";
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
        {"auto_ban",false},{"score_threshold",90},{"min_reports",3},{"ban_seconds",3600},{"max_age_days",30},{"cache_seconds",3600},
        {"auto_report",false},{"report_threshold",10},{"report_categories",Json::array({18})},{"report_cooldown_seconds",86400}};
}
Json validate_abuseipdb_settings(const Json& current, const Json& patch) {
    if (!patch.is_object()) invalid("settings");
    auto result = current; const auto defaults = abuseipdb_defaults();
    for (const auto& [name,value] : patch.items()) {
        if (name == "clear_api_key") { if (!value.is_boolean()) invalid(name); continue; }
        if (!defaults.contains(name)) invalid(name);
        if (name == "api_key" && value.is_string() && value.get<std::string>().empty()) continue;
        result[name] = value;
    }
    for (const auto* field : {"enabled","auto_ban","auto_report"}) if (!result.at(field).is_boolean()) invalid(field);
    const auto env_name = string_field(result,"api_key_env",128,false);
    if (env_name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != env_name.npos || (!env_name.empty() && env_name.front()>='0' && env_name.front()<='9')) invalid("api_key_env");
    const auto key = string_field(result,"api_key",512,false); if (!safe_key(key)) invalid("api_key");
    const auto token = string_field(result,"verification_token",256,false);
    if (!token.empty() && (!token.starts_with("abuseipdb-verification-") || token.size() <= std::string_view("abuseipdb-verification-").size() || token.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != token.npos)) invalid("verification_token");
    for (const auto& [name,range] : std::map<std::string,std::pair<int,int>>{{"score_threshold",{1,100}},{"min_reports",{1,1000000}},{"ban_seconds",{1,604800}},{"max_age_days",{1,365}},{"cache_seconds",{60,86400}},{"report_threshold",{2,10000}},{"report_cooldown_seconds",{900,604800}}})
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
    unsigned active=0;
    std::uint64_t generation=0;
    struct Cached { std::int64_t expires; std::optional<Json> data; };
    std::map<std::string,Cached> cache;
    std::map<std::string,std::int64_t> pending_checks, cooldowns;
    std::deque<Json> reports;
    std::condition_variable wake;
    bool stopping=false;
    std::thread worker;
    explicit Impl(AbuseTransport value):transport(value?std::move(value):native_transport) {
        worker=std::thread([this] {
            for (;;) {
                Json report;
                { std::unique_lock lock(mutex); wake.wait(lock,[&]{return stopping || !reports.empty();}); if(stopping) return; report=std::move(reports.front()); reports.pop_front(); }
                if(report.contains("check_ip")) {
                    const auto address=report.at("check_ip").get<std::string>();
                    const auto result=perform("check",{{"ipAddress",address},{"maxAgeInDays",report.at("max_age_days")}});
                    const auto data=reputation_data(result,address);
                    std::lock_guard lock(mutex);
                    if(report.at("generation")==generation) {
                        pending_checks.erase(address);
                        cache[address]={now_seconds()+(data?config.at("cache_seconds").get<int>():60),data};
                    }
                    continue;
                }
                const auto result=perform("report",report);
                log("auth",std::string("AbuseIPDB automatic report ")+(result.value("ok",false)?"submitted":"failed")+" ip="+report.at("ip").get<std::string>(),result.value("ok",false)?"info":"warn");
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
    Json perform(const std::string& endpoint,const Json& input,Clock::time_point deadline=Clock::time_point::max()) {
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
        std::string key; {
            std::lock_guard lock(mutex);key=key_for(config);
            if(!config.at("enabled").get<bool>() || key.empty())return {{"ok",false},{"status",400},{"code","abuseipdb_not_configured"},{"error","Enable AbuseIPDB and configure an API key."}};
            const auto now=now_seconds();
            if(quotas.contains(endpoint)) {
                const auto& quota=quotas.at(endpoint);
                if(quota.value("blocked_until",INT64_C(0))>now)return {{"ok",false},{"status",429},{"code","abuseipdb_rate_limit"},{"error","AbuseIPDB quota is exhausted. Retry after the reset."},{"quotas",quota_view()}};
            }
            if(active>=2)return {{"ok",false},{"status",503},{"code","abuseipdb_busy"},{"error","AbuseIPDB requests are busy. Retry shortly."}};
            ++active;
        }
        AbuseHttpResponse response;
        try {response=transport(request,key,std::min(deadline,Clock::now()+std::chrono::seconds(4)));}
        catch(const std::exception&) {
            std::lock_guard lock(mutex);--active;
            return {{"ok",false},{"status",502},{"code","abuseipdb_unavailable"},{"error","Unable to reach AbuseIPDB over verified HTTPS."},{"quotas",quota_view()}};
        }
        std::lock_guard lock(mutex);--active;const auto now=now_seconds();
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
AbuseIpDb::AbuseIpDb(AbuseTransport transport):impl_(std::make_unique<Impl>(std::move(transport))){}
AbuseIpDb::~AbuseIpDb()=default;
void AbuseIpDb::configure(const Json& settings) {
    const auto validated=validate_abuseipdb_settings(abuseipdb_defaults(),settings);
    std::lock_guard lock(impl_->mutex);
    if(key_for(validated)!=key_for(impl_->config))impl_->quotas=Json::object();
    impl_->config=validated;++impl_->generation;impl_->cache.clear();impl_->pending_checks.clear();impl_->reports.clear();
}
Json AbuseIpDb::settings() const {std::lock_guard lock(impl_->mutex);return impl_->config;}
Json AbuseIpDb::view() const {
    std::lock_guard lock(impl_->mutex);auto settings=impl_->config;settings.erase("api_key");
    return {{"ok",true},{"settings",settings},{"api_key_configured",!key_for(impl_->config).empty()},{"quotas",impl_->quota_view()},{"verification_path","/abuseipdb-verification.html"}};
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
    const auto result=impl_->perform("check",{{"ipAddress",address},{"maxAgeInDays",config.at("max_age_days")}});
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
        impl_->reports.push_back({{"check_ip",address},{"max_age_days",config.at("max_age_days")},{"generation",impl_->generation}});
        impl_->wake.notify_one();
    }
    if(!config.at("auto_report").get<bool>() || failures<config.at("report_threshold").get<int>())return;
    if(const auto found=impl_->cooldowns.find(address);found!=impl_->cooldowns.end() && found->second>now)return;
    std::erase_if(impl_->cooldowns,[&](const auto& row){return row.second<=now;});
    if(impl_->reports.size()>=256 || impl_->cooldowns.size()>=10000)return;
    impl_->cooldowns[address]=now+config.at("report_cooldown_seconds").get<int>();
    impl_->reports.push_back({{"ip",address},{"categories",config.at("report_categories")},{"comment","PostPlus observed "+std::to_string(failures)+" failed authentication attempts within the local security observation window; latest protocol: "+protocol+". No account names or credentials included."},{"timestamp",utc_time()}});
    impl_->wake.notify_one();
}
}
