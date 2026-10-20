#include <postplus/domains.hpp>
#include <postplus/settings.hpp>
#include <postplus/restart.hpp>
#include <postplus/dkim.hpp>
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <set>

namespace postplus {
namespace {
struct Snapshot {Config config;std::string raw,revision;};
std::string digest(std::string_view input) {
    std::array<unsigned char,EVP_MAX_MD_SIZE> bytes{};unsigned size=0;
    if(EVP_Digest(input.data(),input.size(),bytes.data(),&size,EVP_sha256(),nullptr)!=1) throw std::runtime_error("cannot calculate domain revision");
    std::string result;constexpr char alphabet[]="0123456789abcdef";
    for(unsigned index=0;index<size;++index){result+=alphabet[bytes[index]>>4];result+=alphabet[bytes[index]&15];}
    return result;
}
std::string read(const std::filesystem::path& path) {
    std::error_code error;const auto status=std::filesystem::symlink_status(path,error);
    if(error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status) || std::filesystem::file_size(path)>1048576)
        throw SettingsError("","Configuration must be a regular file no larger than 1 MiB.",409);
    std::ifstream file(path,std::ios::binary);if(!file)throw SettingsError("","Cannot read configuration file.",503);
    return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
}
std::int64_t now() {return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
Snapshot snapshot(const Config& running) {
    Snapshot result;
    if(running.source.empty()){result.config=running;result.raw=running.values.dump();}
    else {result.raw=read(running.source);result.config=Config::from_file(running.source);if(read(running.source)!=result.raw)throw SettingsError("","Configuration changed while it was read. Reload the page.",409);}
    result.revision=digest(result.raw);return result;
}
void fields(const Json& request,std::initializer_list<const char*> allowed) {
    if(!request.is_object())throw SettingsError("","Send a JSON object.");
    const std::set<std::string> names(allowed.begin(),allowed.end());
    for(const auto& item:request.items())if(!names.contains(item.key()))throw SettingsError(item.key(),"Unknown domain field: "+item.key()+".");
}
std::string domain_field(const Json& request,bool public_domain=true) {
    if(!request.contains("domain") || !request.at("domain").is_string())throw SettingsError("domain","Enter a mail domain.");
    const auto domain=lower(trim(request.at("domain").get<std::string>()));
    if(!valid_address("postmaster@"+domain) || (public_domain && !valid_public_dns_name(domain)))
        throw SettingsError("domain","Enter a public ASCII domain without a scheme, port or path that fits a mailbox address.");
    return domain;
}
void editable(const Config& running,const Snapshot& state,const Json& request) {
    if(running.source.empty())throw SettingsError("","A saved configuration file is required.",409);
    if(supervisor_restart_busy(running))throw SettingsError("","Wait for the service restart to finish before changing domains.",409);
    if(!request.contains("revision") || !request.at("revision").is_string())throw SettingsError("revision","Send the current configuration revision.");
    if(!secure_equal(request.at("revision").get<std::string>(),state.revision))throw SettingsError("revision","Configuration changed since it was opened. Reload before saving.",409);
}
Json registry(const Config& config) {
    Json result=config.values.value("domain_registry",Json::object());
    if(!result.is_object())throw SettingsError("domain_registry","Domain registry must be an object.",409);
    for(auto& item:result.items()) {
        if(!valid_address("postmaster@"+item.key()) || !item.value().is_object() ||
           (item.value().value("status",std::string{})!="pending" && item.value().value("status",std::string{})!="active"))
            throw SettingsError("domain_registry","The saved domain registry is invalid.",409);
    }
    for(const auto& domain:config.mail_domains()) {
        if(!result.contains(domain))result[domain]=Json::object();
        result[domain]["status"]="active";
    }
    return result;
}
Config candidate(Config config,const std::string& domain) {
    auto active=config.mail_domains();
    if(std::find(active.begin(),active.end(),domain)==active.end())active.push_back(domain);
    config.values["mail_domains"]=active;config.values.erase("additional_domains");return config;
}
Json dns_input(const Json& request,const std::string& domain) {
    Json input=request.value("dns",Json::object());
    if(!input.is_object() || input.contains("domain"))throw SettingsError("dns","DNS expectations must be an object without a domain field.");
    input["domain"]=domain;return input;
}
std::string dns_fingerprint(const Config& config,const std::string& domain,const Json& input) {
    const auto guide=dns_recommendations(candidate(config,domain),input);
    return digest(Json{{"expected",guide.at("expected")},{"outbound_mode",config.outbound_mode()}}.dump());
}
bool can_activate(const Config& config,const std::string& domain,const Json& item) {
    if(!item.contains("dns") || !item.at("dns").is_object())return false;
    const auto& evidence=item.at("dns");
    if(!evidence.value("ready",false) || !evidence.contains("checked_epoch") || !evidence.at("checked_epoch").is_number_integer())return false;
    const auto age=now()-evidence.at("checked_epoch").get<std::int64_t>();if(age<0 || age>86400)return false;
    try {return secure_equal(evidence.value("fingerprint",std::string{}),dns_fingerprint(config,domain,item.value("dns_input",Json{{"domain",domain}})));}
    catch(const std::exception&){return false;}
}
Json record(const Config& config,const std::string& domain,const Json& item) {
    const bool primary=domain==config.text("domain","localhost");
    const auto dns=item.value("dns",Json::object());
    Json result={{"domain",domain},{"primary",primary},{"status",config.hosts_domain(domain)?"active":"pending"},
        {"dns_status",dns.value("status",std::string("unchecked"))},{"checked_at",dns.value("checked_at",std::string{})},
        {"can_activate",!config.hosts_domain(domain) && can_activate(config,domain,item)},{"can_remove",!primary}};
    auto expectations=item.value("dns_input",Json::object());expectations.erase("domain");result["dns"]=std::move(expectations);
    return result;
}
void store(Snapshot& state,const Json& entries) {
    // Older active installations remain active. Pending entries only live in
    // the registry; all mail protocols read the canonical active domain array.
    state.config.values["mail_domains"]=state.config.mail_domains();
    state.config.values.erase("additional_domains");
    state.config.values["domain_registry"]=entries;
    replace_config_file(state.config.source,state.raw,state.config.values.dump(2)+"\n");
}
Json response(const Config& running,const Config& saved,const std::string& domain,const Json& item) {
    const auto active=supervisor_running_config(running).value_or(running);
    return {{"ok",true},{"revision",digest(saved.values.dump(2)+"\n")},{"record",record(saved,domain,item)},
        {"restart_required",!restart_plan(active,saved,"changed").empty()}};
}
}

Json domains_list(const Config& running,const Json& query) {
    fields(query,{"q","offset","limit"});
    if(query.contains("q") && (!query.at("q").is_string() || query.at("q").get<std::string>().size()>253))throw SettingsError("q","Search must be at most 253 characters.");
    for(const auto* key:{"offset","limit"})if(query.contains(key) && !query.at(key).is_number_integer())throw SettingsError(key,"Pagination values must be whole numbers.");
    const auto offset=query.value("offset",std::int64_t(0)),limit=query.value("limit",std::int64_t(25));
    if(offset<0 || limit<1 || limit>200)throw SettingsError("limit","Use an offset of zero or greater and a page size from 1 to 200.");
    const auto state=snapshot(running);const auto entries=registry(state.config);const auto search=lower(trim(query.value("q",std::string{})));
    Json items=Json::array();std::int64_t matched=0;
    // Primary first; remaining domains sort lexicographically for stable pages.
    auto append=[&](const std::string& name,const Json& item){if(!search.empty() && name.find(search)==std::string::npos)return;
        if(matched>=offset && matched-offset<limit)items.push_back(record(state.config,name,item));++matched;};
    const auto primary=state.config.text("domain","localhost");append(primary,entries.at(primary));
    for(const auto& item:entries.items())if(item.key()!=primary)append(item.key(),item.value());
    const auto active=supervisor_running_config(running).value_or(running);
    return {{"ok",true},{"revision",state.revision},{"items",items},{"total",matched},{"total_domains",entries.size()},
        {"active_count",state.config.mail_domains().size()},{"offset",offset},{"limit",limit},
        {"restart_required",!restart_plan(active,state.config,"changed").empty()}};
}
Json domains_add(const Config& running,const Json& request) {
    fields(request,{"revision","domain"});const auto domain=domain_field(request);auto state=snapshot(running);editable(running,state,request);
    auto entries=registry(state.config);if(entries.contains(domain))throw SettingsError("domain","This domain has already been added.",409);
    entries[domain]={{"status","pending"}};store(state,entries);
    log("admin","administrator added pending mail domain "+domain);return response(running,state.config,domain,entries.at(domain));
}
Json domains_preview(const Config& running,const Json& request) {
    fields(request,{"domain","dns"});const auto domain=domain_field(request);const auto state=snapshot(running);
    return dns_recommendations(candidate(state.config,domain),dns_input(request,domain));
}
Json domains_check(const Config& running,const Json& request,DnsOptions options) {
    fields(request,{"revision","domain","dns"});const auto domain=domain_field(request);auto state=snapshot(running);editable(running,state,request);
    auto entries=registry(state.config);if(!entries.contains(domain))throw SettingsError("domain","Add this domain before saving its DNS check.",404);
    const auto input=dns_input(request,domain);auto checked=DnsChecker(std::move(options)).check_server(candidate(state.config,domain),input);
    bool mx=false,address=false,warnings=false;
    for(const auto& item:checked.at("records")) {
        const auto id=item.at("id").get<std::string>(),status=item.value("status",std::string{});
        if(id=="mx")mx=status=="matched";
        if((id=="a" || id=="aaaa") && (status=="matched" || status=="published"))address=true;
        if(item.value("required",false) && status!="matched" && status!="published" && id!="a")warnings=true;
    }
    const bool ready=mx && address;
    entries[domain]["dns_input"]=input;
    entries[domain]["dns"]={{"ready",ready},{"status",ready?(warnings?"warnings":"verified"):"incomplete"},
        {"checked_at",checked.at("checked_at")},{"checked_epoch",now()},{"fingerprint",dns_fingerprint(state.config,domain,input)}};
    store(state,entries);auto result=response(running,state.config,domain,entries.at(domain));result["dns"]=std::move(checked);return result;
}
Json domains_activate(const Config& running,const Json& request) {
    fields(request,{"revision","domain"});const auto domain=domain_field(request);auto state=snapshot(running);editable(running,state,request);
    auto entries=registry(state.config);if(!entries.contains(domain))throw SettingsError("domain","Add this domain first.",404);
    if(state.config.hosts_domain(domain))throw SettingsError("domain","This domain is already active.",409);
    if(!can_activate(state.config,domain,entries.at(domain)))throw SettingsError("domain","Check DNS first: MX must point to this mail server and its hostname must publish a public address. Checks expire after 24 hours or a relevant settings change.",409);
    if((state.config.outbound_mode()=="direct" || !state.config.text("dkim_private_key").empty()) &&
       !valid_dkim_record_name(domain,state.config.text("dkim_selector","postplus")))
        throw SettingsError("domain","This domain is too long for the configured DKIM selector.");
    state.config=candidate(state.config,domain);entries[domain]["status"]="active";store(state,entries);
    log("admin","administrator activated mail domain "+domain);return response(running,state.config,domain,entries.at(domain));
}
Json domains_remove(const Config& running,const Json& request) {
    // Legacy configurations may host private names such as example.test.
    // Removing an existing entry does not require public DNS eligibility.
    fields(request,{"revision","domain"});const auto domain=domain_field(request,false);auto state=snapshot(running);editable(running,state,request);
    if(domain==state.config.text("domain","localhost"))throw SettingsError("domain","The first mail domain cannot be removed.",409);
    auto entries=registry(state.config);if(!entries.contains(domain))throw SettingsError("domain","This domain was not found.",404);
    entries.erase(domain);auto domains=state.config.mail_domains();domains.erase(std::remove(domains.begin(),domains.end(),domain),domains.end());state.config.values["mail_domains"]=domains;
    store(state,entries);const auto active=supervisor_running_config(running).value_or(running);
    log("admin","administrator removed mail domain "+domain);
    return {{"ok",true},{"revision",digest(state.config.values.dump(2)+"\n")},{"restart_required",!restart_plan(active,state.config,"changed").empty()},
        {"accounts_retained",true}};
}
}
