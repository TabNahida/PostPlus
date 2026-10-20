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
std::string webmail_hostname(const Config& config,std::string_view domain) {
    const auto name=lower(trim(std::string(domain)));
    const auto found=config.values.find("webmail_hostnames");
    if(found!=config.values.end() && found->is_object()) {
        const auto host=found->find(name);
        if(host!=found->end() && host->is_string() && !host->get_ref<const std::string&>().empty())return lower(trim(host->get<std::string>()));
    }
    return name;
}
std::string portal_domain(const Config& config,std::string_view hostname) {
    const auto host=lower(trim(std::string(hostname)));std::string result;
    for(const auto& domain:config.mail_domains())if(webmail_hostname(config,domain)==host) {
        // Malformed in-memory configurations must not make an ambiguous host
        // authenticate as whichever domain happened to be listed first.
        if(!result.empty())return {};result=domain;
    }
    return result;
}
void validate_webmail_hostnames(const Config& config) {
    const auto found=config.values.find("webmail_hostnames");
    if(found==config.values.end())return;
    if(!found->is_object())throw SettingsError("webmail_hostnames","Webmail hostname bindings must be an object.");
    const auto active=config.mail_domains();std::set<std::string> domains(active.begin(),active.end());
    const auto entries=config.values.find("domain_registry");
    if(entries!=config.values.end() && entries->is_object())for(const auto& item:entries->items())
        if(item.value().is_object() && item.value().value("status",std::string{})=="pending")domains.insert(item.key());
    for(const auto& item:found->items()) {
        if(!domains.contains(item.key()) || item.key()!=lower(trim(item.key())))
            throw SettingsError("webmail_hostnames","Bind Webmail hostnames only to existing mail domains.");
        if(!item.value().is_string())throw SettingsError("webmail_hostnames","Each Webmail hostname must be text.");
        const auto host=item.value().get<std::string>();
        if(host!=lower(trim(host)) || !valid_address("postmaster@"+host))
            throw SettingsError("webmail_hostnames","Enter a valid lowercase ASCII Webmail hostname without a scheme, port or path.");
    }
    std::set<std::string> hosts;
    for(const auto& domain:domains)if(!hosts.insert(webmail_hostname(config,domain)).second)
        throw SettingsError("webmail_hostname","Each mail domain needs a different Webmail hostname. This hostname is already assigned to another domain.",409);
}
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
    return digest(Json{{"expected",guide.at("expected")},{"outbound_mode",config.outbound_mode()},
        {"webmail_hostname",webmail_hostname(config,domain)}}.dump());
}
void portal_dns(Json& result,const Config& config,const std::string& domain,const DnsOptions* options=nullptr,
                std::chrono::steady_clock::time_point deadline={}) {
    struct Portal {std::string hostname,purpose;};std::vector<Portal> portals;
    std::set<std::string> included{config.mail_hostname()};
    const auto append=[&](std::string hostname,const std::string& purpose) {
        hostname=lower(trim(std::move(hostname)));
        if(!hostname.empty() && included.insert(hostname).second)portals.push_back({std::move(hostname),purpose});
    };
    result["webmail_hostname"]=webmail_hostname(config,domain);append(webmail_hostname(config,domain),"webmail");
    const bool primary=domain==config.text("domain","localhost");
    for(const auto& item:{std::pair{"admin_hostname","admin"},std::pair{"webmail_shared_hostname","shared-webmail"}}) {
        const auto hostname=lower(trim(config.text(item.first)));
        if(primary || hostname==domain || hostname.ends_with("."+domain))append(hostname,item.second);
    }
    for(const auto& portal:portals)for(const auto& pair:{std::pair{"ipv4",DnsType::a},std::pair{"ipv6",DnsType::aaaa}}) {
        const auto& hostname=portal.hostname;
        const bool ipv4=pair.second==DnsType::a;const auto value=result.at("expected").at(pair.first).get<std::string>();
        const auto owner=hostname==domain?"@":hostname.ends_with("."+domain)?hostname.substr(0,hostname.size()-domain.size()-1):hostname;
        Json item={{"id",portal.purpose+(ipv4?"-a":"-aaaa")},{"name",hostname},{"host",owner},{"type",ipv4?"A":"AAAA"},
            {"value",value},{"purpose",portal.purpose},{"required",false},{"expected",value.empty()?Json::array():Json::array({value})},
            {"observed",Json::array()},{"status",value.empty()?"not_configured":"unchecked"},
            {"message","Point this portal hostname to this service or its HTTPS reverse proxy. This record does not change the mail server MX hostname."}};
        if(options)try {
            const auto lookup=DnsResolver(*options).lookup(hostname,pair.second,deadline);item["observed"]=lookup.values;
            bool matched=!lookup.values.empty(),public_only=true;
            for(const auto& observed:lookup.values) {
                std::error_code error;const auto address=asio::ip::make_address(observed,error);
                public_only=public_only && !error && is_public_mail_address(address);
                matched=matched && (value.empty() || observed==value);
            }
            item["status"]=lookup.values.empty()?(ipv4 || !value.empty()?"missing":"skipped"):!public_only?"mismatch":matched?(value.empty()?"published":"matched"):"mismatch";
            item["code"]=!public_only?"dns_private_address":lookup.values.empty()?"dns_missing":matched?(value.empty()?"dns_published":"dns_matched"):"dns_mismatch";
        }catch(const DnsError& error){item["status"]="error";item["code"]=error.code;}
        catch(const std::exception&){item["status"]="error";item["code"]="dns_unavailable";}
        result["records"].push_back(std::move(item));
    }
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
        {"webmail_hostname",webmail_hostname(config,domain)},{"webmail_hostname_overridden",webmail_hostname(config,domain)!=domain},
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
    validate_webmail_hostnames(state.config);
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
Json domains_update(const Config& running,const Json& request) {
    fields(request,{"revision","domain","webmail_hostname"});const auto domain=domain_field(request,false);
    if(!request.contains("webmail_hostname") || !request.at("webmail_hostname").is_string())
        throw SettingsError("webmail_hostname","Enter a Webmail hostname or leave it empty to use the mail domain.");
    const auto hostname=lower(trim(request.at("webmail_hostname").get<std::string>()));
    if(!hostname.empty() && (!valid_public_dns_name(hostname) || !valid_address("postmaster@"+hostname)))
        throw SettingsError("webmail_hostname","Enter a public ASCII hostname without a scheme, port or path.");
    auto state=snapshot(running);editable(running,state,request);const auto entries=registry(state.config);
    if(!entries.contains(domain))throw SettingsError("domain","Add this mail domain before binding its Webmail hostname.",404);
    auto bindings=state.config.values.value("webmail_hostnames",Json::object());
    if(!bindings.is_object())throw SettingsError("webmail_hostnames","Webmail hostname bindings must be an object.",409);
    if(hostname.empty() || hostname==domain)bindings.erase(domain);else bindings[domain]=hostname;
    if(bindings.empty())state.config.values.erase("webmail_hostnames");else state.config.values["webmail_hostnames"]=std::move(bindings);
    store(state,entries);
    log("admin","administrator updated Webmail hostname for "+domain);return response(running,state.config,domain,entries.at(domain));
}
Json domains_preview(const Config& running,const Json& request) {
    fields(request,{"domain","dns"});const auto domain=domain_field(request);const auto state=snapshot(running);
    auto result=dns_recommendations(candidate(state.config,domain),dns_input(request,domain));portal_dns(result,state.config,domain);return result;
}
Json domains_check(const Config& running,const Json& request,DnsOptions options) {
    fields(request,{"revision","domain","dns"});const auto domain=domain_field(request);auto state=snapshot(running);editable(running,state,request);
    auto entries=registry(state.config);if(!entries.contains(domain))throw SettingsError("domain","Add this domain before saving its DNS check.",404);
    const auto input=dns_input(request,domain);const auto deadline=std::chrono::steady_clock::now()+options.timeout;
    auto checked=DnsChecker(options).check_server(candidate(state.config,domain),input);portal_dns(checked,state.config,domain,&options,deadline);
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
    if(state.config.values.contains("webmail_hostnames")) {
        state.config.values["webmail_hostnames"].erase(domain);
        if(state.config.values["webmail_hostnames"].empty())state.config.values.erase("webmail_hostnames");
    }
    store(state,entries);const auto active=supervisor_running_config(running).value_or(running);
    log("admin","administrator removed mail domain "+domain);
    return {{"ok",true},{"revision",digest(state.config.values.dump(2)+"\n")},{"restart_required",!restart_plan(active,state.config,"changed").empty()},
        {"accounts_retained",true}};
}
}
