#include <postplus/domains.hpp>
#include <postplus/settings.hpp>
#include <postplus/restart.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace postplus;
namespace {
using Bytes=std::vector<unsigned char>;
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F>void rejects(int status,F call){try{call();}catch(const SettingsError& error){check(error.status==status,"unexpected domain HTTP status");return;}throw std::runtime_error("invalid domain operation accepted");}
void save(const std::filesystem::path& path,const Json& value){std::ofstream file(path,std::ios::binary|std::ios::trunc);file<<value.dump(2)<<'\n';check(file.good(),"cannot write domain fixture");}
void number(Bytes& data,unsigned value){data.push_back(static_cast<unsigned char>(value>>8));data.push_back(static_cast<unsigned char>(value));}
void name(Bytes& data,const std::string& value){std::size_t offset=0;while(offset<value.size()){auto end=value.find('.',offset);if(end==std::string::npos)end=value.size();data.push_back(static_cast<unsigned char>(end-offset));data.insert(data.end(),value.begin()+offset,value.begin()+end);offset=end+1;}data.push_back(0);}
struct Fixture {
    bool matching=true,public_address=true,policies=true,portal_public=true;unsigned calls=0;std::string portal_host;
    DnsOptions options(){DnsOptions options;options.connect=[](const auto&,int,auto){return false;};
        options.transport=[this](const Bytes& wire,auto){
            ++calls;std::size_t position=12;std::string owner;
            while(wire.at(position)){const auto length=wire.at(position++);if(!owner.empty())owner+='.';owner.append(reinterpret_cast<const char*>(wire.data()+position),length);position+=length;}
            ++position;const unsigned type=(wire.at(position)<<8)|wire.at(position+1);position+=4;Bytes data;
            if(type==1 && owner=="mail.example.com")data=public_address?Bytes{93,184,216,34}:Bytes{127,0,0,1};
            if(type==1 && owner==portal_host)data=portal_public?Bytes{93,184,216,35}:Bytes{127,0,0,1};
            if(type==15){number(data,10);name(data,matching?"mail.example.com":"other.example.com");}
            if(type==16 && policies){const std::string text=owner.starts_with("_dmarc.")?"v=DMARC1; p=none":"v=spf1 -all";data.push_back(static_cast<unsigned char>(text.size()));data.insert(data.end(),text.begin(),text.end());}
            Bytes result{wire[0],wire[1]};number(result,0x8180);number(result,1);number(result,data.empty()?0:1);number(result,0);number(result,0);result.insert(result.end(),wire.begin()+12,wire.begin()+position);
            if(!data.empty()){number(result,0xc00c);number(result,type);number(result,1);result.insert(result.end(),{0,0,0,60});number(result,static_cast<unsigned>(data.size()));result.insert(result.end(),data.begin(),data.end());}return result;
        };return options;}
};
}
int main(){try {
    // DKIM rejects symlinks in every parent component. macOS temporary paths
    // can contain /var -> /private/var, so use a real workspace path as in the
    // dedicated DKIM suite and resolve it before writing fixture paths.
    const auto fixture_directory=std::filesystem::current_path()/"build"/("postplus-domains-"+random_hex(10));
    std::filesystem::create_directories(fixture_directory);
    const auto directory=std::filesystem::canonical(fixture_directory);
    const auto path=directory/"config.json",secret=directory/"token";{std::ofstream file(secret);file<<std::string(64,'a');}
    Json values={{"domain"," Example.COM "},{"mail_hostname","mail.example.com"},{"allow_insecure_auth",true},
        {"outbound_mode","disabled"},{"data_dir",directory.string()},{"service_token_file",secret.string()},{"additional_domains",Json::array()}};
    for(int index=0;index<150;++index)values["additional_domains"].push_back("domain"+std::to_string(index)+".example.net");save(path,values);
    auto private_legacy=values;private_legacy["additional_domains"].push_back("legacy.example.test");save(path,private_legacy);
    const auto private_config=Config::from_file(path);const auto private_listing=domains_list(private_config);
    const auto private_removed=domains_remove(private_config,{{"revision",private_listing.at("revision")},{"domain"," LEGACY.EXAMPLE.TEST "}});
    const auto private_saved=Config::from_file(path);
    check(private_removed.at("accounts_retained").get<bool>() && !private_saved.hosts_domain("legacy.example.test") &&
        private_saved.values.contains("mail_domains") && !private_saved.values.contains("additional_domains"),"legacy private domains must migrate and remain removable");
    rejects(404,[&]{domains_remove(private_config,{{"revision",private_removed.at("revision")},{"domain","unknown.example.test"}});});
    rejects(400,[&]{domains_add(private_config,{{"revision",private_removed.at("revision")},{"domain","new.example.test"}});});
    save(path,values);
    auto config=Config::from_file(path);check(config.mail_domains().size()==151,"more than 50 legacy domains rejected");
    auto listing=domains_list(config,{{"limit",200}});check(listing.at("total")==151 && listing.at("items").size()==151,"domain list truncated at legacy cap");
    check(listing.at("items").at(0).at("primary")==true,"first domain must remain primary");
    check(domains_list(config,{{"offset",140},{"limit",25}}).at("items").size()==11,"domain pagination is incorrect");
    check(domains_list(config,{{"q","DOMAIN14"}}).at("total")==11,"domain search must normalize case");
    check(webmail_hostname(config," EXAMPLE.COM ")=="example.com" && portal_domain(config," EXAMPLE.COM ")=="example.com",
        "unbound Webmail hostname must default to the mailbox domain");
    check(listing.at("items").at(0).at("webmail_hostname")=="example.com" && !listing.at("items").at(0).at("webmail_hostname_overridden").get<bool>(),
        "domain listing must describe the effective Webmail hostname");
    auto bound=domains_update(config,{{"revision",listing.at("revision")},{"domain","example.com"},{"webmail_hostname"," MAIL.EXAMPLE.COM "}});
    auto mapped=Config::from_file(path);
    check(mapped.values.at("webmail_hostnames").at("example.com")=="mail.example.com" &&
        webmail_hostname(mapped,"example.com")=="mail.example.com" && portal_domain(mapped,"mail.example.com")=="example.com" &&
        portal_domain(mapped,"example.com").empty(),"a mail domain must move its Webmail login to its bound hostname");
    check(bound.at("record").at("webmail_hostname_overridden").get<bool>(),"domain binding response must mark custom hostname");
    auto portal_config=mapped;portal_config.source.clear();portal_config.values["admin_hostname"]="admin.example.com";
    portal_config.values["webmail_shared_hostname"]="login.domain0.example.net";
    const auto portal_records=domains_preview(portal_config,{{"domain","example.com"}}).at("records");
    unsigned admin_records=0,shared_records=0,bound_records=0;
    for(const auto& item:portal_records) {
        const auto id=item.at("id").get<std::string>();
        if(id.starts_with("admin-")){++admin_records;check(item.at("name")=="admin.example.com" && !item.at("required").get<bool>(),"administration DNS must remain advisory");}
        if(id.starts_with("shared-webmail-")){++shared_records;check(item.at("name")=="login.domain0.example.net" && !item.at("required").get<bool>(),"shared Webmail DNS must remain advisory");}
        if(id.starts_with("webmail-"))++bound_records;
    }
    check(admin_records==2 && shared_records==2 && bound_records==0,"primary domain must show all portal DNS while deduplicating the mail hostname");
    const auto matching_records=domains_preview(portal_config,{{"domain","domain0.example.net"}}).at("records");
    unsigned matching_shared=0;for(const auto& item:matching_records)
        if(item.at("id").get<std::string>().starts_with("shared-webmail-"))++matching_shared;
    check(matching_shared==2,"shared portal DNS must also appear for its matching hosted domain");
    portal_config.values["admin_hostname"]="mail.example.com";portal_config.values["webmail_shared_hostname"]="mail.example.com";
    const auto duplicate_records=domains_preview(portal_config,{{"domain","example.com"}}).at("records");
    for(const auto& item:duplicate_records)
        check(!item.contains("purpose"),"mail, Webmail, administration and shared hostnames must not create duplicate address records");
    rejects(400,[&]{domains_update(config,{{"revision",bound.at("revision")},{"domain","example.com"},{"webmail_hostname","https://mail.example.com"}});});
    rejects(400,[&]{domains_update(config,{{"revision",bound.at("revision")},{"domain","example.com"},{"webmail_hostname",false}});});
    rejects(409,[&]{domains_update(config,{{"revision",listing.at("revision")},{"domain","example.com"},{"webmail_hostname",""}});});
    rejects(409,[&]{domains_update(config,{{"revision",bound.at("revision")},{"domain","example.com"},{"webmail_hostname","domain0.example.net"}});});
    rejects(409,[&]{domains_update(config,{{"revision",bound.at("revision")},{"domain","domain0.example.net"},{"webmail_hostname","mail.example.com"}});});
    rejects(409,[&]{domains_add(config,{{"revision",bound.at("revision")},{"domain","mail.example.com"}});});
    rejects(404,[&]{domains_update(config,{{"revision",bound.at("revision")},{"domain","missing.example.net"},{"webmail_hostname","login.example.net"}});});
    check(domains_list(config).at("revision")==bound.at("revision"),"invalid binding must leave the saved configuration intact");
    auto malformed=mapped;malformed.values["webmail_hostnames"]["domain0.example.net"]="mail.example.com";
    rejects(409,[&]{validate_webmail_hostnames(malformed);});
    check(portal_domain(malformed,"mail.example.com").empty(),"ambiguous in-memory hostname must fail closed");
    malformed=mapped;malformed.values["webmail_hostnames"]={{"missing.example.net","webmail.example.net"}};
    rejects(400,[&]{validate_webmail_hostnames(malformed);});
    malformed=mapped;malformed.values["webmail_hostnames"]=Json::array();rejects(400,[&]{validate_webmail_hostnames(malformed);});
    bound=domains_update(config,{{"revision",bound.at("revision")},{"domain","example.com"},{"webmail_hostname",""}});
    mapped=Config::from_file(path);check(webmail_hostname(mapped,"example.com")=="example.com" && !mapped.values.contains("webmail_hostnames"),"empty binding must restore the domain hostname");
    listing=domains_list(config,{{"limit",200}});
    rejects(400,[&]{domains_list(config,{{"limit",201}});});rejects(400,[&]{domains_add(config,{{"revision",listing.at("revision")},{"domain","https://invalid.example.com"}});});
    // DNS permits a 253-byte name, but every hosted domain must also fit a
    // complete mailbox address. Reject it before persisting a broken draft.
    const auto too_long=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(61,'d');
    check(too_long.size()==253 && valid_public_dns_name(too_long),"long-domain fixture must be valid DNS");
    rejects(400,[&]{domains_add(config,{{"revision",listing.at("revision")},{"domain",too_long}});});
    rejects(400,[&]{domains_preview(config,{{"domain",too_long}});});
    check(domains_list(config).at("revision")==listing.at("revision"),"invalid long domain must not change configuration");
    auto manual=domains_mark_checked(config,{{"revision",listing.at("revision")},{"domain","example.com"}});
    check(manual.at("record").at("dns_status")=="manual_checked" && manual.at("record").at("checked_manually")==true && !manual.at("restart_required").get<bool>(),"manual acknowledgement must persist without restarting services");
    listing=domains_list(config,{{"limit",200}});
    check(listing.at("items").at(0).at("dns_status")=="manual_checked" && !listing.at("items").at(0).at("checked_at").get<std::string>().empty(),"manual acknowledgement must survive reload");
    auto manual_settings=Config::from_file(path);const auto manual_original=manual_settings.values;
    manual_settings.values["mail_hostname"]="changed.example.com";save(path,manual_settings.values);
    check(domains_list(config).at("items").at(0).at("dns_status")=="stale","changing the expected mail hostname must invalidate manual acknowledgement");
    save(path,manual_original);listing=domains_list(config,{{"limit",200}});
    rejects(404,[&]{domains_mark_checked(config,{{"revision",listing.at("revision")},{"domain","missing.example.net"}});});
    rejects(400,[&]{domains_mark_checked(config,{{"revision",listing.at("revision")},{"domain","example.com"},{"ready",true}});});
    auto added=domains_add(config,{{"revision",listing.at("revision")},{"domain"," New.Example.NET "}});
    check(added.at("record").at("status")=="pending" && !added.at("restart_required").get<bool>(),"pending add must not change running routing");
    const auto pending=Config::from_file(path);check(!pending.hosts_domain("new.example.net") && pending.values.contains("mail_domains") && !pending.values.contains("additional_domains"),"pending add must migrate legacy domains without activating draft");
    rejects(409,[&]{domains_add(config,{{"revision",listing.at("revision")},{"domain","later.example.net"}});});
    rejects(409,[&]{domains_activate(config,{{"revision",added.at("revision")},{"domain","new.example.net"}});});
    manual=domains_mark_checked(config,{{"revision",added.at("revision")},{"domain","new.example.net"}});
    check(manual.at("record").at("can_activate")==true && manual.at("record").at("status")=="pending","manual acknowledgement must allow explicit activation without automatically enabling mail");
    rejects(409,[&]{domains_mark_checked(config,{{"revision",added.at("revision")},{"domain","new.example.net"}});});
    added["revision"]=manual.at("revision");
    const auto guide=domains_preview(config,{{"domain","preview.example.org"}});check(guide.at("domain")=="preview.example.org" && guide.at("hostname")=="mail.example.com","unsaved DNS preview must retain configured server hostname");
    Fixture fixture;fixture.matching=false;
    auto checked=domains_check(config,{{"revision",added.at("revision")},{"domain","new.example.net"}},fixture.options());
    check(!checked.at("record").at("can_activate").get<bool>() && checked.at("record").at("dns_status")=="incomplete","incorrect MX cannot activate");
    fixture.matching=true;fixture.public_address=false;
    checked=domains_check(config,{{"revision",checked.at("revision")},{"domain","new.example.net"}},fixture.options());
    check(!checked.at("record").at("can_activate").get<bool>(),"private mail server address cannot activate");
    fixture.public_address=true;fixture.policies=false;
    checked=domains_check(config,{{"revision",checked.at("revision")},{"domain","new.example.net"}},fixture.options());
    check(checked.at("record").at("can_activate").get<bool>() && checked.at("record").at("dns_status")=="warnings","working ingress with policy warnings should remain explicitly activatable");
    bound=domains_update(config,{{"revision",checked.at("revision")},{"domain","new.example.net"},{"webmail_hostname","login.new.example.net"}});
    check(bound.at("record").at("status")=="pending" && !bound.at("record").at("can_activate").get<bool>() &&
        portal_domain(Config::from_file(path),"login.new.example.net").empty(),"pending binding must invalidate DNS evidence without enabling authentication");
    const auto portal_guide=domains_preview(config,{{"domain","new.example.net"}});
    check(portal_guide.at("hostname")=="mail.example.com" && portal_guide.at("webmail_hostname")=="login.new.example.net", "mail MX and Webmail hostname must remain independent");
    bool webmail_a=false,webmail_aaaa=false;
    for(const auto& item:portal_guide.at("records")) {
        if(item.at("id")=="webmail-a")webmail_a=item.at("name")=="login.new.example.net" && item.at("host")=="login" && !item.at("required").get<bool>();
        if(item.at("id")=="webmail-aaaa")webmail_aaaa=item.at("name")=="login.new.example.net";
    }
    check(webmail_a && webmail_aaaa,"domain DNS guide must include bound Webmail address records");
    rejects(409,[&]{domains_update(config,{{"revision",bound.at("revision")},{"domain","example.com"},{"webmail_hostname","login.new.example.net"}});});
    checked=domains_check(config,{{"revision",bound.at("revision")},{"domain","new.example.net"}},fixture.options());
    check(checked.at("record").at("can_activate").get<bool>(),"missing Webmail DNS must not prevent mail routing activation");
    bool missing_webmail=false;for(const auto& item:checked.at("dns").at("records"))
        if(item.at("id")=="webmail-a")missing_webmail=item.at("status")=="missing";
    check(missing_webmail,"domain DNS check must report missing bound portal address");
    fixture.portal_host="login.new.example.net";fixture.portal_public=false;
    checked=domains_check(config,{{"revision",checked.at("revision")},{"domain","new.example.net"}},fixture.options());
    bool private_webmail=false;for(const auto& item:checked.at("dns").at("records"))
        if(item.at("id")=="webmail-a")private_webmail=item.at("status")=="mismatch" && item.at("code")=="dns_private_address";
    check(private_webmail,"private portal addresses must not be reported as publicly configured");
    fixture.portal_public=true;
    checked=domains_check(config,{{"revision",checked.at("revision")},{"domain","new.example.net"}},fixture.options());
    bool public_webmail=false;for(const auto& item:checked.at("dns").at("records"))
        if(item.at("id")=="webmail-a")public_webmail=item.at("status")=="published" && item.at("observed").at(0)=="93.184.216.35";
    check(public_webmail,"bound Webmail address must be checked independently of the MX hostname address");
    auto altered=Config::from_file(path);altered.values["mail_hostname"]="changed.example.com";save(path,altered.values);listing=domains_list(config,{{"q","new.example.net"}});
    check(!listing.at("items").at(0).at("can_activate").get<bool>(),"saved DNS evidence must be invalidated by server hostname change");
    rejects(409,[&]{domains_activate(config,{{"revision",listing.at("revision")},{"domain","new.example.net"}});});
    altered.values["mail_hostname"]="mail.example.com";altered.values["domain_registry"]["new.example.net"]["dns"]["checked_epoch"]=0;save(path,altered.values);listing=domains_list(config,{{"q","new.example.net"}});
    check(!listing.at("items").at(0).at("can_activate").get<bool>(),"expired DNS evidence must not activate");
    fixture.policies=true;checked=domains_check(config,{{"revision",listing.at("revision")},{"domain","new.example.net"}},fixture.options());
    auto activated=domains_activate(config,{{"revision",checked.at("revision")},{"domain","new.example.net"}});
    check(activated.at("record").at("status")=="active" && activated.at("restart_required").get<bool>() && Config::from_file(path).hosts_domain("new.example.net"),"verified domain activation must become active after restart");
    check(portal_domain(Config::from_file(path),"login.new.example.net")=="new.example.net","activated domain must authenticate at its bound Webmail hostname");
    rejects(409,[&]{domains_remove(config,{{"revision",activated.at("revision")},{"domain","example.com"}});});
    const auto removed=domains_remove(config,{{"revision",activated.at("revision")},{"domain","new.example.net"}});
    check(removed.at("accounts_retained").get<bool>() && !Config::from_file(path).hosts_domain("new.example.net"),"removed domain should leave active routing");
    check(!Config::from_file(path).values.contains("webmail_hostnames"),"domain removal must release its Webmail hostname binding");
    const auto concurrent=domains_add(config,{{"revision",removed.at("revision")},{"domain","race.example.net"}});
    auto racing_options=fixture.options();const auto transport=racing_options.transport;bool changed=false;
    racing_options.transport=[&](const Bytes& wire,auto deadline){if(!changed){auto newer=Config::from_file(path);newer.values["log_level"]="debug";save(path,newer.values);changed=true;}return transport(wire,deadline);};
    rejects(409,[&]{domains_check(config,{{"revision",concurrent.at("revision")},{"domain","race.example.net"}},racing_options);});
    check(Config::from_file(path).text("log_level")=="debug","a DNS check must not overwrite a concurrent configuration save");
    auto full=Config::from_file(path).values;full["padding"]="";const auto base_size=full.dump(2).size()+1;
    full["padding"]=std::string(1048576-base_size-20,'x');save(path,full);const auto full_revision=domains_list(config).at("revision");
    rejects(400,[&]{domains_add(config,{{"revision",full_revision},{"domain","too-large.example.net"}});});
    check(domains_list(config).at("revision")==full_revision,"configuration size refusal must preserve the current file");
    auto registry_only=config;registry_only.values["domain_registry"]={{"draft.example.net",{{"status","pending"}}}};
    check(restart_plan(config,registry_only).empty(),"DNS metadata should not restart services");
    auto portal=config;portal.values["admin_hostname"]="admin.example.com";check(restart_plan(config,portal)==std::vector<std::string>({"web","admin"}),"admin hostname restart scope incorrect");
    portal=config;portal.values["webmail_hostnames"]={{"example.com","mail.example.com"}};
    check(restart_plan(config,portal)==std::vector<std::string>({"web","admin"}),"Webmail hostname binding restart scope incorrect");
    portal=config;portal.values["webmail_shared_hostname"]="login.example.com";check(restart_plan(config,portal)==std::vector<std::string>({"web","admin"}),"shared Webmail restart scope incorrect");
    auto dkim_pending=config;
    dkim_pending.values["domain_registry"]={{"pending.example.net",{{"status","pending"}}}};
    const auto primary_key=prepare_dkim(dkim_pending,{{"domain","example.com"}});
    const auto pending_key=prepare_dkim(dkim_pending,{{"domain","pending.example.net"}});
    check(primary_key.at("fingerprint")==pending_key.at("fingerprint") && pending_key.at("name")=="postplus._domainkey.pending.example.net",
        "pending hosted domains must publish the server signing key that activation will use");
    std::filesystem::remove_all(directory);
    std::cout<<"PASS hosted domain migration, pagination, pending lifecycle, DNS evidence, expiry, activation, removal and restart policy\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
