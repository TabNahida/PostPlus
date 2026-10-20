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
    bool matching=true,public_address=true,policies=true;unsigned calls=0;
    DnsOptions options(){DnsOptions options;options.connect=[](const auto&,int,auto){return false;};
        options.transport=[this](const Bytes& wire,auto){
            ++calls;std::size_t position=12;std::string owner;
            while(wire.at(position)){const auto length=wire.at(position++);if(!owner.empty())owner+='.';owner.append(reinterpret_cast<const char*>(wire.data()+position),length);position+=length;}
            ++position;const unsigned type=(wire.at(position)<<8)|wire.at(position+1);position+=4;Bytes data;
            if(type==1 && owner=="mail.example.com")data=public_address?Bytes{93,184,216,34}:Bytes{127,0,0,1};
            if(type==15){number(data,10);name(data,matching?"mail.example.com":"other.example.com");}
            if(type==16 && policies){const std::string text=owner.starts_with("_dmarc.")?"v=DMARC1; p=none":"v=spf1 -all";data.push_back(static_cast<unsigned char>(text.size()));data.insert(data.end(),text.begin(),text.end());}
            Bytes result{wire[0],wire[1]};number(result,0x8180);number(result,1);number(result,data.empty()?0:1);number(result,0);number(result,0);result.insert(result.end(),wire.begin()+12,wire.begin()+position);
            if(!data.empty()){number(result,0xc00c);number(result,type);number(result,1);result.insert(result.end(),{0,0,0,60});number(result,static_cast<unsigned>(data.size()));result.insert(result.end(),data.begin(),data.end());}return result;
        };return options;}
};
}
int main(){try {
    const auto directory=std::filesystem::temp_directory_path()/("postplus-domains-"+random_hex(10));std::filesystem::create_directories(directory);
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
    rejects(400,[&]{domains_list(config,{{"limit",201}});});rejects(400,[&]{domains_add(config,{{"revision",listing.at("revision")},{"domain","https://invalid.example.com"}});});
    // DNS permits a 253-byte name, but every hosted domain must also fit a
    // complete mailbox address. Reject it before persisting a broken draft.
    const auto too_long=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(61,'d');
    check(too_long.size()==253 && valid_public_dns_name(too_long),"long-domain fixture must be valid DNS");
    rejects(400,[&]{domains_add(config,{{"revision",listing.at("revision")},{"domain",too_long}});});
    rejects(400,[&]{domains_preview(config,{{"domain",too_long}});});
    check(domains_list(config).at("revision")==listing.at("revision"),"invalid long domain must not change configuration");
    auto added=domains_add(config,{{"revision",listing.at("revision")},{"domain"," New.Example.NET "}});
    check(added.at("record").at("status")=="pending" && !added.at("restart_required").get<bool>(),"pending add must not change running routing");
    const auto pending=Config::from_file(path);check(!pending.hosts_domain("new.example.net") && pending.values.contains("mail_domains") && !pending.values.contains("additional_domains"),"pending add must migrate legacy domains without activating draft");
    rejects(409,[&]{domains_add(config,{{"revision",listing.at("revision")},{"domain","later.example.net"}});});
    rejects(409,[&]{domains_activate(config,{{"revision",added.at("revision")},{"domain","new.example.net"}});});
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
    auto altered=Config::from_file(path);altered.values["mail_hostname"]="changed.example.com";save(path,altered.values);listing=domains_list(config,{{"q","new.example.net"}});
    check(!listing.at("items").at(0).at("can_activate").get<bool>(),"saved DNS evidence must be invalidated by server hostname change");
    rejects(409,[&]{domains_activate(config,{{"revision",listing.at("revision")},{"domain","new.example.net"}});});
    altered.values["mail_hostname"]="mail.example.com";altered.values["domain_registry"]["new.example.net"]["dns"]["checked_epoch"]=0;save(path,altered.values);listing=domains_list(config,{{"q","new.example.net"}});
    check(!listing.at("items").at(0).at("can_activate").get<bool>(),"expired DNS evidence must not activate");
    fixture.policies=true;checked=domains_check(config,{{"revision",listing.at("revision")},{"domain","new.example.net"}},fixture.options());
    auto activated=domains_activate(config,{{"revision",checked.at("revision")},{"domain","new.example.net"}});
    check(activated.at("record").at("status")=="active" && activated.at("restart_required").get<bool>() && Config::from_file(path).hosts_domain("new.example.net"),"verified domain activation must become active after restart");
    rejects(409,[&]{domains_remove(config,{{"revision",activated.at("revision")},{"domain","example.com"}});});
    const auto removed=domains_remove(config,{{"revision",activated.at("revision")},{"domain","new.example.net"}});
    check(removed.at("accounts_retained").get<bool>() && !Config::from_file(path).hosts_domain("new.example.net"),"removed domain should leave active routing");
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
    auto portal=config;portal.values["admin_hostname"]="admin.example.com";check(restart_plan(config,portal)==std::vector<std::string>{"admin"},"admin hostname restart scope incorrect");
    portal=config;portal.values["webmail_shared_hostname"]="login.example.com";check(restart_plan(config,portal)==std::vector<std::string>({"web","admin"}),"shared Webmail restart scope incorrect");
    std::filesystem::remove_all(directory);
    std::cout<<"PASS hosted domain migration, pagination, pending lifecycle, DNS evidence, expiry, activation, removal and restart policy\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
