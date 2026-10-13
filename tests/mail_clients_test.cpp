#include <postplus/mail_clients.hpp>
#include <postplus/settings.hpp>
#include <postplus/restart.hpp>
#include <iostream>
#include <stdexcept>
using namespace postplus;
namespace {
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
}
int main() {
    try {
        Config config; config.values={{"domain","fatutu.xyz"},{"bind","0.0.0.0"},{"admin_bind","::"}};
        check(settings_url(config,"web")=="http://mail.fatutu.xyz/","public Webmail URL must use mail hostname and standard port");
        config.values["tls_certificate"]="certificate.pem"; config.values["tls_private_key"]="key.pem";
        check(settings_url(config,"web")=="https://mail.fatutu.xyz/","TLS Webmail URL");
        check(settings_url(config,"admin")=="https://mail.fatutu.xyz:8081/","administration certificate hostname");
        config.values["ports"]["web"]=8443;
        check(settings_url(config,"web")=="https://mail.fatutu.xyz:8443/","explicit Web port");
        check(!mail_client_settings(config).at("discovery").at("enabled").get<bool>(),"discovery needs standard HTTPS port");
        config.values["ports"].erase("web");
        auto model=mail_client_settings(config);
        check(model.at("listeners").size()==7,"all mail listeners must be advertised");
        check(model.at("discovery").at("enabled").get<bool>(),"discovery on standard HTTPS port");
        HttpRequest request; request.method="GET"; request.path="/mail/config-v1.1.xml?emailaddress=alice%2Btag%40fatutu.xyz"; request.encrypted=true;
        auto response=mail_client_discovery(config,request);
        check(response && response->status==200,"Thunderbird config request");
        check(response->body.find("<port>993</port>")!=std::string::npos && response->body.find("<port>587</port>")!=std::string::npos,"preferred encrypted client ports");
        check(response->body.find("alice+tag@fatutu.xyz")!=std::string::npos,"full email username");
        request.encrypted=false;
        check(mail_client_discovery(config,request)->status==403,"unencrypted discovery must fail");
        request.encrypted=true; request.path="/mail/config-v1.1.xml?emailaddress=alice%40other.xyz";
        check(mail_client_discovery(config,request)->status==404,"foreign domain discovery");
        request.path="/mail/config-v1.1.xml?emailaddress=a%40fatutu.xyz&emailaddress=b%40fatutu.xyz";
        check(mail_client_discovery(config,request)->status==400,"duplicate query email");
        request.path="/mail/config-v1.1.xml?emailaddress=a%00%40fatutu.xyz";
        check(mail_client_discovery(config,request)->status==400,"NUL query injection");
        request.method="POST"; request.path="/Autodiscover/Autodiscover.xml";
        request.body="<Autodiscover><Request><EMailAddress>alice@fatutu.xyz</EMailAddress></Request></Autodiscover>";
        response=mail_client_discovery(config,request);
        check(response && response->status==200 && response->body.find("<LoginName>alice@fatutu.xyz</LoginName>")!=std::string::npos,"Outlook settings discovery");
        request.body="<!DOCTYPE a [<!ENTITY ext SYSTEM 'file:///etc/passwd'>]><EMailAddress>&ext;</EMailAddress>";
        check(mail_client_discovery(config,request)->status==400,"XML entities rejected");
        request.body="<EMailAddress>a@fatutu.xyz</EMailAddress><EMailAddress>b@fatutu.xyz</EMailAddress>";
        check(mail_client_discovery(config,request)->status==400,"duplicate XML email");
        request.body=std::string(4097,'x');
        check(mail_client_discovery(config,request)->status==413,"oversized discovery body");
        config.values["ports"]["imaps"]=0;
        request.body="<EMailAddress>alice@fatutu.xyz</EMailAddress>";
        response=mail_client_discovery(config,request);
        check(response->body.find("<Port>143</Port>")!=std::string::npos && response->body.find("<Encryption>TLS</Encryption>")!=std::string::npos,"STARTTLS fallback for disabled implicit listener");
        auto old=config; config.values["ports"]["imaps"]=1993;
        check(restart_plan(old,config)==std::vector<std::string>{"imap"},"implicit listener change restart");
        config.values["domain"]="mail.fatutu.xyz";
        check(config.mail_hostname()=="mail.fatutu.xyz","mail hostname cannot get duplicate prefix");
        config.values["bind"]="::1";
        check(settings_url(config,"web")=="https://localhost/","local TLS URL");
        std::cout<<"Mail client tests passed\n";
        return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
