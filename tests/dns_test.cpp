#include <postplus/dns.hpp>
#include <algorithm>
#include <iostream>
#include <map>

using namespace postplus;
namespace {
using Bytes=std::vector<unsigned char>;
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
void number(Bytes& packet,unsigned value){packet.push_back(static_cast<unsigned char>(value>>8));packet.push_back(static_cast<unsigned char>(value));}
void name(Bytes& packet,std::string value){std::size_t begin=0;while(begin<value.size()){const auto dot=value.find('.',begin),end=dot==std::string::npos?value.size():dot;packet.push_back(static_cast<unsigned char>(end-begin));packet.insert(packet.end(),value.begin()+begin,value.begin()+end);begin=end+1;}packet.push_back(0);}
struct Fixture {
    std::map<std::pair<std::string,unsigned>,std::vector<Bytes>> answers;
    int requests=0;unsigned rcode=0;bool truncated=false,wrong_id=false,wrong_question=false,bad_pointer=false,alias=false;bool timeout=false;
    static Bytes txt(const std::string& value,bool split=false){Bytes data;const auto first=split?value.size()/2:value.size();data.push_back(static_cast<unsigned char>(first));data.insert(data.end(),value.begin(),value.begin()+first);if(split){data.push_back(static_cast<unsigned char>(value.size()-first));data.insert(data.end(),value.begin()+first,value.end());}return data;}
    static Bytes mx(unsigned preference,const std::string& host){Bytes data;number(data,preference);name(data,host);return data;}
    static Bytes address(const std::string& value){const auto parsed=asio::ip::make_address(value);if(parsed.is_v4()){const auto bytes=parsed.to_v4().to_bytes();return {bytes.begin(),bytes.end()};}const auto bytes=parsed.to_v6().to_bytes();return {bytes.begin(),bytes.end()};}
    Bytes send(const Bytes& request,std::chrono::steady_clock::time_point deadline){
        ++requests;check(deadline>std::chrono::steady_clock::now(),"invalid DNS deadline");if(timeout)throw DnsError("dns_timeout","test timeout");
        std::size_t position=12;std::string owner;
        while(request.at(position)){const auto size=request.at(position++);if(!owner.empty())owner+='.';owner.append(reinterpret_cast<const char*>(request.data()+position),size);position+=size;}
        ++position;const unsigned type=(request.at(position)<<8)|request.at(position+1);position+=4;
        const auto found=answers.find({owner,type});const std::vector<Bytes> empty;const auto& rows=found==answers.end()?empty:found->second;
        const bool use_alias=alias && type==1;
        Bytes result{request[0],request[1]};number(result,0x8180|rcode|(truncated?0x0200:0));number(result,1);number(result,static_cast<unsigned>(rows.size())+(use_alias?1:0));number(result,0);number(result,0);
        result.insert(result.end(),request.begin()+12,request.begin()+position);
        if(wrong_id)++result[0];if(wrong_question)result[13]='z';
        if(use_alias){Bytes target;name(target,"alias.example.com");number(result,0xc00c);number(result,5);number(result,1);result.insert(result.end(),{0,0,0,60});number(result,static_cast<unsigned>(target.size()));result.insert(result.end(),target.begin(),target.end());}
        for(const auto& data:rows){if(use_alias)name(result,"alias.example.com");else number(result,bad_pointer?0xcfff:0xc00c);number(result,type);number(result,1);result.insert(result.end(),{0,0,0,60});number(result,static_cast<unsigned>(data.size()));result.insert(result.end(),data.begin(),data.end());}
        return result;
    }
    DnsOptions options(){DnsOptions value;value.transport=[this](const auto& wire,auto deadline){return send(wire,deadline);};return value;}
};
const Json& record(const Json& response,const std::string& id){for(const auto& item:response.at("records"))if(item.at("id")==id)return item;throw std::runtime_error("missing DNS result id");}
Json request(){return {{"domain","example.com"},{"hostname","mail.example.com"},{"ipv4","93.184.216.34"},{"ipv6","2606:4700::1111"},{"spf","v=spf1 include:relay.example.com -all"},{"dkim_name","selector._domainkey.example.com"},{"dkim_type","TXT"},{"dkim_value","k=rsa; p=AbCd1234"},{"dmarc","v=DMARC1; p=none"}};}
template<class F>void rejects(F call){try{call();}catch(const DnsError& error){check(error.code=="invalid_dns_input","wrong DNS validation code");return;}throw std::runtime_error("invalid DNS input accepted");}
}
int main(){try {
    Fixture fixture;
    fixture.answers[{"mail.example.com",1}]={Fixture::address("93.184.216.34")};
    fixture.answers[{"mail.example.com",28}]={Fixture::address("2606:4700::1111")};
    fixture.answers[{"example.com",15}]={Fixture::mx(10,"mail.example.com")};
    fixture.answers[{"example.com",16}]={Fixture::txt("unrelated-domain-verification\xff"),Fixture::txt("v=spf1 include:relay.example.com -all",true)};
    fixture.answers[{"selector._domainkey.example.com",16}]={Fixture::txt("k=rsa; p=AbCd1234",true)};
    fixture.answers[{"_dmarc.example.com",16}]={Fixture::txt("v=DMARC1; p=none")};
    DnsChecker checker(fixture.options());auto input=request();input["hostname"]="MAIL.EXAMPLE.COM.";input["ipv6"]="2606:4700:0:0:0:0:0:1111";
    auto result=checker.check(input);check(fixture.requests==6,"DNS query count was not bounded");
    for(const auto& item:result.at("records"))check(item.at("status")=="matched","correct DNS value did not match");
    check(record(result,"mx").at("observed")==Json::array({"10 mail.example.com"}),"MX priority was discarded");
    check(record(result,"spf").at("observed")==Json::array({"v=spf1 include:relay.example.com -all"}),"TXT chunks were not joined or unrelated TXT was included");
    input=request();input["dmarc"]="v=DMARC1 ; rua=mailto:reports@example.com; p=none";fixture.answers[{"_dmarc.example.com",16}]={Fixture::txt(input.at("dmarc").get<std::string>())};result=checker.check(input);check(record(result,"dmarc").at("status")=="matched","valid DMARC tag order or spacing failed");fixture.answers[{"_dmarc.example.com",16}]={Fixture::txt("v=DMARC1; p=none")};
    fixture.alias=true;result=checker.check(request());check(record(result,"a").at("code")=="dns_mx_alias" && record(result,"mx").at("status")=="mismatch","MX hostname CNAME alias passed");fixture.alias=false;
    fixture.answers[{"mail.example.com",1}].push_back(Fixture::address("93.184.216.35"));result=checker.check(request());check(record(result,"a").at("status")=="mismatch","an additional incorrect address passed");
    fixture.answers[{"example.com",16}].push_back(Fixture::txt("v=spf1 -all"));result=checker.check(request());check(record(result,"spf").at("code")=="dns_multiple_policy_records","multiple SPF records passed");
    input=request();input["dkim_value"]="k=rsa; p=abcd1234";result=checker.check(input);check(record(result,"dkim").at("status")=="mismatch","DKIM key comparison ignored case");
    input=request();input["dkim_type"]="CNAME";input["dkim_value"]="DKIM.RELAY.EXAMPLE.COM.";Bytes target;name(target,"dkim.relay.example.com");fixture.answers[{"selector._domainkey.example.com",5}]={target};result=checker.check(input);check(record(result,"dkim").at("status")=="matched","provider CNAME target failed");
    input["dkim_value"]="SELECTOR1._DOMAINKEY.RELAY.EXAMPLE.COM.";target.clear();name(target,"selector1._domainkey.relay.example.com");fixture.answers[{"selector._domainkey.example.com",5}]={target};result=checker.check(input);check(record(result,"dkim").at("status")=="matched","provider CNAME target containing _domainkey failed");
    input=request();input["spf"]="";input["dkim_name"]="";input["dkim_value"]="";input["dmarc"]="";input["ipv6"]="";result=checker.check(input);
    check(record(result,"spf").at("status")=="not_configured" && record(result,"dkim").at("status")=="not_configured","missing provider values were passed");
    check(record(result,"aaaa").at("status")=="mismatch","unexpected public AAAA was ignored");
    fixture.answers.clear();result=checker.check(request());check(record(result,"a").at("status")=="missing","DNS NODATA did not remain missing");
    fixture.rcode=3;result=checker.check(request());check(record(result,"mx").at("status")=="missing","NXDOMAIN did not remain missing");
    fixture.rcode=2;result=checker.check(request());check(record(result,"mx").at("status")=="error","SERVFAIL was marked missing");fixture.rcode=0;
    fixture.timeout=true;result=checker.check(request());check(record(result,"a").at("status")=="error" && record(result,"a").at("code")=="dns_timeout","timeout was marked missing");fixture.timeout=false;
    fixture.wrong_id=true;result=checker.check(request());check(record(result,"a").at("code")=="dns_invalid_response","mismatched transaction was accepted");fixture.wrong_id=false;
    fixture.wrong_question=true;result=checker.check(request());check(record(result,"a").at("code")=="dns_invalid_response","mismatched question was accepted");fixture.wrong_question=false;
    fixture.truncated=true;result=checker.check(request());check(record(result,"a").at("code")=="dns_truncated","truncated response was accepted");fixture.truncated=false;
    fixture.answers[{"mail.example.com",1}]={Fixture::address("93.184.216.34")};fixture.bad_pointer=true;result=checker.check(request());check(record(result,"a").at("code")=="dns_invalid_response","out-of-range compression pointer accepted");fixture.bad_pointer=false;
    const auto before=fixture.requests;
    input=request();input["resolver"]="http://127.0.0.1/";rejects([&]{checker.check(input);});
    input=request();input["hostname"]="https://example.com/";rejects([&]{checker.check(input);});
    input=request();input["dkim_name"]="selector._domainkey.other.net";rejects([&]{checker.check(input);});
    input=request();input["dkim_value"]=std::string(4097,'a');rejects([&]{checker.check(input);});
    input=request();input["ipv4"]="2001:db8::1";rejects([&]{checker.check(input);});
    input=request();input["dkim_value"]="v=DKIM1; p=";rejects([&]{checker.check(input);});
    input=request();input["dmarc"]="v=DMARC1; p=invalid";rejects([&]{checker.check(input);});
    for(const auto& domain:{"example.test","example.invalid","example.local","example.localhost","example.example"}) {
        input=request();input["domain"]=domain;rejects([&]{checker.check(input);});
    }
    for(const auto& address:{"127.0.0.1","10.0.0.2","100.64.0.1","169.254.1.2","192.168.1.2","198.51.100.2","203.0.113.2","224.0.0.1"}) {
        input=request();input["ipv4"]=address;rejects([&]{checker.check(input);});
    }
    for(const auto& address:{"::1","fe80::1","fd00::1","2001:db8::1","3fff::1"}) {
        input=request();input["ipv6"]=address;rejects([&]{checker.check(input);});
    }
    input=request();input["dkim_value"]="";rejects([&]{checker.check(input);});
    input=request();input["dkim_value"]="v = DKIM2; p=AbCd1234";rejects([&]{checker.check(input);});
    input=request();input["dkim_value"]="v=; p=AbCd1234";rejects([&]{checker.check(input);});
    input=request();input["dkim_value"]="p=AbCd1234; P=AbCd1234";rejects([&]{checker.check(input);});
    input=request();input["dkim_name"]="bad_selector._domainkey.example.com";rejects([&]{checker.check(input);});
    input=request();input["dmarc"]="v=DMARC1; p=none; rua=mailto:a@example.com; RUA=mailto:b@example.com";rejects([&]{checker.check(input);});
    check(fixture.requests==before,"invalid DNS input made a network request");
    std::cout<<"PASS DNS input/transport limits, public record matching, TXT chunks, MX priorities, DKIM TXT/CNAME, missing/error separation and packet validation\n";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
