#include <postplus/dns.hpp>
#include <algorithm>
#include <array>
#include <charconv>
#include <ctime>
#include <iomanip>
#include <set>
#include <sstream>

namespace postplus {
namespace {
using Clock=std::chrono::steady_clock;
using Bytes=std::vector<unsigned char>;
constexpr std::size_t max_packet=8192;
constexpr std::uint16_t type_a=1,type_cname=5,type_mx=15,type_txt=16,type_aaaa=28;

[[noreturn]] void malformed() {throw DnsError("dns_invalid_response","The public DNS resolver returned an invalid response. Retry the check.");}
std::uint16_t number(const Bytes& packet,std::size_t offset) {
    if(offset+2>packet.size()) malformed();
    return static_cast<std::uint16_t>((packet[offset]<<8)|packet[offset+1]);
}
void append_number(Bytes& packet,std::uint16_t value) {packet.push_back(static_cast<unsigned char>(value>>8));packet.push_back(static_cast<unsigned char>(value));}
std::string canonical(std::string value) {value=lower(trim(std::move(value)));if(value.ends_with('.'))value.pop_back();return value;}
bool domain_name(std::string_view value,bool underscores=false) {
    if(value.empty() || value.size()>253 || value.find('.')==std::string_view::npos) return false;
    const auto suffix=value.substr(value.rfind('.')+1);
    if(suffix=="localhost" || suffix=="local" || suffix=="test" || suffix=="invalid" || suffix=="example")return false;
    if(suffix.find_first_not_of("0123456789")==std::string_view::npos)return false;
    std::size_t label=0;char previous='\0';
    for(char character:value) {
        if(character=='.') {if(!label || previous=='-')return false;label=0;}
        else {
            if(!((character>='a' && character<='z') || (character>='0' && character<='9') || character=='-' ||
                 (underscores && character=='_')) || (!label && character=='-') || ++label>63) return false;
        }
        previous=character;
    }
    std::error_code error;(void)asio::ip::make_address(value,error);
    return label && previous!='-' && error;
}
bool public_address(const asio::ip::address& address) {
    if(address.is_v4()) {
        const auto bytes=address.to_v4().to_bytes();const auto a=bytes[0],b=bytes[1],c=bytes[2];
        return !(a==0 || a==10 || a==127 || a>=224 || (a==100 && b>=64 && b<=127) || (a==169 && b==254) ||
            (a==172 && b>=16 && b<=31) || (a==192 && (b==168 || (b==0 && (c==0 || c==2)))) ||
            (a==192 && b==88 && c==99) ||
            (a==198 && (b==18 || b==19 || (b==51 && c==100))) || (a==203 && b==0 && c==113));
    }
    const auto value=address.to_v6();const auto bytes=value.to_bytes();
    return value.scope_id()==0 && bytes[0]>=0x20 && bytes[0]<0x40 &&
        !(bytes[0]==0x20 && bytes[1]==0x01 && bytes[2]<2) &&
        !(bytes[0]==0x20 && bytes[1]==0x02) &&
        !(bytes[0]==0x20 && bytes[1]==0x01 && bytes[2]==0x0d && bytes[3]==0xb8) &&
        !(bytes[0]==0x3f && bytes[1]==0xff && bytes[2]<0x10);
}
std::string field(const Json& request,const std::string& key,std::size_t maximum=4096) {
    if(!request.contains(key)) return {};
    if(!request.at(key).is_string()) throw DnsError("invalid_dns_input","DNS fields must be text.");
    auto value=trim(request.at(key).get<std::string>());
    if(value.size()>maximum || std::any_of(value.begin(),value.end(),[](unsigned char byte){return (byte<32 && byte!='\t') || byte==127;}))
        throw DnsError("invalid_dns_input","A DNS field is too long or contains invalid characters.");
    return value;
}
void append_name(Bytes& packet,const std::string& name) {
    std::size_t begin=0;
    while(begin<name.size()) {
        const auto dot=name.find('.',begin),end=dot==std::string::npos?name.size():dot;
        packet.push_back(static_cast<unsigned char>(end-begin));
        packet.insert(packet.end(),name.begin()+begin,name.begin()+end);begin=end+1;
    }
    packet.push_back(0);
}
Bytes question(const std::string& name,std::uint16_t type) {
    Bytes result;unsigned id=0;const auto random=random_hex(2);
    (void)std::from_chars(random.data(),random.data()+random.size(),id,16);
    append_number(result,static_cast<std::uint16_t>(id));append_number(result,0x0100);
    append_number(result,1);append_number(result,0);append_number(result,0);append_number(result,1);
    append_name(result,name);append_number(result,type);append_number(result,1);
    // EDNS0 asks for bounded UDP answers large enough for common DKIM keys.
    result.push_back(0);append_number(result,41);append_number(result,4096);
    result.insert(result.end(),{0,0,0,0});append_number(result,0);
    return result;
}
Bytes native_query(const Bytes& request,Clock::time_point deadline) {
    asio::io_context io;asio::ip::udp::socket socket(io);asio::steady_timer timer(io);
    std::error_code error;
    socket.open(asio::ip::udp::v4(),error);
    if(!error) socket.connect({asio::ip::make_address_v4("1.1.1.1"),53},error);
    if(error) throw DnsError("dns_unavailable","Cannot reach the public DNS resolver. Allow outbound UDP port 53 and retry.");
    bool timed_out=false;
    const auto limit=std::min(deadline,Clock::now()+std::chrono::milliseconds(1500));
    if(limit<=Clock::now()) throw DnsError("dns_timeout","The DNS check timed out. Retry after checking network access.");
    timer.expires_at(limit);
    timer.async_wait([&](std::error_code issue){if(!issue){timed_out=true;std::error_code ignored;socket.cancel(ignored);}});
    std::array<unsigned char,max_packet> buffer{};std::size_t received=0;
    socket.async_send(asio::buffer(request),[&](std::error_code issue,std::size_t count){
        if(issue || count!=request.size()) {error=issue?issue:asio::error::message_size;timer.cancel();return;}
        socket.async_receive(asio::buffer(buffer),[&](std::error_code failure,std::size_t size){error=failure;received=size;timer.cancel();});
    });
    io.run();
    if(timed_out) throw DnsError("dns_timeout","The public DNS resolver did not answer in time. Allow outbound UDP port 53 and retry.");
    if(error || !received) throw DnsError("dns_unavailable","Cannot read a response from the public DNS resolver. Check network access and retry.");
    return {buffer.begin(),buffer.begin()+received};
}
Bytes native_tcp_query(const Bytes& request,Clock::time_point deadline) {
    asio::io_context io;tcp::socket socket(io);asio::steady_timer timer(io);
    std::error_code error;bool timed_out=false;Bytes response;
    const auto limit=std::min(deadline,Clock::now()+std::chrono::seconds(3));
    if(limit<=Clock::now())throw DnsError("dns_timeout","The DNS lookup timed out.");
    timer.expires_at(limit);
    timer.async_wait([&](std::error_code issue){if(!issue){timed_out=true;std::error_code ignored;socket.cancel(ignored);socket.close(ignored);}});
    Bytes framed;append_number(framed,static_cast<std::uint16_t>(request.size()));framed.insert(framed.end(),request.begin(),request.end());
    std::array<unsigned char,2> prefix{};
    socket.async_connect({asio::ip::make_address_v4("1.1.1.1"),53},[&](std::error_code issue){
        if(issue){error=issue;timer.cancel();return;}
        asio::async_write(socket,asio::buffer(framed),[&](std::error_code failure,std::size_t){
            if(failure){error=failure;timer.cancel();return;}
            asio::async_read(socket,asio::buffer(prefix),[&](std::error_code failure,std::size_t){
                if(failure){error=failure;timer.cancel();return;}
                const auto size=static_cast<std::size_t>((prefix[0]<<8)|prefix[1]);
                if(size<12 || size>max_packet){error=asio::error::message_size;timer.cancel();return;}
                response.resize(size);
                asio::async_read(socket,asio::buffer(response),[&](std::error_code failure,std::size_t){error=failure;timer.cancel();});
            });
        });
    });
    io.run();
    if(timed_out)throw DnsError("dns_timeout","The public DNS resolver did not answer over TCP in time.");
    if(error || response.empty())throw DnsError("dns_unavailable","Cannot read a TCP DNS response. Allow outbound TCP port 53 and retry.");
    return response;
}
std::string read_name(const Bytes& packet,std::size_t& offset) {
    std::string result;std::size_t position=offset;bool jumped=false;
    for(int steps=0;steps<128;++steps) {
        if(position>=packet.size()) malformed();
        const auto length=packet[position];
        if((length&0xc0)==0xc0) {
            const auto target=static_cast<std::size_t>(number(packet,position)&0x3fff);
            if(target>=position) malformed();
            if(!jumped) offset=position+2;
            jumped=true;position=target;continue;
        }
        if(length>63 || position+1+length>packet.size()) malformed();
        ++position;
        if(!length) {if(!jumped)offset=position;return result;}
        if(!result.empty())result+='.';
        for(std::size_t index=0;index<length;++index) {
            const auto byte=packet[position+index];
            if(!((byte>='a' && byte<='z') || (byte>='A' && byte<='Z') || (byte>='0' && byte<='9') || byte=='-' || byte=='_')) malformed();
            result+=static_cast<char>(byte);
        }
        if(result.size()>253) malformed();
        position+=length;if(!jumped)offset=position;
    }
    malformed();
}
struct Answer {std::string name,value;std::uint16_t type;};
DnsLookup parse(const Bytes& packet,const Bytes& request,const std::string& name,std::uint16_t type) {
    if(packet.size()<12 || packet.size()>max_packet || number(packet,0)!=number(request,0)) malformed();
    const auto flags=number(packet,2),answers=number(packet,6),authority=number(packet,8),additional=number(packet,10);
    if(!(flags&0x8000) || (flags&0x7800) || number(packet,4)!=1 || answers>128 || authority>128 || additional>128) malformed();
    if(flags&0x0200) throw DnsError("dns_truncated","The DNS answer was too large for this check. Retry using your DNS provider's lookup tools.");
    std::size_t position=12;
    if(canonical(read_name(packet,position))!=name || number(packet,position)!=type || number(packet,position+2)!=1) malformed();
    position+=4;
    const auto rcode=flags&15;
    if(rcode==3)return {{},false,true,name,0};
    if(rcode!=0)throw DnsError("dns_resolver_failed","The public DNS resolver could not complete the lookup. Check DNS delegation and DNSSEC, then retry.");
    std::vector<Answer> records;
    const unsigned count=answers+authority+additional;
    for(unsigned index=0;index<count;++index) {
        auto owner=canonical(read_name(packet,position));
        const auto rr_type=number(packet,position),rr_class=number(packet,position+2),size=number(packet,position+8);
        position+=10;if(position+size>packet.size())malformed();
        const auto end=position+size;std::string value;
        if(index<answers && rr_class==1) {
            if(rr_type==type_a) {
                if(size!=4)malformed();asio::ip::address_v4::bytes_type bytes{};std::copy_n(packet.begin()+position,4,bytes.begin());value=asio::ip::address_v4(bytes).to_string();
            } else if(rr_type==type_aaaa) {
                if(size!=16)malformed();asio::ip::address_v6::bytes_type bytes{};std::copy_n(packet.begin()+position,16,bytes.begin());value=asio::ip::address_v6(bytes).to_string();
            } else if(rr_type==type_cname || rr_type==type_mx) {
                auto cursor=position;
                if(rr_type==type_mx) {if(size<3)malformed();value=std::to_string(number(packet,cursor))+" ";cursor+=2;}
                value+=canonical(read_name(packet,cursor));if(cursor!=end)malformed();
            } else if(rr_type==type_txt) {
                auto cursor=position;
                while(cursor<end) {
                    const auto length=packet[cursor++];if(cursor+length>end)malformed();
                    for(std::size_t item=0;item<length;++item)value+=static_cast<char>(packet[cursor++]);
                }
            }
            if(rr_type==type_a || rr_type==type_aaaa || rr_type==type_cname || rr_type==type_mx || rr_type==type_txt)
                records.push_back({std::move(owner),std::move(value),rr_type});
        }
        position=end;
    }
    if(position!=packet.size())malformed();
    // Only records for the actual question or its bounded CNAME chain count.
    // Additional/unrelated answers never become a successful match.
    std::set<std::string> names{name};auto current=name;unsigned hops=0;
    if(type!=type_cname) {
        for(int step=0;step<16;++step) {
            const auto alias=std::find_if(records.begin(),records.end(),[&](const Answer& answer){return answer.name==current && answer.type==type_cname;});
            if(alias==records.end())break;
            for(const auto& other:records)if(other.name==current && other.type==type_cname && other.value!=alias->value)malformed();
            if(!names.insert(alias->value).second)malformed();current=alias->value;
            ++hops;
            if(step==15)malformed();
        }
    }
    std::vector<std::string> values;
    for(const auto& record:records)if(record.type==type && names.contains(record.name))values.push_back(record.value);
    std::sort(values.begin(),values.end());values.erase(std::unique(values.begin(),values.end()),values.end());return {std::move(values),names.size()>1,false,current,hops};
}
DnsLookup exchange(const DnsOptions& options,const std::string& name,std::uint16_t type,Clock::time_point deadline) {
    if(Clock::now()>=deadline)throw DnsError("dns_timeout","The DNS lookup reached its time limit.");
    const auto wire=question(name,type);
    const auto response=options.transport?options.transport(wire,deadline):native_query(wire,deadline);
    try {return parse(response,wire,name,type);}
    catch(const DnsError& error) {
        if(error.code!="dns_truncated")throw;
        if(options.transport && !options.tcp_transport)throw;
        const auto tcp_response=options.tcp_transport?options.tcp_transport(wire,deadline):native_tcp_query(wire,deadline);
        return parse(tcp_response,wire,name,type);
    }
}
std::string timestamp() {
    const auto now=std::time(nullptr);std::tm time{};
#ifdef _WIN32
    gmtime_s(&time,&now);
#else
    gmtime_r(&now,&time);
#endif
    std::ostringstream text;text<<std::put_time(&time,"%Y-%m-%dT%H:%M:%SZ");return text.str();
}
std::string display_value(const std::string& value) {
    constexpr char hex[]="0123456789abcdef";std::string result;
    for(unsigned char byte:value) {
        if(byte>=32 && byte<=126)result+=static_cast<char>(byte);
        else {result+="\\x";result+=hex[byte>>4];result+=hex[byte&15];}
    }
    return result;
}
std::string tag_value(const std::string& record,const std::string& name,bool* present=nullptr) {
    std::size_t begin=0;std::string result;bool seen=false;
    while(begin<record.size()) {
        const auto end=record.find(';',begin),last=end==std::string::npos?record.size():end;
        const auto part=trim(record.substr(begin,last-begin));const auto equal=part.find('=');
        if(equal!=std::string::npos && lower(trim(part.substr(0,equal)))==name) {
            if(seen)throw DnsError("invalid_dns_input","A DNS policy contains duplicate tags.");
            seen=true;result=trim(part.substr(equal+1));
        }
        begin=last+1;
    }
    if(present)*present=seen;return result;
}
void validate_unique_tags(const std::string& record) {
    std::set<std::string> names;std::size_t begin=0;
    while(begin<record.size()) {
        const auto end=record.find(';',begin),last=end==std::string::npos?record.size():end;
        const auto part=trim(record.substr(begin,last-begin));const auto equal=part.find('=');
        if(!part.empty() && (equal==std::string::npos || trim(part.substr(0,equal)).empty() || !names.insert(lower(trim(part.substr(0,equal)))).second))
            throw DnsError("invalid_dns_input","A DNS policy contains invalid or duplicate tags.");
        begin=last+1;
    }
}
std::string first_version(const std::string& record) {
    const auto first=trim(record.substr(0,record.find(';')));const auto equal=first.find('=');
    if(equal==std::string::npos || lower(trim(first.substr(0,equal)))!="v")return {};
    return lower(trim(first.substr(equal+1)));
}
}

bool is_public_mail_address(const asio::ip::address& address){return public_address(address);}
bool valid_public_dns_name(std::string_view name){return domain_name(name);}
DnsResolver::DnsResolver(DnsOptions options):options_(std::move(options)){}
DnsLookup DnsResolver::lookup(std::string name,DnsType type,Clock::time_point deadline) const {
    name=canonical(std::move(name));
    if(!domain_name(name,true))throw DnsError("dns_invalid_name","The destination has an invalid public DNS name.");
    deadline=std::min(deadline,Clock::now()+options_.timeout);
    std::set<std::string> visited{name};bool alias=false;unsigned hops=0;
    for(unsigned queries=0;queries<16;++queries) {
        auto result=exchange(options_,name,static_cast<std::uint16_t>(type),deadline);
        alias=alias || result.alias;hops+=result.alias_hops;
        if(hops>=16)throw DnsError("dns_alias_limit","The destination DNS alias chain exceeds its limit.");
        if(result.nxdomain || !result.values.empty() || !result.alias) {result.alias=alias;result.alias_hops=hops;return result;}
        if(!domain_name(result.canonical_name,true) || !visited.insert(result.canonical_name).second)
            throw DnsError("dns_alias_loop","The destination DNS alias chain is invalid or loops.");
        name=std::move(result.canonical_name);
    }
    throw DnsError("dns_alias_limit","The destination DNS alias chain exceeds its query limit.");
}
DnsChecker::DnsChecker(DnsOptions options):options_(std::move(options)) {
    if(options_.timeout<std::chrono::seconds(1) || options_.timeout>std::chrono::seconds(15))throw std::invalid_argument("invalid DNS check timeout");
}
Json DnsChecker::check(const Json& request) const {
    if(!request.is_object())throw DnsError("invalid_dns_input","DNS checks require a JSON object.");
    const std::set<std::string> keys{"domain","hostname","ipv4","ipv6","spf","dkim_name","dkim_type","dkim_value","dmarc"};
    for(const auto& entry:request.items())if(!keys.contains(entry.key()))throw DnsError("invalid_dns_input","Unknown DNS check field.");
    const auto domain=canonical(field(request,"domain",253)),hostname=canonical(field(request,"hostname",253));
    if(!domain_name(domain) || !domain_name(hostname))throw DnsError("invalid_dns_input","Enter a valid public ASCII mail domain and server hostname.");
    auto ipv4=field(request,"ipv4",64),ipv6=field(request,"ipv6",64);
    for(auto* value:{&ipv4,&ipv6})if(!value->empty()) {
        std::error_code error;const auto address=asio::ip::make_address(*value,error);
        if(error || (value==&ipv4 && !address.is_v4()) || (value==&ipv6 && !address.is_v6()) || !public_address(address))
            throw DnsError("invalid_dns_input","Enter public IPv4 and IPv6 addresses in their matching fields; private and documentation addresses cannot receive Internet mail.");
        *value=address.to_string();
    }
    const auto spf=field(request,"spf"),dkim_value=field(request,"dkim_value"),dmarc=field(request,"dmarc");
    const auto dkim_name=canonical(field(request,"dkim_name",253));
    auto dkim_type=lower(field(request,"dkim_type",8));if(dkim_type.empty())dkim_type="txt";
    if(dkim_type!="txt" && dkim_type!="cname")throw DnsError("invalid_dns_input","The DKIM record type must be TXT or CNAME.");
    const auto dkim_suffix="._domainkey."+domain;
    if(!dkim_name.empty() && (!domain_name(dkim_name,true) || !dkim_name.ends_with(dkim_suffix) ||
        !domain_name(dkim_name.substr(0,dkim_name.size()-dkim_suffix.size())+"."+domain)))
        throw DnsError("invalid_dns_input","Use a full DKIM selector name ending in ._domainkey. followed by the mail domain.");
    if(dkim_value.empty()!=dkim_name.empty())throw DnsError("invalid_dns_input","Enter both the provider's full DKIM record name and public record value.");
    if(dkim_type=="cname" && !dkim_value.empty() && !domain_name(canonical(dkim_value),true))throw DnsError("invalid_dns_input","Enter the provider's DKIM CNAME target hostname.");
    if(!spf.empty() && lower(spf)!="v=spf1" && !lower(spf).starts_with("v=spf1 ") && !lower(spf).starts_with("v=spf1\t"))throw DnsError("invalid_dns_input","Use the provider's complete SPF value beginning with v=spf1.");
    if(!dmarc.empty() && first_version(dmarc)!="dmarc1")throw DnsError("invalid_dns_input","Use a complete DMARC value beginning with v=DMARC1;.");
    if(!dmarc.empty()) {
        validate_unique_tags(dmarc);
        const auto policy=lower(tag_value(dmarc,"p"));
        if(policy!="none" && policy!="quarantine" && policy!="reject")throw DnsError("invalid_dns_input","A DMARC record needs p=none, p=quarantine or p=reject.");
    }
    if(dkim_type=="txt" && !dkim_value.empty()) {
        validate_unique_tags(dkim_value);
        bool version_present=false;const auto version=tag_value(dkim_value,"v",&version_present);auto key=tag_value(dkim_value,"p");
        key.erase(std::remove_if(key.begin(),key.end(),[](unsigned char byte){return byte==' ' || byte=='\t';}),key.end());
        if((version_present && lower(version)!="dkim1") || key.empty() || key.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")!=std::string::npos)
            throw DnsError("invalid_dns_input","Enter the provider's public DKIM TXT value with a nonempty base64 p= key. If present, v must be DKIM1.");
    }
    const auto deadline=Clock::now()+options_.timeout;
    Json result={{"ok",true},{"resolver","Cloudflare public DNS (1.1.1.1)"},{"checked_at",timestamp()},
        {"limitations","This checks public DNS records only; it does not verify ports, PTR, DKIM signing or mail delivery."},{"records",Json::array()}};
    bool hostname_alias=false;
    auto record=[&](const std::string& id,const std::string& name,std::uint16_t type,const std::string& label,const std::string& expected,bool query_unconfigured=false) {
        Json item={{"id",id},{"name",name},{"type",label},{"expected",expected.empty()?Json::array():Json::array({expected})},
            {"observed",Json::array()},{"status","not_configured"},{"code","dns_not_configured"},{"message","Enter the expected DNS record value before checking this record."}};
        if(expected.empty() && !query_unconfigured){result["records"].push_back(std::move(item));return;}
        try {
            if(Clock::now()>=deadline)throw DnsError("dns_timeout","The DNS check reached its time limit. Retry the check.");
            auto lookup=exchange(options_,name,type,deadline);
            auto observed=std::move(lookup.values);
            if((id=="a" || id=="aaaa") && lookup.alias)hostname_alias=true;
            if(id=="spf" || id=="dmarc") {
                observed.erase(std::remove_if(observed.begin(),observed.end(),[&](const std::string& value){
                    const auto text=lower(value);
                    return id=="spf" ? !(text=="v=spf1" || text.starts_with("v=spf1 ") || text.starts_with("v=spf1\t")) : first_version(value)!="dmarc1";
                }),observed.end());
            }
            auto display=observed;for(auto& value:display)value=display_value(value);item["observed"]=display;
            if(((id=="a" || id=="aaaa") && lookup.alias) || (id=="mx" && hostname_alias)) {
                item["status"]="mismatch";item["code"]="dns_mx_alias";item["message"]="The mail server hostname is a CNAME alias. Publish direct A/AAAA records for an MX target.";
            } else if(expected.empty()) {
                if(!observed.empty()){item["status"]="mismatch";item["code"]="dns_unexpected_record";item["message"]="A public record exists, but no expected address was entered. Check it before requesting a certificate.";}
            } else if(observed.empty()) {
                item["status"]="missing";item["code"]="dns_missing";item["message"]="The expected record is not visible in public DNS yet.";
            } else {
                const bool multiple_policy=(id=="spf" || id=="dmarc") && observed.size()!=1;
                const bool matched=!multiple_policy && std::all_of(observed.begin(),observed.end(),[&](const std::string& value){
                    if(id=="mx")return canonical(value.substr(value.find(' ')+1))==hostname;
                    if(id=="dkim" && type==type_cname)return canonical(value)==canonical(expected);
                    return value==expected;
                });
                item["status"]=matched?"matched":"mismatch";item["code"]=matched?"dns_matched":multiple_policy?"dns_multiple_policy_records":"dns_mismatch";
                item["message"]=matched?"The public DNS record matches the expected value.":multiple_policy?"Multiple policy records are published. Keep only one SPF or DMARC record at this name.":"Public DNS values do not all match the expected value. Review the observed records.";
            }
        } catch(const DnsError& error) {item["status"]="error";item["code"]=error.code;item["message"]=error.what();}
        catch(const std::exception&) {item["status"]="error";item["code"]="dns_unavailable";item["message"]="The DNS lookup could not be completed. Check network access and retry.";}
        result["records"].push_back(std::move(item));
    };
    record("a",hostname,type_a,"A",ipv4,true);record("aaaa",hostname,type_aaaa,"AAAA",ipv6,true);
    record("mx",domain,type_mx,"MX",hostname);record("spf",domain,type_txt,"TXT",spf);
    record("dkim",dkim_name,dkim_type=="cname"?type_cname:type_txt,dkim_type=="cname"?"CNAME":"TXT",dkim_type=="cname"?canonical(dkim_value):dkim_value);
    record("dmarc","_dmarc."+domain,type_txt,"TXT",dmarc);
    return result;
}
}
