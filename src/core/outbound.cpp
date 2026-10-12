#include <postplus/outbound.hpp>
#include <algorithm>
#include <charconv>
#include <random>
#include <set>

namespace postplus {
namespace {
using Clock=std::chrono::steady_clock;
struct Exchange {unsigned preference;std::string hostname;bool implicit=false;};
struct Reply {int code=0;std::vector<std::string> lines;};
Reply reply(Connection& peer) {
    Reply result;std::size_t total=0;
    for(unsigned count=0;count<100;++count) {
        const auto line=peer.line(2048);total+=line.size();
        if(line.size()<4 || total>32768 || line[0]<'1' || line[0]>'5' || line[1]<'0' || line[1]>'9' || line[2]<'0' || line[2]>'9' || (line[3]!=' ' && line[3]!='-'))
            throw OutboundError("smtp_invalid_reply","The destination returned an invalid SMTP reply.");
        const int code=(line[0]-'0')*100+(line[1]-'0')*10+line[2]-'0';
        if(result.code && result.code!=code)throw OutboundError("smtp_invalid_reply","The destination changed status within an SMTP reply.");
        result.code=code;result.lines.push_back(line.substr(4));
        if(line[3]==' ')return result;
    }
    throw OutboundError("smtp_invalid_reply","The destination returned too many SMTP reply lines.");
}
bool capability(const Reply& response,std::string_view expected) {
    // The first EHLO line is the server identity, not a capability.
    for(std::size_t index=1;index<response.lines.size();++index) {
        const auto value=lower(trim(response.lines[index]));
        if(value.substr(0,value.find_first_of(" \t"))==expected)return true;
    }
    return false;
}
[[noreturn]] void status(const Reply& response,const std::string& stage,bool message_stage) {
    throw OutboundError(response.code>=500?"smtp_rejected":"smtp_temporary_failure",
        "Destination SMTP status "+std::to_string(response.code)+" during "+stage+".",message_stage && response.code>=500);
}
void expect(Connection& peer,int expected,const std::string& stage,bool message_stage=false,int alternative=0) {
    const auto response=reply(peer);
    if(response.code!=expected && response.code!=alternative)status(response,stage,message_stage);
}
std::string data(std::string_view raw,std::size_t maximum) {
    std::string escaped;escaped.reserve(raw.size()+256);bool beginning=true;std::size_t normalized=0;
    for(std::size_t index=0;index<raw.size();++index) {
        const char byte=raw[index];if(beginning && byte=='.')escaped+='.';
        if(byte=='\n'){if(index==0 || raw[index-1]!='\r'){escaped+='\r';++normalized;}escaped+='\n';beginning=true;}
        else {escaped+=byte;beginning=false;}
        if(++normalized>maximum)throw OutboundError("message_too_large","The signed and normalized message exceeds max_message_bytes.",true);
    }
    if(!escaped.ends_with("\r\n")){escaped+="\r\n";normalized+=2;}
    if(normalized>maximum)throw OutboundError("message_too_large","The signed and normalized message exceeds max_message_bytes.",true);
    return escaped;
}
void transaction(Connection& peer,const std::string& mx,const std::string& hostname,const std::string& tls,
                 const std::string& sender,const std::string& recipient,const std::string& escaped) {
    expect(peer,220,"greeting");peer.write("EHLO "+hostname+"\r\n");auto capabilities=reply(peer);
    bool ehlo=true;
    if(capabilities.code!=250) {
        if(tls=="starttls" && (capabilities.code==500 || capabilities.code==502 || capabilities.code==504)) {
            peer.write("HELO "+hostname+"\r\n");expect(peer,250,"HELO");ehlo=false;
        } else status(capabilities,"EHLO",false);
    }
    if(ehlo && capability(capabilities,"starttls")) {
        // An advertised but failed upgrade cannot become a plaintext delivery,
        // including on another MX in this attempt.
        try {
            peer.write("STARTTLS\r\n");expect(peer,220,"STARTTLS");peer.start_tls_client(mx);
            peer.write("EHLO "+hostname+"\r\n");expect(peer,250,"EHLO after STARTTLS");
        } catch(const std::exception&) {throw OutboundError("smtp_tls_failed","The destination STARTTLS negotiation or certificate verification failed; delivery was deferred.");}
    } else if(tls=="required") {
        throw OutboundError("smtp_tls_required","The destination does not offer required STARTTLS.");
    }
    peer.write("MAIL FROM:<"+sender+">\r\n");expect(peer,250,"MAIL FROM",true);
    peer.write("RCPT TO:<"+recipient+">\r\n");expect(peer,250,"RCPT TO",true,251);
    peer.write("DATA\r\n");expect(peer,354,"DATA",true);peer.write(escaped);
    Reply final;
    try {peer.write(".\r\n");final=reply(peer);}
    catch(const std::exception&) {throw OutboundError("delivery_unknown","The connection ended before final DATA acceptance could be confirmed; delivery was deferred.");}
    if(final.code!=250)status(final,"final DATA",true);
    // Acceptance is final. QUIT/disconnect failures must never queue a duplicate.
}
std::vector<Exchange> exchanges(const DnsResolver& resolver,const std::string& domain,Clock::time_point deadline) {
    const auto answer=resolver.lookup(domain,DnsType::mx,deadline);
    if(answer.nxdomain)throw OutboundError("dns_nxdomain","The recipient domain does not exist.",true);
    if(answer.values.empty())return {{0,answer.canonical_name.empty()?domain:answer.canonical_name,true}};
    if(answer.values.size()>32)throw OutboundError("dns_mx_limit","The destination publishes too many MX records.");
    std::vector<Exchange> result;
    for(const auto& value:answer.values) {
        const auto separator=value.find(' ');unsigned preference=0;
        if(separator==std::string::npos)throw OutboundError("dns_invalid_mx","The destination publishes an invalid MX record.");
        const auto converted=std::from_chars(value.data(),value.data()+separator,preference);
        auto host=value.substr(separator+1);
        if(converted.ec!=std::errc{} || converted.ptr!=value.data()+separator || preference>65535)
            throw OutboundError("dns_invalid_mx","The destination publishes an invalid MX preference.");
        if(host.empty() || host==".") {
            if(preference==0 && answer.values.size()==1)throw OutboundError("dns_null_mx","The recipient domain explicitly does not accept mail (null MX).",true);
            throw OutboundError("dns_invalid_mx","The destination publishes a conflicting or invalid null MX record.",true);
        }
        if(!valid_public_dns_name(host))throw OutboundError("dns_invalid_mx","The destination MX hostname is not a valid public name.");
        result.push_back({preference,std::move(host)});
    }
    unsigned seed=0;const auto random=random_hex(4);(void)std::from_chars(random.data(),random.data()+random.size(),seed,16);
    std::mt19937 generator(seed);std::shuffle(result.begin(),result.end(),generator);
    std::stable_sort(result.begin(),result.end(),[](const auto& left,const auto& right){return left.preference<right.preference;});
    return result;
}
std::vector<asio::ip::address> addresses(const DnsResolver& resolver,const std::string& host,Clock::time_point deadline,bool implicit) {
    std::vector<asio::ip::address> result;std::optional<DnsError> failure;bool any_answer=false,blocked=false;
    for(const auto type:{DnsType::a,DnsType::aaaa}) {
        try {
            const auto answer=resolver.lookup(host,type,deadline);any_answer=true;
            if(answer.alias && !implicit)throw OutboundError("dns_mx_alias","An explicit MX target must publish direct A or AAAA records rather than a CNAME alias.");
            for(const auto& value:answer.values) {
                std::error_code error;const auto address=asio::ip::make_address(value,error);
                if(error || !is_public_mail_address(address)){blocked=true;continue;}
                if(std::find(result.begin(),result.end(),address)==result.end())result.push_back(address);
            }
        } catch(const DnsError& issue) {failure=issue;}
    }
    if(result.size()>16)result.resize(16);
    if(result.empty()) {
        if(blocked)throw OutboundError("dns_private_destination","The destination resolves only to unsafe or non-public addresses.");
        if(!any_answer && failure)throw *failure;
        throw OutboundError("dns_no_address","The destination has no usable public A or AAAA address.");
    }
    return result;
}
}
void deliver_direct(const Config& config,const std::string& sender,const std::string& recipient,std::string_view raw,OutboundOptions options) {
    if((!sender.empty() && !valid_address(sender)) || !valid_address(recipient))throw OutboundError("invalid_envelope","Invalid message envelope.",true);
    const auto configured_domain=lower(config.text("domain"));
    if(!sender.empty() && lower(sender.substr(sender.rfind('@')+1))!=configured_domain)
        throw OutboundError("sender_domain_mismatch","Direct delivery requires the envelope sender to belong to the configured mail domain.",true);
    const auto domain=lower(recipient.substr(recipient.rfind('@')+1));
    if(!valid_public_dns_name(domain))throw OutboundError("dns_invalid_name","The recipient needs a public mail domain.",true);
    const auto hostname=lower(config.text("mail_hostname","mail."+config.text("domain")));
    if(!valid_public_dns_name(hostname))throw OutboundError("invalid_mail_hostname","Direct delivery requires a public mail_hostname.",true);
    const auto budget=config.number("direct_timeout_seconds",120),operation_timeout=config.number("timeout_seconds",30);
    const auto maximum=config.number("max_message_bytes",10485760);
    const auto tls=config.text("direct_tls","starttls");
    if(budget<1 || budget>300 || operation_timeout<1 || operation_timeout>300 || maximum<1024 || maximum>104857600 || (tls!="starttls" && tls!="required"))
        throw OutboundError("invalid_outbound_config","Invalid direct delivery timeout, message size limit, or TLS mode.",true);
    if(raw.size()>static_cast<std::size_t>(maximum))throw OutboundError("message_too_large","The signed message exceeds max_message_bytes.",true);
    const auto deadline=Clock::now()+std::chrono::seconds(budget);const auto escaped=data(raw,static_cast<std::size_t>(maximum));
    options.dns.timeout=std::chrono::seconds(std::min(budget,15));DnsResolver resolver(std::move(options.dns));
    try {
        const auto hosts=exchanges(resolver,domain,deadline);OutboundError last("smtp_unavailable","No destination MX accepted the message.");unsigned attempts=0;
        for(std::size_t index=0;index<hosts.size();++index) {
            if(Clock::now()>=deadline)throw OutboundError("delivery_timeout","Direct delivery reached its total time limit.");
            const auto& host=hosts[index].hostname;std::vector<asio::ip::address> destinations;
            try {destinations=addresses(resolver,host,deadline,hosts[index].implicit);}
            catch(const DnsError& error){last=OutboundError(error.code,error.what());continue;}
            catch(const OutboundError& error){last=error;continue;}
            for(const auto& address:destinations) {
                if(++attempts>32)throw OutboundError("delivery_attempt_limit","Direct delivery reached its destination attempt limit.");
                Connection peer{std::chrono::seconds(operation_timeout)};
                // Reserve time for alternate MX hosts and cap one dead endpoint.
                const auto now=Clock::now();const auto remaining=deadline-now;
                if(remaining<=Clock::duration::zero())throw OutboundError("delivery_timeout","Direct delivery reached its total time limit.");
                const auto slice=std::min(remaining/static_cast<Clock::duration::rep>(hosts.size()-index),std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(30)));
                peer.set_deadline(now+slice);
                try {
                    const tcp::endpoint endpoint(address,25);
                    if(options.connect)options.connect(peer,endpoint,host);else peer.connect(endpoint);
                    transaction(peer,host,hostname,tls,sender,recipient,escaped);return;
                } catch(const OutboundError& error) {
                    if(error.permanent || error.code=="smtp_tls_failed" || error.code=="delivery_unknown")throw;
                    last=error;
                } catch(const std::exception&) {last=OutboundError("smtp_connection_failed","Cannot connect to or complete SMTP with destination MX "+host+".");}
            }
        }
        if(Clock::now()>=deadline)throw OutboundError("delivery_timeout","Direct delivery reached its total time limit.");
        throw last;
    } catch(const DnsError& error) {throw OutboundError(error.code,error.what());}
}
}
