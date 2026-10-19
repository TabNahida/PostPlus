#include <postplus/outbound.hpp>
#include <postplus/dkim.hpp>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <map>
#include <thread>

using namespace postplus;
namespace {
using Clock=std::chrono::steady_clock;using Bytes=std::vector<unsigned char>;
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
void number(Bytes& data,unsigned value){data.push_back(static_cast<unsigned char>(value>>8));data.push_back(static_cast<unsigned char>(value));}
void name(Bytes& data,const std::string& value){std::size_t begin=0;while(begin<value.size()){const auto dot=value.find('.',begin),end=dot==std::string::npos?value.size():dot;data.push_back(static_cast<unsigned char>(end-begin));data.insert(data.end(),value.begin()+begin,value.begin()+end);begin=end+1;}data.push_back(0);}
struct DnsFixture {
    std::map<std::pair<std::string,unsigned>,std::vector<Bytes>> rows;
    std::map<std::string,unsigned> rcodes;unsigned requests=0,tcp_requests=0;bool truncate=false;
    static Bytes mx(unsigned priority,const std::string& host){Bytes data;number(data,priority);name(data,host);return data;}
    static Bytes address(const std::string& value){const auto parsed=asio::ip::make_address(value);if(parsed.is_v4()){const auto data=parsed.to_v4().to_bytes();return {data.begin(),data.end()};}const auto data=parsed.to_v6().to_bytes();return {data.begin(),data.end()};}
    Bytes send(const Bytes& question,bool tcp=false) {
        if(tcp)++tcp_requests;else ++requests;
        std::size_t position=12;std::string owner;
        while(question.at(position)){const auto size=question.at(position++);if(!owner.empty())owner+='.';owner.append(reinterpret_cast<const char*>(question.data()+position),size);position+=size;}
        ++position;const unsigned type=(question.at(position)<<8)|question.at(position+1);position+=4;
        const auto found=rows.find({owner,type}),alias=rows.find({owner,5});
        const std::vector<Bytes> empty;const auto& values=found==rows.end()?empty:found->second;
        const bool use_alias=type!=5 && alias!=rows.end();
        const unsigned flags=0x8180|rcodes[owner]|(truncate && !tcp?0x0200:0);
        Bytes result{question[0],question[1]};number(result,flags);number(result,1);
        number(result,static_cast<unsigned>(values.size())+(use_alias?static_cast<unsigned>(alias->second.size()):0));number(result,0);number(result,0);
        result.insert(result.end(),question.begin()+12,question.begin()+position);
        auto append=[&](unsigned record_type,const Bytes& data){number(result,0xc00c);number(result,record_type);number(result,1);result.insert(result.end(),{0,0,0,60});number(result,static_cast<unsigned>(data.size()));result.insert(result.end(),data.begin(),data.end());};
        if(use_alias)for(const auto& data:alias->second)append(5,data);
        for(const auto& data:values)append(type,data);
        return result;
    }
    DnsOptions options(){DnsOptions result;result.transport=[this](const auto& wire,auto){return send(wire);};result.tcp_transport=[this](const auto& wire,auto){return send(wire,true);};return result;}
    void standard(){rows[{"example.net",15}]={mx(10,"mx1.example.net")};rows[{"mx1.example.net",1}]={address("93.184.216.34")};}
};
Config config(){Config result;result.values={{"domain","example.com"},{"mail_hostname","mail.example.com"},{"timeout_seconds",2},{"direct_timeout_seconds",5},{"direct_tls","starttls"}};return result;}
const std::string raw="From: alice@example.com\r\nTo: bob@example.net\r\nSubject: test\r\n\r\n.leading\nlast";
template<class F>void rejects(F call,const std::string& code,bool permanent=false){try{call();}catch(const OutboundError& error){if(error.code!=code)throw std::runtime_error("Expected "+code+", got "+error.code+": "+error.what());check(error.permanent==permanent,"wrong outbound error permanence");return;}throw std::runtime_error("outbound failure was accepted");}
class Server {
    asio::io_context io_;tcp::acceptor acceptor_{io_,{asio::ip::make_address("127.0.0.1"),0}};
    std::thread thread_;std::atomic<bool> stop_{false};std::exception_ptr failure_;
public:
    template<class F>explicit Server(F handler){acceptor_.non_blocking(true);thread_=std::thread([this,handler]{try{Connection peer{std::chrono::seconds(2)};const auto deadline=Clock::now()+std::chrono::seconds(5);for(;;){std::error_code error;acceptor_.accept(peer.socket(),error);if(!error)break;if(error!=asio::error::would_block && error!=asio::error::try_again)throw std::system_error(error);if(stop_ || Clock::now()>=deadline)return;std::this_thread::sleep_for(std::chrono::milliseconds(5));}peer.set_deadline(Clock::now()+std::chrono::seconds(5));handler(peer);}catch(...){failure_=std::current_exception();}});}
    ~Server(){stop_=true;if(thread_.joinable())thread_.join();}
    int port()const{return acceptor_.local_endpoint().port();}
    void finish(){if(thread_.joinable())thread_.join();if(failure_)std::rethrow_exception(failure_);}
};
void greet(Connection& peer,const std::string& capability="") {
    peer.write("220 destination ready\r\n");check(peer.line()=="EHLO mail.example.com","wrong direct EHLO hostname");
    peer.write(capability.empty()?"250 destination\r\n":"250-destination\r\n250 "+capability+"\r\n");
}
void mail(Connection& peer,int recipient_status=250,int final_status=250,bool lose_final=false) {
    check(peer.line()=="MAIL FROM:<alice@example.com>","wrong direct sender");peer.write("250 sender\r\n");
    check(peer.line()=="RCPT TO:<bob@example.net>","wrong direct recipient");peer.write(std::to_string(recipient_status)+" recipient\r\n");
    if(recipient_status!=250 && recipient_status!=251)return;
    check(peer.line()=="DATA","missing direct DATA");peer.write("354 message\r\n");std::string body;
    for(;;){const auto line=peer.line();if(line==".")break;body+=line+"\r\n";}
    check(body=="From: alice@example.com\r\nTo: bob@example.net\r\nSubject: test\r\n\r\n..leading\r\nlast\r\n","direct dot stuffing or CRLF normalization changed");
    if(lose_final)return;
    peer.write(std::to_string(final_status)+" queued\r\n");
    // Force an immediate disconnect after acceptance; no QUIT is required.
}
std::string capture(Connection& peer,const std::string& sender="alice@example.com") {
    check(peer.line()=="MAIL FROM:<"+sender+">","wrong signed/null envelope sender");peer.write("250 sender\r\n");
    check(peer.line()=="RCPT TO:<bob@example.net>","wrong signed DATA recipient");peer.write("250 recipient\r\n");
    check(peer.line()=="DATA","missing signed DATA");peer.write("354 message\r\n");std::string received;
    for(;;){auto line=peer.line();if(line==".")break;if(line.starts_with(".."))line.erase(0,1);received+=line+"\r\n";}
    peer.write("250 accepted\r\n");return received;
}
OutboundOptions options(DnsFixture& dns,Server& server,std::vector<std::string>* tried=nullptr){OutboundOptions result;result.dns=dns.options();result.connect=[&server,tried](Connection& peer,const tcp::endpoint& endpoint,const std::string& host){check(is_public_mail_address(endpoint.address()) && endpoint.port()==25,"non-public destination passed to connector");if(tried)tried->push_back(host);peer.connect({asio::ip::make_address("127.0.0.1"),static_cast<unsigned short>(server.port())});};return result;}
void deliver(const Config& settings,OutboundOptions opts){deliver_direct(settings,"alice@example.com","bob@example.net",raw,std::move(opts));}
void environment(const char* key,const std::string& value){
#ifdef _WIN32
    if(value.empty())_putenv_s(key,"");else _putenv_s(key,value.c_str());
#else
    if(value.empty())unsetenv(key);else setenv(key,value.c_str(),1);
#endif
}
struct Certificate {
    std::filesystem::path directory=std::filesystem::temp_directory_path()/("postplus-outbound-test-"+random_hex(8));
    std::string old_trust;bool had_trust=false;
    Certificate(){if(const char* value=std::getenv("SSL_CERT_FILE")){old_trust=value;had_trust=true;}std::filesystem::create_directories(directory);
        std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr),EVP_PKEY_CTX_free);check(context && EVP_PKEY_keygen_init(context.get())==1 && EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(),2048)==1,"test RSA setup failed");
        EVP_PKEY* generated=nullptr;check(EVP_PKEY_keygen(context.get(),&generated)==1,"test key generation failed");std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(generated,EVP_PKEY_free);
        std::unique_ptr<X509,decltype(&X509_free)> certificate(X509_new(),X509_free);check(static_cast<bool>(certificate),"test certificate creation failed");
        X509_set_version(certificate.get(),2);ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()),1);X509_gmtime_adj(X509_getm_notBefore(certificate.get()),-3600);X509_gmtime_adj(X509_getm_notAfter(certificate.get()),86400);X509_set_pubkey(certificate.get(),key.get());
        auto* subject=X509_get_subject_name(certificate.get());X509_NAME_add_entry_by_txt(subject,"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>("mx1.example.net"),-1,-1,0);X509_set_issuer_name(certificate.get(),subject);
        X509V3_CTX extension_context;X509V3_set_ctx(&extension_context,certificate.get(),certificate.get(),nullptr,nullptr,0);
        for(const auto& item:std::vector<std::pair<int,std::string>>{{NID_basic_constraints,"critical,CA:TRUE"},{NID_key_usage,"critical,digitalSignature,keyEncipherment,keyCertSign"},{NID_subject_alt_name,"DNS:mx1.example.net"}}){std::unique_ptr<X509_EXTENSION,decltype(&X509_EXTENSION_free)> extension(X509V3_EXT_conf_nid(nullptr,&extension_context,item.first,const_cast<char*>(item.second.c_str())),X509_EXTENSION_free);check(extension && X509_add_ext(certificate.get(),extension.get(),-1)==1,"test certificate extension failed");}
        check(X509_sign(certificate.get(),key.get(),EVP_sha256())>0,"test certificate signing failed");
        auto save=[&](const std::string& filename,auto writer){std::unique_ptr<BIO,decltype(&BIO_free)> buffer(BIO_new(BIO_s_mem()),BIO_free);check(buffer && writer(buffer.get())==1,"test PEM creation failed");char* bytes=nullptr;const auto size=BIO_get_mem_data(buffer.get(),&bytes);std::ofstream output(directory/filename,std::ios::binary);output.write(bytes,size);check(static_cast<bool>(output),"test PEM write failed");};
        save("certificate.pem",[&](BIO* bio){return PEM_write_bio_X509(bio,certificate.get());});save("private.pem",[&](BIO* bio){return PEM_write_bio_PrivateKey(bio,key.get(),nullptr,nullptr,0,nullptr,nullptr);});
    }
    ~Certificate(){environment("SSL_CERT_FILE",had_trust?old_trust:"");std::filesystem::remove_all(directory);}
    Config server()const{Config result;result.values={{"tls_certificate",(directory/"certificate.pem").string()},{"tls_private_key",(directory/"private.pem").string()}};return result;}
    void trust()const{environment("SSL_CERT_FILE",(directory/"certificate.pem").string());}
};
}
int main(){try {
    // Wire-level DNS fixtures exercise fallback and bounded alias following.
    DnsFixture dns;dns.standard();dns.truncate=true;DnsResolver resolver(dns.options());
    auto lookup=resolver.lookup("example.net",DnsType::mx,Clock::now()+std::chrono::seconds(5));check(lookup.values==std::vector<std::string>{"10 mx1.example.net"} && dns.tcp_requests==1,"truncated DNS did not use TCP fallback");dns.truncate=false;
    dns.rcodes["absent.example.net"]=3;lookup=resolver.lookup("absent.example.net",DnsType::mx,Clock::now()+std::chrono::seconds(5));check(lookup.nxdomain,"NXDOMAIN was not distinct from NODATA");lookup=resolver.lookup("empty.example.net",DnsType::mx,Clock::now()+std::chrono::seconds(5));check(!lookup.nxdomain && lookup.values.empty(),"NODATA was reported as NXDOMAIN");
    Bytes alias;name(alias,"mx1.example.net");dns.rows[{"alias.example.net",5}]={alias};lookup=resolver.lookup("alias.example.net",DnsType::a,Clock::now()+std::chrono::seconds(5));check(lookup.alias && lookup.values==std::vector<std::string>{"93.184.216.34"} && lookup.alias_hops==1,"cross-packet CNAME follow-up failed");
    Bytes loop;name(loop,"loop2.example.net");dns.rows[{"loop1.example.net",5}]={loop};loop.clear();name(loop,"loop1.example.net");dns.rows[{"loop2.example.net",5}]={loop};bool loop_failed=false;try{resolver.lookup("loop1.example.net",DnsType::a,Clock::now()+std::chrono::seconds(5));}catch(const DnsError&){loop_failed=true;}check(loop_failed,"DNS alias loop was unbounded");
    for(const auto& value:{"127.0.0.1","10.0.0.1","100.64.0.1","169.254.1.1","192.168.1.1","192.88.99.1","198.51.100.1","::ffff:127.0.0.1","2002:7f00:1::1","2001:0:1234::1","2001:db8::1","3fff::1"})check(!is_public_mail_address(asio::ip::make_address(value)),"unsafe mail destination accepted");
    // A production destination is always validated before a native test hook.
    auto settings=config();
    {auto multiple=settings;multiple.values["additional_domains"]=Json::array({"example.org"});DnsFixture fixture;fixture.standard();std::string received;Server server([&](Connection& peer){greet(peer);received=capture(peer,"alice@example.org");});deliver_direct(multiple,"alice@example.org","bob@example.net",raw,options(fixture,server));server.finish();check(!received.empty(),"hosted secondary envelope sender was rejected");}
    {DnsFixture fixture;fixture.standard();OutboundOptions opts;opts.dns=fixture.options();bool connected=false;opts.connect=[&](auto&,const auto&,const auto&){connected=true;};rejects([&]{deliver_direct(settings,"alice@foreign.example.org","bob@example.net",raw,opts);},"sender_domain_mismatch",true);check(!connected && fixture.requests==0,"foreign envelope sender reached DNS or connector");}
    {DnsFixture fixture;fixture.standard();OutboundOptions opts;opts.dns=fixture.options();auto limited=settings;limited.values["max_message_bytes"]=1024;
        for(const auto& message:{std::string(1025,'x'),std::string(700,'\n'),std::string(1023,'x')})rejects([&]{deliver_direct(limited,"alice@example.com","bob@example.net",message,opts);},"message_too_large",true);
        check(fixture.requests==0,"oversize raw, LF normalization or final CRLF reached DNS");}
    {const auto key=generate_dkim_key();const auto signed_message=dkim_sign(raw,"example.com","postplus",key.private_pem);DnsFixture fixture;fixture.standard();std::string received;Server server([&](Connection& peer){greet(peer);received=capture(peer);});deliver_direct(settings,"alice@example.com","bob@example.net",signed_message,options(fixture,server));server.finish();check(received==signed_message && received.starts_with("DKIM-Signature:"),"SMTP DATA changed the signed headers/body after unstuffing");
        auto limited=settings;limited.values["max_message_bytes"]=1024;const auto signed_large=dkim_sign(raw+std::string(700,'x'),"example.com","postplus",key.private_pem);OutboundOptions opts;opts.dns=fixture.options();const auto before=fixture.requests;rejects([&]{deliver_direct(limited,"alice@example.com","bob@example.net",signed_large,opts);},"message_too_large",true);check(fixture.requests==before,"DKIM header expansion exceeded the limit after DNS");}
    {DnsFixture fixture;fixture.standard();std::string received;Server server([&](Connection& peer){greet(peer);received=capture(peer,"");});deliver_direct(settings,"","bob@example.net",raw,options(fixture,server));server.finish();check(received=="From: alice@example.com\r\nTo: bob@example.net\r\nSubject: test\r\n\r\n.leading\r\nlast\r\n","null reverse-path delivery or body changed");}
    {DnsFixture fixture;fixture.standard();Server server([](Connection& peer){greet(peer);mail(peer,251);});deliver(settings,options(fixture,server));server.finish();}
    {DnsFixture fixture;fixture.standard();fixture.rows[{"example.net",15}]={DnsFixture::mx(0,"")};OutboundOptions opts;opts.dns=fixture.options();rejects([&]{deliver(settings,opts);},"dns_null_mx",true);}
    {DnsFixture fixture;fixture.standard();fixture.rcodes["example.net"]=3;OutboundOptions opts;opts.dns=fixture.options();rejects([&]{deliver(settings,opts);},"dns_nxdomain",true);}
    {DnsFixture fixture;fixture.rows[{"example.net",1}]={DnsFixture::address("93.184.216.34")};std::vector<std::string> tried;Server server([](Connection& peer){greet(peer);mail(peer);});deliver(settings,options(fixture,server,&tried));server.finish();check(tried==std::vector<std::string>{"example.net"},"MX NODATA did not fall back to recipient domain address");}
    {DnsFixture fixture;fixture.standard();Bytes target;name(target,"target.example.net");fixture.rows.erase({"mx1.example.net",1});fixture.rows[{"mx1.example.net",5}]={target};fixture.rows[{"target.example.net",1}]={DnsFixture::address("93.184.216.34")};OutboundOptions opts;opts.dns=fixture.options();bool connected=false;opts.connect=[&](auto&,const auto&,const auto&){connected=true;};rejects([&]{deliver(settings,opts);},"dns_mx_alias");check(!connected,"explicit MX alias reached connector");}
    {DnsFixture fixture;Bytes target;name(target,"target.example.net");fixture.rows[{"example.net",5}]={target};fixture.rows[{"target.example.net",1}]={DnsFixture::address("93.184.216.34")};Server server([](Connection& peer){greet(peer);mail(peer);});deliver(settings,options(fixture,server));server.finish();}
    {DnsFixture fixture;fixture.standard();fixture.rows[{"mx1.example.net",1}]={DnsFixture::address("127.0.0.1")};OutboundOptions opts;opts.dns=fixture.options();bool connected=false;opts.connect=[&](auto&,const auto&,const auto&){connected=true;};rejects([&]{deliver(settings,opts);},"dns_private_destination");check(!connected,"private destination reached test connector");}
    {DnsFixture fixture;fixture.standard();fixture.rows[{"example.net",15}]={DnsFixture::mx(20,"mx2.example.net"),DnsFixture::mx(10,"mx1.example.net")};fixture.rows[{"mx2.example.net",1}]={DnsFixture::address("93.184.216.35")};std::vector<std::string> tried;Server first([](Connection& peer){peer.write("550 server unavailable\r\n");});Server second([](Connection& peer){greet(peer);mail(peer);});auto opts=options(fixture,second,&tried);opts.connect=[&](Connection& peer,const tcp::endpoint&,const std::string& host){tried.push_back(host);peer.connect({asio::ip::make_address("127.0.0.1"),static_cast<unsigned short>(host=="mx1.example.net"?first.port():second.port())});};deliver(settings,std::move(opts));first.finish();second.finish();check(tried==std::vector<std::string>{"mx1.example.net","mx2.example.net"},"MX priority or greeting 5xx failover failed");}
    for(const int status:{450,550}){DnsFixture fixture;fixture.standard();Server server([status](Connection& peer){greet(peer);mail(peer,status);});auto opts=options(fixture,server);rejects([&]{deliver(settings,opts);},status==550?"smtp_rejected":"smtp_temporary_failure",status==550);server.finish();}
    {DnsFixture fixture;fixture.standard();Server server([](Connection& peer){greet(peer);mail(peer,250,550);});auto opts=options(fixture,server);rejects([&]{deliver(settings,opts);},"smtp_rejected",true);server.finish();}
    {DnsFixture fixture;fixture.standard();fixture.rows[{"example.net",15}].push_back(DnsFixture::mx(20,"mx2.example.net"));fixture.rows[{"mx2.example.net",1}]={DnsFixture::address("93.184.216.35")};unsigned attempts=0;Server server([](Connection& peer){greet(peer);mail(peer,250,250,true);});auto opts=options(fixture,server);const auto connector=opts.connect;opts.connect=[&](auto& peer,const auto& endpoint,const auto& host){++attempts;connector(peer,endpoint,host);};rejects([&]{deliver(settings,opts);},"delivery_unknown");server.finish();check(attempts==1,"unconfirmed final DATA was retried against a second MX");}
    {DnsFixture fixture;fixture.standard();Server server([](Connection& peer){greet(peer,"XSTARTTLS");mail(peer);});deliver(settings,options(fixture,server));server.finish();}
    {DnsFixture fixture;fixture.standard();Server server([](Connection& peer){greet(peer);});auto required=settings;required.values["direct_tls"]="required";auto opts=options(fixture,server);rejects([&]{deliver(required,opts);},"smtp_tls_required");server.finish();}
    {DnsFixture fixture;fixture.standard();Server server([](Connection& peer){peer.write("220 destination\r\n");check(peer.line().starts_with("EHLO "),"missing EHLO before HELO");peer.write("502 EHLO unsupported\r\n");check(peer.line()=="HELO mail.example.com","HELO fallback failed");peer.write("250 hello\r\n");mail(peer);});deliver(settings,options(fixture,server));server.finish();}
    {DnsFixture fixture;fixture.standard();Server server([](Connection& peer){peer.write("220 destination\r\n");peer.line();peer.write("250-destination\r\n550 different\r\n");});auto opts=options(fixture,server);rejects([&]{deliver(settings,opts);},"smtp_invalid_reply");server.finish();}
    {DnsFixture fixture;fixture.standard();Server server([](Connection& peer){greet(peer,"STARTTLS");check(peer.line()=="STARTTLS","missing advertised TLS upgrade");peer.write("454 TLS unavailable\r\n");});auto opts=options(fixture,server);rejects([&]{deliver(settings,opts);},"smtp_tls_failed");server.finish();}
    // Actual loopback TLS uses a generated test root, a public MX hostname and
    // the production hostname verification path. No external mail is sent.
    Certificate certificate;certificate.trust();
    {DnsFixture fixture;fixture.standard();Server server([&](Connection& peer){greet(peer,"STARTTLS");check(peer.line()=="STARTTLS","missing TLS command");peer.write("220 ready\r\n");peer.start_tls_server(certificate.server());check(peer.encrypted(),"test TLS did not activate");check(peer.line()=="EHLO mail.example.com","missing EHLO after TLS");peer.write("250 encrypted\r\n");mail(peer);});auto required=settings;required.values["direct_tls"]="required";deliver(required,options(fixture,server));server.finish();}
    {DnsFixture fixture;fixture.rows[{"example.net",15}]={DnsFixture::mx(10,"mx2.example.net"),DnsFixture::mx(20,"mx3.example.net")};fixture.rows[{"mx2.example.net",1}]={DnsFixture::address("93.184.216.34")};fixture.rows[{"mx3.example.net",1}]={DnsFixture::address("93.184.216.35")};unsigned attempts=0;Server server([&](Connection& peer){greet(peer,"STARTTLS");check(peer.line()=="STARTTLS","missing TLS command");peer.write("220 ready\r\n");try{peer.start_tls_server(certificate.server());}catch(const std::exception&){};});auto opts=options(fixture,server);const auto connector=opts.connect;opts.connect=[&](auto& peer,const auto& endpoint,const auto& host){++attempts;connector(peer,endpoint,host);};rejects([&]{deliver(settings,opts);},"smtp_tls_failed");server.finish();check(attempts==1,"TLS hostname failure downgraded via another MX");}
    environment("SSL_CERT_FILE","");
    {DnsFixture fixture;fixture.standard();Server server([&](Connection& peer){greet(peer,"STARTTLS");peer.line();peer.write("220 ready\r\n");try{peer.start_tls_server(certificate.server());}catch(const std::exception&){};});auto opts=options(fixture,server);rejects([&]{deliver(settings,opts);},"smtp_tls_failed");server.finish();}
    {DnsFixture fixture;fixture.standard();Server server([](Connection&){std::this_thread::sleep_for(std::chrono::milliseconds(1300));});auto limited=settings;limited.values["direct_timeout_seconds"]=1;const auto start=Clock::now();auto opts=options(fixture,server);rejects([&]{deliver(limited,opts);},"delivery_timeout");check(Clock::now()-start>=std::chrono::milliseconds(900) && Clock::now()-start<std::chrono::milliseconds(1250),"direct total transaction timeout exceeded its budget");server.finish();}
    std::cout<<"PASS offline DNS TCP/CNAME/NXDOMAIN, public destinations, MX ordering/failover, SMTP status/DATA acceptance, TLS verification/no downgrade and transaction deadlines\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
