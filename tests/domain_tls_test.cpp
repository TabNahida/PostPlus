#include <postplus/domain_tls.hpp>
#include <postplus/settings.hpp>
#include <asio/ssl.hpp>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <fstream>
#include <iostream>
#include <thread>

using namespace postplus;
namespace {
namespace fs=std::filesystem;
template<class T,auto Free>using Owned=std::unique_ptr<T,decltype(Free)>;
// Older supported Apple libc++ versions do not provide std::jthread.
struct JoinThread {
    std::thread& thread;
    ~JoinThread(){if(thread.joinable())thread.join();}
};
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F>void rejects(int status,F call){try{call();}catch(const SettingsError& error){check(error.status==status,"unexpected TLS error status");return;}throw std::runtime_error("invalid TLS configuration accepted");}
void write(const fs::path& path,const std::string& value){std::ofstream file(path,std::ios::binary|std::ios::trunc);file<<value;check(file.good(),"cannot write TLS fixture");}
Json certificate(const fs::path& directory,const std::string& hostname,long duration=86400,const std::string& additional_san="") {
    Owned<EVP_PKEY,EVP_PKEY_free> key(EVP_PKEY_Q_keygen(nullptr,nullptr,"EC","P-256"),EVP_PKEY_free);
    Owned<X509,X509_free> cert(X509_new(),X509_free);check(key && cert,"cannot create TLS fixture");
    check(X509_set_version(cert.get(),2)==1 && ASN1_INTEGER_set(X509_get_serialNumber(cert.get()),1)==1,"cannot set TLS fixture identity");
    X509_gmtime_adj(X509_getm_notBefore(cert.get()),-3600);X509_gmtime_adj(X509_getm_notAfter(cert.get()),duration);
    auto* name=X509_get_subject_name(cert.get());
    check(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>(hostname.c_str()),-1,-1,0)==1,"cannot set TLS fixture name");
    check(X509_set_issuer_name(cert.get(),name)==1 && X509_set_pubkey(cert.get(),key.get())==1,"cannot set TLS fixture key");
    const auto san="DNS:"+hostname+(additional_san.empty()?"":","+additional_san);
    Owned<X509_EXTENSION,X509_EXTENSION_free> extension(X509V3_EXT_conf_nid(nullptr,nullptr,NID_subject_alt_name,san.c_str()),X509_EXTENSION_free);
    check(extension && X509_add_ext(cert.get(),extension.get(),-1)==1 && X509_sign(cert.get(),key.get(),EVP_sha256())>0,"cannot sign TLS fixture");
    const auto stem=hostname+"-"+random_hex(4);
    const auto cert_path=directory/(stem+".crt"),key_path=directory/(stem+".key");
    auto save=[&](const fs::path& path,bool secret){
        Owned<BIO,BIO_free> bio(BIO_new(BIO_s_mem()),BIO_free);check(static_cast<bool>(bio),"cannot allocate certificate fixture output");
        check((secret?PEM_write_bio_PrivateKey(bio.get(),key.get(),nullptr,nullptr,0,nullptr,nullptr):PEM_write_bio_X509(bio.get(),cert.get()))==1,"cannot encode certificate fixture");
        char* data=nullptr;const auto size=BIO_get_mem_data(bio.get(),&data);check(size>0,"certificate fixture empty");write(path,{data,static_cast<std::size_t>(size)});
    };
    save(cert_path,false);save(key_path,true);
    return {{"tls_certificate",cert_path.string()},{"tls_private_key",key_path.string()}};
}
std::string peer_hostname(const Config& config,const std::string& requested,bool expected_failure=false) {
    asio::io_context io;tcp::acceptor listener(io,{asio::ip::address_v4::loopback(),0});
    const auto endpoint=listener.local_endpoint();std::exception_ptr server_error;
    std::thread server([&]{try{Connection connection(std::chrono::seconds(5));listener.accept(connection.socket());connection.start_tls_server(config);connection.write("ok\r\n");}catch(...){server_error=std::current_exception();}});
    JoinThread join_server{server};
    std::string hostname;std::exception_ptr client_error;
    try {
        asio::ssl::context context(asio::ssl::context::tls_client);context.set_verify_mode(asio::ssl::verify_none);
        asio::ssl::stream<tcp::socket> client(io,context);client.lowest_layer().connect(endpoint);
        if(!requested.empty())check(SSL_set_tlsext_host_name(client.native_handle(),requested.c_str())==1,"cannot set SNI fixture");
        client.handshake(asio::ssl::stream_base::client);
        Owned<X509,X509_free> peer(SSL_get1_peer_certificate(client.native_handle()),X509_free);check(static_cast<bool>(peer),"server did not supply a certificate");
        char name[256]{};check(X509_NAME_get_text_by_NID(X509_get_subject_name(peer.get()),NID_commonName,name,sizeof(name))>0,"peer certificate name missing");hostname=name;
        std::array<char,4> response{};asio::read(client,asio::buffer(response));check(std::string(response.data(),response.size())=="ok\r\n","TLS session did not transfer data");
    }catch(...){client_error=std::current_exception();}
    server.join();
    if(expected_failure){check(client_error && server_error,"unreadable configured SNI certificate must fail the handshake");return {};}
    if(server_error)std::rethrow_exception(server_error);if(client_error)std::rethrow_exception(client_error);return hostname;
}
}
int main(){try {
    const auto directory=fs::temp_directory_path()/("postplus-domain-tls-"+random_hex(10));fs::create_directories(directory);
    const auto fallback=certificate(directory,"mail.example.com"),selected=certificate(directory,"inbox.example.net");
    Config network;network.values=fallback;network.values["domain_tls"]={{"inbox.example.net",selected}};
    check(peer_hostname(network,"inbox.example.net")=="inbox.example.net","SNI did not select its domain certificate");
    check(peer_hostname(network,"INBOX.EXAMPLE.NET.")=="inbox.example.net","SNI canonicalization failed");
    check(peer_hostname(network,"unknown.example.org")=="mail.example.com","unknown SNI must retain default certificate");
    check(peer_hostname(network,"")=="mail.example.com","clients without SNI must retain default certificate");
    auto missing=network;missing.values["domain_tls"]["inbox.example.net"]["tls_private_key"]=(directory/"missing.key").string();
    peer_hostname(missing,"inbox.example.net",true);
    check(peer_hostname(missing,"unknown.example.org")=="mail.example.com","broken unused domain certificate affected another hostname");
    std::cout<<"PASS actual TLS handshakes select SNI certificates, retain the no-SNI default and isolate broken domain credentials\n";

    const auto path=directory/"config.json",token=directory/"token";write(token,std::string(64,'b'));
    Json values={{"domain","example.com"},{"mail_domains",Json::array({"example.com","example.net"})},
        {"webmail_hostnames",{{"example.net","inbox.example.net"}}},{"admin_hostname","admin.example.com"},
        {"webmail_shared_hostname","login.example.com"},{"service_token_file",token.string()},
        {"data_dir",directory.string()},{"allow_insecure_auth",true},{"outbound_mode","disabled"}};
    write(path,values.dump(2)+"\n");auto config=Config::from_file(path);
    const auto listing=domain_tls_view(config,"example.net");
    check(listing.at("hostnames").size()==2,"domain view must include suffix and bound Webmail hostname");
    check(domain_tls_view(config,"example.com").at("hostnames").size()==4,"primary domain view must include mail/admin/shared service hosts");
    rejects(404,[&]{domain_tls_view(config,"unconfigured.example.org");});
    Json input={{"revision",listing.at("revision")},{"domain","example.net"},{"hostname","inbox.example.net"},
        {"tls_certificate",selected.at("tls_certificate")},{"tls_private_key",selected.at("tls_private_key")}};
    const auto saved=save_domain_tls(config,input);const auto first=Config::from_file(path);
    check(first.values.at("domain_tls").at("inbox.example.net")==selected,"per-host pair was not saved");
    check(first.text("tls_certificate")==selected.at("tls_certificate").get<std::string>(),"first certificate must establish a usable TLS default");
    check(saved.at("restart_required").get<bool>(),"certificate save must require public service restart");
    rejects(409,[&]{save_domain_tls(config,input);});input["revision"]=saved.at("revision");
    auto bad=input;bad["hostname"]="unconfigured.example.org";rejects(400,[&]{save_domain_tls(config,bad);});
    bad=input;bad["tls_certificate"]=fallback.at("tls_certificate");bad["tls_private_key"]=fallback.at("tls_private_key");rejects(400,[&]{save_domain_tls(config,bad);});
    bad=input;bad["tls_private_key"]=fallback.at("tls_private_key");rejects(400,[&]{save_domain_tls(config,bad);});
    bad=input;bad["tls_private_key"]="";rejects(400,[&]{save_domain_tls(config,bad);});
    const auto expired=certificate(directory,"inbox.example.net",-60);bad=input;bad.update(expired);rejects(400,[&]{save_domain_tls(config,bad);});
    check(domain_tls_view(config,"example.net").at("revision")==saved.at("revision"),"invalid pair changed configuration");
    const auto replacement=certificate(directory,"inbox.example.net");input.update(replacement);
    const auto renewed=save_domain_tls(config,input);const auto updated=Config::from_file(path);
    check(updated.values.at("domain_tls").at("inbox.example.net")==replacement &&
        updated.text("tls_certificate")==selected.at("tls_certificate").get<std::string>() &&
        updated.text("tls_private_key")==selected.at("tls_private_key").get<std::string>(),
        "renewing a hostname must preserve an existing shared default certificate and key");
    input["revision"]=renewed.at("revision");input["tls_certificate"]="";input["tls_private_key"]="";
    const auto removed=save_domain_tls(config,input);const auto after=Config::from_file(path);
    check(after.values.at("domain_tls").empty() && after.text("tls_certificate")==selected.at("tls_certificate").get<std::string>(),"removing an override must retain the working default certificate");
    check(removed.at("hostnames").at(1).at("inherited").get<bool>(),"removed certificate override must show inherited state");
    auto mail_input=fallback;mail_input["revision"]=removed.at("revision");mail_input["domain"]="example.com";mail_input["hostname"]="mail.example.com";
    save_domain_tls(config,mail_input);
    check(Config::from_file(path).text("tls_certificate")==selected.at("tls_certificate").get<std::string>(),"mail server certificate must not implicitly replace the no-SNI compatibility default");

    const auto shared=certificate(directory,"mail.example.com",86400,"DNS:admin.example.com");
    auto shared_values=values;shared_values.update(shared);shared_values["domain_tls"]={{"mail.example.com",shared}};
    write(path,shared_values.dump(2)+"\n");config=Config::from_file(path);
    mail_input["revision"]=domain_tls_view(config,"example.com").at("revision");
    save_domain_tls(config,mail_input);const auto preserved=Config::from_file(path);
    check(preserved.text("tls_certificate")==shared.at("tls_certificate").get<std::string>() &&
        preserved.text("tls_private_key")==shared.at("tls_private_key").get<std::string>() &&
        preserved.values.at("domain_tls").at("mail.example.com")==fallback,
        "replacing a mail hostname override must preserve the shared default's administration SAN");

    auto conflicting=values;conflicting["ports"]={{"admin",443}};
    const auto before_conflict=conflicting.dump(2)+"\n";write(path,before_conflict);config=Config::from_file(path);
    check(config.port("web")==80 && config.port("admin")==443,"first-TLS port conflict fixture must initially be valid");
    const auto conflict_revision=domain_tls_view(config,"example.com").at("revision");mail_input["revision"]=conflict_revision;
    rejects(400,[&]{save_domain_tls(config,mail_input);});
    const auto rejected=Config::from_file(path);
    check(domain_tls_view(config,"example.com").at("revision")==conflict_revision && rejected.text("tls_certificate").empty() &&
        !rejected.values.contains("domain_tls") && rejected.port("web")==80,
        "a first-TLS listener conflict must be rejected before modifying the saved configuration");
    auto relative=after;relative.values["domain_tls"]={{"inbox.example.net",{{"tls_certificate","server.crt"},{"tls_private_key","server.key"}}}};normalize_domain_tls(relative);
    check(relative.values.at("domain_tls").at("inbox.example.net").at("tls_certificate")== (directory/"server.crt").string(),"nested certificate paths must resolve against config directory");
    relative.values["domain_tls"]["inbox.example.net"]["tls_private_key"]="";rejects(400,[&]{normalize_domain_tls(relative);});
    std::cout<<"PASS domain certificate host scoping, revision conflicts, file/key/name/date validation, default preservation and atomic port-conflict rejection\n";
    fs::remove_all(directory);return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
