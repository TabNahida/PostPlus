#include <postplus/acme.hpp>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

using namespace postplus;
namespace {
namespace fs=std::filesystem;
template<class T,auto Free> using Owned=std::unique_ptr<T,decltype(Free)>;
using Key=Owned<EVP_PKEY,EVP_PKEY_free>;
using Cert=Owned<X509,X509_free>;
using Bio=Owned<BIO,BIO_free>;
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F> void rejects(F function,const std::string& expected) {
    try{function();}catch(const AcmeError& error){check(error.code==expected,"unexpected ACME error code");return;}
    throw std::runtime_error("unsafe ACME request was accepted");
}
std::string encode(std::string_view input){auto value=base64_encode(input);while(value.ends_with('='))value.pop_back();std::replace(value.begin(),value.end(),'+','-');std::replace(value.begin(),value.end(),'/','_');return value;}
std::string decode(std::string value){std::replace(value.begin(),value.end(),'-','+');std::replace(value.begin(),value.end(),'_','/');while(value.size()%4)value+='=';return base64_decode(value);}
std::string digest(const std::string& input){unsigned char value[32];unsigned int size=0;check(EVP_Digest(input.data(),input.size(),value,&size,EVP_sha256(),nullptr)==1 && size==32,"SHA-256 failed");return encode({reinterpret_cast<char*>(value),32});}
std::string contents(const fs::path& path){std::ifstream file(path,std::ios::binary);check(static_cast<bool>(file),"missing certificate file");return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};}
std::string pem(X509* value){Bio bio(BIO_new(BIO_s_mem()),BIO_free);check(bio && PEM_write_bio_X509(bio.get(),value)==1,"PEM encoding failed");char* data=nullptr;const auto count=BIO_get_mem_data(bio.get(),&data);return {data,static_cast<std::size_t>(count)};}
void extension(X509* certificate,X509* issuer,int nid,const std::string& value){X509V3_CTX context{};X509V3_set_ctx(&context,issuer,certificate,nullptr,nullptr,0);Owned<X509_EXTENSION,X509_EXTENSION_free> result(X509V3_EXT_conf_nid(nullptr,&context,nid,value.c_str()),X509_EXTENSION_free);check(result && X509_add_ext(certificate,result.get(),-1)==1,"certificate extension failed");}

class MockCa {
public:
    std::string origin="http://127.0.0.1:19090",domain="mail.example.test",email="operator@example.test";
    const std::string terms="https://localhost/terms.pdf";
    std::string token="mock_http01_token_with_128_bits_123456",chain,account_jwk;
    Key ca_key{EVP_PKEY_Q_keygen(nullptr,nullptr,"EC","P-256"),EVP_PKEY_free};
    Cert ca{X509_new(),X509_free};
    Key account{nullptr,EVP_PKEY_free};
    AcmeManager* manager=nullptr;
    int challenge_port=0;
    bool bad_nonce_once=true,challenged=false,finalized=false,challenge_fail=false,wrong_domain=false,cross_origin=false,hang=false,terms_changed=false;
    std::atomic<int> requests{0},post_as_get{0};
    std::mutex mutex;
    std::set<std::string> nonces;
    MockCa(){
        check(ca_key && ca,"mock CA allocation failed");
        check(X509_set_version(ca.get(),2)==1 && ASN1_INTEGER_set(X509_get_serialNumber(ca.get()),1)==1,"mock CA identity failed");
        X509_gmtime_adj(X509_getm_notBefore(ca.get()),-3600);X509_gmtime_adj(X509_getm_notAfter(ca.get()),365*86400L);
        auto* name=X509_get_subject_name(ca.get());check(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>("PostPlus offline ACME test CA"),-1,-1,0)==1,"mock CA subject failed");
        check(X509_set_issuer_name(ca.get(),name)==1 && X509_set_pubkey(ca.get(),ca_key.get())==1,"mock CA key failed");
        extension(ca.get(),ca.get(),NID_basic_constraints,"critical,CA:TRUE");extension(ca.get(),ca.get(),NID_key_usage,"critical,keyCertSign,cRLSign");extension(ca.get(),ca.get(),NID_subject_key_identifier,"hash");
        check(X509_sign(ca.get(),ca_key.get(),EVP_sha256())>0,"mock CA signing failed");
    }
    Json order()const{
        Json value={{"status",finalized?"valid":challenged && !hang?"ready":"pending"},{"identifiers",Json::array({{{"type","dns"},{"value",domain}}})},{"authorizations",Json::array({origin+"/authorization/1"})},{"finalize",origin+"/finalize/1"}};
        if(finalized)value["certificate"]=origin+"/certificate/1";
        return value;
    }
    AcmeHttpResponse reply(int status,const Json& value,std::string location="") {
        AcmeHttpResponse result{status,{},value.dump()};
        const auto nonce=random_hex(24);nonces.insert(nonce);result.headers["replay-nonce"]=nonce;
        if(!location.empty())result.headers["location"]=std::move(location);
        result.headers["retry-after"]="1";return result;
    }
    void import_jwk(const Json& jwk) {
        check(jwk.size()==4 && jwk.at("crv")=="P-256" && jwk.at("kty")=="EC","account JWK is not canonical P-256");
        const auto x=decode(jwk.at("x")),y=decode(jwk.at("y"));check(x.size()==32 && y.size()==32,"JWK coordinate length");
        const auto point=std::string(1,'\x04')+x+y;
        char group[]="prime256v1";
        OSSL_PARAM params[]={OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,group,0),OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,const_cast<char*>(point.data()),point.size()),OSSL_PARAM_construct_end()};
        Owned<EVP_PKEY_CTX,EVP_PKEY_CTX_free> context(EVP_PKEY_CTX_new_from_name(nullptr,"EC",nullptr),EVP_PKEY_CTX_free);
        EVP_PKEY* raw=nullptr;check(context && EVP_PKEY_fromdata_init(context.get())==1 && EVP_PKEY_fromdata(context.get(),&raw,EVP_PKEY_PUBLIC_KEY,params)==1,"cannot import account JWK");account.reset(raw);
        const auto serialized=jwk.dump();if(!account_jwk.empty())check(account_jwk==serialized,"account key was not reused");account_jwk=serialized;
    }
    std::string verify(const std::string& url,const std::string& body) {
        const auto jws=Json::parse(body);check(jws.size()==3,"unexpected JWS fields");
        const auto header=Json::parse(decode(jws.at("protected")));
        check(header.at("alg")=="ES256" && header.at("url")==url,"JWS algorithm or URL mismatch");
        check(nonces.erase(header.at("nonce").get<std::string>())==1,"JWS reused or invented a nonce");
        if(url==origin+"/account") {check(header.contains("jwk") && !header.contains("kid"),"newAccount must use JWK");import_jwk(header.at("jwk"));}
        else check(!header.contains("jwk") && header.at("kid")==origin+"/account/1","subsequent request must use account URL");
        const auto raw=decode(jws.at("signature"));check(raw.size()==64,"JWS signature is not raw ES256");
        Owned<ECDSA_SIG,ECDSA_SIG_free> signature(ECDSA_SIG_new(),ECDSA_SIG_free);
        check(signature && ECDSA_SIG_set0(signature.get(),BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()),32,nullptr),BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()+32),32,nullptr))==1,"signature import failed");
        const int size=i2d_ECDSA_SIG(signature.get(),nullptr);std::vector<unsigned char> der(static_cast<std::size_t>(size));auto* pointer=der.data();check(i2d_ECDSA_SIG(signature.get(),&pointer)==size,"signature DER failed");
        const std::string signed_data=jws.at("protected").get<std::string>()+"."+jws.at("payload").get<std::string>();
        Owned<EVP_MD_CTX,EVP_MD_CTX_free> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        check(context && EVP_DigestVerifyInit(context.get(),nullptr,EVP_sha256(),nullptr,account.get())==1 && EVP_DigestVerify(context.get(),der.data(),der.size(),reinterpret_cast<const unsigned char*>(signed_data.data()),signed_data.size())==1,"ACME JWS signature verification failed");
        return decode(jws.at("payload"));
    }
    void issue_certificate(const std::string& encoded) {
        const auto der=decode(encoded);const auto* pointer=reinterpret_cast<const unsigned char*>(der.data());
        Owned<X509_REQ,X509_REQ_free> request(d2i_X509_REQ(nullptr,&pointer,static_cast<long>(der.size())),X509_REQ_free);
        check(request && pointer==reinterpret_cast<const unsigned char*>(der.data()+der.size()),"CSR DER invalid");
        Key public_key(X509_REQ_get_pubkey(request.get()),EVP_PKEY_free);check(public_key && X509_REQ_verify(request.get(),public_key.get())==1,"CSR self-signature invalid");
        if(domain.size()>64)check(X509_NAME_get_index_by_NID(X509_REQ_get_subject_name(request.get()),NID_commonName,-1)==-1,"long DNS name was put in a restricted-length common name");
        STACK_OF(X509_EXTENSION)* requested=X509_REQ_get_extensions(request.get());check(requested && sk_X509_EXTENSION_num(requested)==1,"CSR SAN missing");
        auto* name_extension=sk_X509_EXTENSION_value(requested,0);check(OBJ_obj2nid(X509_EXTENSION_get_object(name_extension))==NID_subject_alt_name,"CSR extension not SAN");
        GENERAL_NAMES* names=static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(name_extension));
        check(names && sk_GENERAL_NAME_num(names)==1,"CSR contains extra names");
        const auto* name=sk_GENERAL_NAME_value(names,0);
        check(name->type==GEN_DNS && std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(name->d.dNSName)),static_cast<std::size_t>(ASN1_STRING_length(name->d.dNSName)))==domain,"CSR requested wrong DNS name");
        GENERAL_NAMES_free(names);sk_X509_EXTENSION_pop_free(requested,X509_EXTENSION_free);
        Cert leaf(X509_new(),X509_free);check(leaf && X509_set_version(leaf.get(),2)==1 && ASN1_INTEGER_set(X509_get_serialNumber(leaf.get()),2)==1,"leaf creation failed");
        X509_gmtime_adj(X509_getm_notBefore(leaf.get()),-60);X509_gmtime_adj(X509_getm_notAfter(leaf.get()),30*86400L);
        check(X509_set_subject_name(leaf.get(),X509_REQ_get_subject_name(request.get()))==1 && X509_set_issuer_name(leaf.get(),X509_get_subject_name(ca.get()))==1 && X509_set_pubkey(leaf.get(),public_key.get())==1,"leaf identity failed");
        extension(leaf.get(),ca.get(),NID_basic_constraints,"critical,CA:FALSE");extension(leaf.get(),ca.get(),NID_key_usage,"critical,digitalSignature");extension(leaf.get(),ca.get(),NID_ext_key_usage,"serverAuth");extension(leaf.get(),ca.get(),NID_subject_alt_name,std::string(domain.size()>64?"critical,DNS:":"DNS:")+(wrong_domain?"wrong.example.test":domain));extension(leaf.get(),ca.get(),NID_authority_key_identifier,"keyid:always");
        check(X509_sign(leaf.get(),ca_key.get(),EVP_sha256())>0,"leaf signing failed");chain=pem(leaf.get())+pem(ca.get());
    }
    void verify_challenge() {
        const auto expected=token+"."+digest(account_jwk);
        HttpRequest request{"GET","/.well-known/acme-challenge/"+token,"",{{"host",domain}}};
        const auto direct=manager->challenge(request);check(direct && direct->status==200 && direct->body==expected,"HTTP-01 key authorization incorrect");
        request.headers["host"]="wrong.example.test";check(manager->challenge(request)->status==404,"challenge disclosed for wrong host");
        request.headers["host"]=domain;request.path+="?query=1";check(manager->challenge(request)->status==404,"challenge query accepted");
        if(challenge_port) {
            Connection connection(std::chrono::seconds(5));connection.connect("127.0.0.1",challenge_port);
            connection.write("GET /.well-known/acme-challenge/"+token+" HTTP/1.1\r\nHost: "+domain+"\r\nConnection: close\r\n\r\n");
            check(connection.line().starts_with("HTTP/1.1 200 "),"native challenge listener did not respond");
            std::size_t size=0;for(;;){const auto line=connection.line();if(line.empty())break;if(lower(line).starts_with("content-length:"))size=static_cast<std::size_t>(std::stoul(trim(line.substr(15))));}
            check(size==expected.size() && connection.read(size)==expected,"native HTTP-01 response mismatch");
        }
    }
    AcmeHttpResponse handle(const std::string& method,const std::string& url,const std::map<std::string,std::string>& headers,const std::string& body,std::chrono::steady_clock::time_point deadline) {
        std::lock_guard lock(mutex);++requests;check(std::chrono::steady_clock::now()<deadline,"client passed an expired deadline");
        check(url.starts_with(origin+"/"),"test transport was used for a nonlocal URL");
        if(method=="GET" && url==origin+"/directory") return reply(200,{{"newNonce",origin+"/nonce"},{"newAccount",origin+"/account"},{"newOrder",cross_origin?"https://attacker.example/newOrder":origin+"/order"},{"meta",{{"termsOfService",terms_changed?"https://localhost/new-terms.pdf":terms}}}});
        if(method=="HEAD" && url==origin+"/nonce"){check(body.empty(),"newNonce body was not empty");return reply(204,Json::object());}
        check(method=="POST" && headers.at("Content-Type")=="application/jose+json","ACME resource did not use signed POST");
        const auto payload=verify(url,body);
        if(bad_nonce_once){bad_nonce_once=false;return reply(400,{{"type","urn:ietf:params:acme:error:badNonce"}});}
        if(url==origin+"/account") {const auto input=Json::parse(payload);check(input.at("termsOfServiceAgreed")==true && input.at("contact")==Json::array({"mailto:"+email}),"CA terms/contact were not explicit");return reply(201,{{"status","valid"}},origin+"/account/1");}
        if(url==origin+"/order") {check(Json::parse(payload).at("identifiers")==Json::array({{{"type","dns"},{"value",domain}}}),"order domain mismatch");challenged=false;finalized=false;return reply(201,order(),origin+"/order/1");}
        if(url==origin+"/challenge/1") {check(payload=="{}","challenge acknowledgment body mismatch");verify_challenge();challenged=true;return reply(200,{{"status","pending"}});}
        if(url==origin+"/finalize/1") {check(challenged,"CSR sent before domain validation");issue_certificate(Json::parse(payload).at("csr"));finalized=true;return reply(200,order());}
        check(payload.empty(),"POST-as-GET must have an empty encoded payload");++post_as_get;
        if(url==origin+"/authorization/1") return reply(200,{{"status",challenged && challenge_fail?"invalid":challenged && !hang?"valid":"pending"},{"identifier",{{"type","dns"},{"value",domain}}},{"challenges",Json::array({{{"type","http-01"},{"url",origin+"/challenge/1"},{"token",token},{"status","pending"}}})}});
        if(url==origin+"/order/1")return reply(200,order());
        if(url==origin+"/certificate/1"){check(headers.at("Accept")=="application/pem-certificate-chain","certificate accept type mismatch");auto response=reply(200,Json::object());response.body=chain;return response;}
        throw std::runtime_error("unexpected mock ACME endpoint");
    }
    AcmeOptions options(const fs::path& directory,bool listener=false) {
        AcmeOptions options;options.storage_directory=directory;options.manage_http_listener=listener;options.challenge_bind="127.0.0.1";options.test_directory_url=origin+"/directory";
        options.transport=[this](const auto& method,const auto& url,const auto& headers,const auto& body,auto deadline){return handle(method,url,headers,body,deadline);};
        options.test_ca_file=directory.parent_path()/"mock-ca.pem";
        if(!fs::exists(options.test_ca_file)){std::ofstream file(options.test_ca_file);file<<pem(ca.get());}
        if(listener){asio::io_context io;tcp::acceptor reserve(io,{asio::ip::address_v4::loopback(),0});challenge_port=reserve.local_endpoint().port();options.challenge_port=challenge_port;}
        return options;
    }
    Json request(const std::string& directory="staging")const{return {{"domain",domain},{"email",email},{"directory",directory},{"agree_terms",true},{"terms_of_service",terms}};}
};
Json finished(AcmeManager& manager,const std::string& id,int seconds=10) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
    while(std::chrono::steady_clock::now()<deadline){const auto state=manager.status(id);if(state.at("state")=="succeeded" || state.at("state")=="failed" || state.at("state")=="cancelled")return state;std::this_thread::sleep_for(std::chrono::milliseconds(10));}
    throw std::runtime_error("offline ACME test timed out");
}
void private_file(const fs::path& path){check(fs::is_regular_file(fs::symlink_status(path)),"issued file is not regular");
#ifndef _WIN32
check((fs::status(path).permissions()&(fs::perms::group_all|fs::perms::others_all))==fs::perms::none,"issued key/certificate is not private");
#endif
}
}

int main() {
    try {
        const auto directory=fs::absolute(fs::path("build/test-runs")/("acme-"+random_hex(6)));fs::create_directories(directory);
        MockCa mock;AcmeManager manager(mock.options(directory/"certificates",true));mock.manager=&manager;
        const auto metadata=manager.terms("staging");check(metadata.at("terms_of_service")==mock.terms && metadata.at("public_challenge_port")==80,"CA terms metadata mismatch");
        const auto before=mock.requests.load();auto input=mock.request();
        input["agree_terms"]=false;rejects([&]{manager.start(input);},"terms_required");input=mock.request();input["domain"]="*.example.test";rejects([&]{manager.start(input);},"invalid_domain");input=mock.request();input["domain"]="127.0.0.1";rejects([&]{manager.start(input);},"invalid_domain");input=mock.request();input["email"]="not-an-address";rejects([&]{manager.start(input);},"invalid_email");input=mock.request();input["directory"]="http://attacker.example/";rejects([&]{manager.start(input);},"invalid_request");input=mock.request();input["test_directory_url"]=mock.origin;rejects([&]{manager.start(input);},"invalid_request");
        check(mock.requests==before,"invalid input made external protocol requests");
        const auto started=manager.start(mock.request());const auto result=finished(manager,started.at("job_id"));
        if(result.at("state")!="succeeded")throw std::runtime_error("issuance failed: "+result.dump());
        check(mock.post_as_get>=4,"POST-as-GET flow not exercised");
        const auto certificate=fs::path(result.at("result").at("tls_certificate").get<std::string>()),key=fs::path(result.at("result").at("tls_private_key").get<std::string>());
        private_file(certificate);private_file(key);private_file(directory/"certificates/staging/account-key.pem");
        check(contents(certificate)==mock.chain && result.at("result").at("staging")==true && result.at("result").at("restart_required")==true,"issued files or manual restart result mismatch");
        check(result.dump().find("PRIVATE KEY")==std::string::npos && result.dump().find(mock.email)==std::string::npos,"job response exposed private material");
        HttpRequest challenge{"GET","/.well-known/acme-challenge/"+mock.token,"",{{"host",mock.domain}}};check(manager.challenge(challenge)->status==404,"challenge was retained after issuance");
        check(!manager.challenge(HttpRequest{"GET","/api/private","",{}}),"challenge responder intercepted unrelated API");
        rejects([&]{manager.status("unknown");},"unknown_job");
        // A second order uses the same persisted account key and a new leaf key.
        const auto second=finished(manager,manager.start(mock.request()).at("job_id"));check(second.at("state")=="succeeded","account key reuse failed");check(second.at("result").at("tls_private_key")!=result.at("result").at("tls_private_key"),"leaf private key path was reused");
        mock.domain=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(56,'d')+".test";
        check(mock.domain.size()==253,"long hostname fixture length mismatch");
        const auto long_name=finished(manager,manager.start(mock.request()).at("job_id"));check(long_name.at("state")=="succeeded","full-length DNS SAN issuance failed");
        check(fs::path(long_name.at("result").at("tls_private_key").get<std::string>()).parent_path().filename().string().size()<=128,"long domain exceeded the file component bound");
        std::cout<<"PASS offline ACME ES256/JWK/nonces, badNonce recovery, HTTP-01 listener, CSR and chain/private-file validation\n";

        MockCa invalid;auto invalid_options=invalid.options(directory/"invalid");invalid_options.test_ca_file=directory/"invalid-ca.pem";{std::ofstream file(invalid_options.test_ca_file);file<<pem(invalid.ca.get());}AcmeManager failed(invalid_options);invalid.manager=&failed;
        invalid.wrong_domain=true;auto rejected=finished(failed,failed.start(invalid.request()).at("job_id"));check(rejected.at("state")=="failed" && rejected.at("code")=="invalid_certificate","mismatched certificate domain was accepted");
        invalid.wrong_domain=false;invalid.challenge_fail=true;rejected=finished(failed,failed.start(invalid.request()).at("job_id"));check(rejected.at("code")=="challenge_failed","failed authorization was accepted");
        invalid.challenge_fail=false;invalid.cross_origin=true;rejects([&]{failed.terms();},"unsafe_ca_url");invalid.cross_origin=false;invalid.terms_changed=true;rejected=finished(failed,failed.start(invalid.request()).at("job_id"));check(rejected.at("code")=="terms_changed","changed terms were silently accepted");
        invalid.terms_changed=false;invalid.hang=true;const auto pending=failed.start(invalid.request());rejects([&]{failed.start(invalid.request());},"issuance_busy");check(failed.cancel(pending.at("job_id")).at("cancel_requested")==true,"cancel was not acknowledged");check(finished(failed,pending.at("job_id")).at("state")=="cancelled","cancel did not stop issuance");
        auto timeout_options=invalid_options;timeout_options.job_timeout=std::chrono::seconds(2);AcmeManager limited(timeout_options);invalid.manager=&limited;
        const auto timed_out=finished(limited,limited.start(invalid.request()).at("job_id"),5);check(timed_out.at("state")=="failed" && timed_out.at("code")=="timeout","pending authorization exceeded the whole-job deadline");
        std::cout<<"PASS ACME consent/input gates, CA origin policy, changed terms, invalid leaf, failed authorization and cancellation\n";
        std::cout<<"All ACME tests passed (local mock CA only; no public CA contacted)\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
