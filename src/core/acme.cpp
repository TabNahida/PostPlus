#include <postplus/acme.hpp>
#include <postplus/trust.hpp>
#include <asio/ssl.hpp>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <wincrypt.h>
#undef X509_NAME
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace postplus {
namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
constexpr std::size_t max_response = 256 * 1024;
constexpr std::string_view challenge_prefix = "/.well-known/acme-challenge/";
template<class T, auto Free> using Owned = std::unique_ptr<T, decltype(Free)>;
using Key = Owned<EVP_PKEY, EVP_PKEY_free>;
using Certificate = Owned<X509, X509_free>;
using Bio = Owned<BIO, BIO_free>;

struct Url { std::string origin, host, target; int port; bool tls; };
bool dns_name(std::string_view value) {
    if(value.empty() || value.size()>253) return false;
    std::size_t label=0;
    char previous='\0';
    for(const char character:value) {
        if(character=='.') {
            if(!label || previous=='-') return false;
            label=0;
        } else {
            if(!((character>='a' && character<='z') || (character>='A' && character<='Z') ||
                 (character>='0' && character<='9') || character=='-') || (!label && character=='-') || ++label>63) return false;
        }
        previous=character;
    }
    return label && previous!='-';
}
Url parse_url(const std::string& value) {
    if (value.size() > 4096 || value.find_first_of("\r\n\0\\#",0,5) != std::string::npos)
        throw AcmeError("invalid_ca_url", "The certificate authority returned an invalid URL.");
    const bool tls = value.starts_with("https://");
    const auto begin = tls ? 8U : 7U;
    if (!tls && !value.starts_with("http://")) throw AcmeError("invalid_ca_url", "The certificate authority URL must use HTTPS.");
    const auto slash = value.find('/',begin);
    if (slash == std::string::npos) throw AcmeError("invalid_ca_url", "The certificate authority URL needs an absolute path.");
    const auto authority = value.substr(begin,slash-begin);
    if (authority.empty() || authority.find_first_of("@? []") != std::string::npos)
        throw AcmeError("invalid_ca_url", "The certificate authority returned an invalid URL authority.");
    auto host = authority;
    int port = tls ? 443 : 80;
    if (const auto colon = authority.find(':'); colon != std::string::npos) {
        host = authority.substr(0,colon);
        const auto text = authority.substr(colon+1);
        const auto [end,error] = std::from_chars(text.data(),text.data()+text.size(),port);
        if (error!=std::errc{} || end!=text.data()+text.size() || port<1 || port>65535)
            throw AcmeError("invalid_ca_url", "The certificate authority returned an invalid port.");
    }
    if (!dns_name(host) || value.substr(slash).find_first_of(" \t")!=std::string::npos)
        throw AcmeError("invalid_ca_url", "The certificate authority returned an invalid URL.");
    return {value.substr(0,slash),lower(host),value.substr(slash),port,tls};
}

std::string base64url(std::string_view value) {
    auto output=base64_encode(value);
    while(output.ends_with('=')) output.pop_back();
    std::replace(output.begin(),output.end(),'+','-');
    std::replace(output.begin(),output.end(),'/','_');
    return output;
}
bool url_token(std::string_view value,std::size_t minimum=16,std::size_t maximum=512) {
    return value.size()>=minimum && value.size()<=maximum &&
        value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")==std::string_view::npos;
}
std::string sha256(std::string_view value) {
    std::array<unsigned char,32> digest{};
    unsigned int size=0;
    if(EVP_Digest(value.data(),value.size(),digest.data(),&size,EVP_sha256(),nullptr)!=1 || size!=digest.size())
        throw AcmeError("crypto_failed","Could not calculate an ACME digest.",503);
    return {reinterpret_cast<const char*>(digest.data()),digest.size()};
}
std::string bio_text(BIO* bio) {
    char* contents=nullptr;
    const auto count=BIO_get_mem_data(bio,&contents);
    if(count<0 || !contents) throw AcmeError("crypto_failed","Could not encode certificate material.",503);
    return {contents,static_cast<std::size_t>(count)};
}
Key generate_key() {
    Key result(EVP_PKEY_Q_keygen(nullptr,nullptr,"EC","P-256"),EVP_PKEY_free);
    if(!result) throw AcmeError("crypto_failed","Could not generate an ECDSA key.",503);
    return result;
}
std::string key_pem(EVP_PKEY* key) {
    Bio bio(BIO_new(BIO_s_mem()),BIO_free);
    if(!bio || PEM_write_bio_PrivateKey(bio.get(),key,nullptr,nullptr,0,nullptr,nullptr)!=1)
        throw AcmeError("crypto_failed","Could not encode a private key.",503);
    return bio_text(bio.get());
}
Key read_key(const fs::path& path) {
    const auto status=fs::symlink_status(path);
    if(!fs::is_regular_file(status) || fs::is_symlink(status) || fs::file_size(path)>16384)
        throw AcmeError("invalid_account_key","The saved ACME account key is not a regular private key file.",503);
#ifndef _WIN32
    if((status.permissions()&(fs::perms::group_all|fs::perms::others_all))!=fs::perms::none)
        throw AcmeError("invalid_account_key","The ACME account key must have owner-only permissions (0600).",503);
#endif
    std::ifstream file(path,std::ios::binary);
    const std::string pem{std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
    Bio bio(BIO_new_mem_buf(pem.data(),static_cast<int>(pem.size())),BIO_free);
    // Never prompt on stdin for an encrypted key in the unattended server.
    Key key(bio ? PEM_read_bio_PrivateKey(bio.get(),nullptr,[](char*,int,int,void*){return 0;},nullptr) : nullptr,EVP_PKEY_free);
    char group[80]{}; std::size_t size=0;
    if(!key || EVP_PKEY_is_a(key.get(),"EC")!=1 ||
       EVP_PKEY_get_utf8_string_param(key.get(),OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof(group),&size)!=1 ||
       (std::string(group)!="prime256v1" && std::string(group)!="P-256"))
        throw AcmeError("invalid_account_key","The saved ACME account key must be an unencrypted P-256 key.",503);
    return key;
}
Json public_jwk(EVP_PKEY* key) {
    auto coordinate=[&](const char* name) {
        BIGNUM* value=nullptr;
        if(EVP_PKEY_get_bn_param(key,name,&value)!=1) throw AcmeError("crypto_failed","Could not read the ACME public key.",503);
        Owned<BIGNUM,BN_free> owned(value,BN_free);
        std::array<unsigned char,32> bytes{};
        if(BN_bn2binpad(value,bytes.data(),static_cast<int>(bytes.size()))!=static_cast<int>(bytes.size()))
            throw AcmeError("crypto_failed","Invalid ECDSA public key size.",503);
        return base64url({reinterpret_cast<const char*>(bytes.data()),bytes.size()});
    };
    return {{"crv","P-256"},{"kty","EC"},{"x",coordinate(OSSL_PKEY_PARAM_EC_PUB_X)},{"y",coordinate(OSSL_PKEY_PARAM_EC_PUB_Y)}};
}
std::string signature(EVP_PKEY* key,const std::string& input) {
    Owned<EVP_MD_CTX,EVP_MD_CTX_free> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    std::size_t size=0;
    if(!context || EVP_DigestSignInit(context.get(),nullptr,EVP_sha256(),nullptr,key)!=1 ||
       EVP_DigestSign(context.get(),nullptr,&size,reinterpret_cast<const unsigned char*>(input.data()),input.size())!=1)
        throw AcmeError("crypto_failed","Could not sign the ACME request.",503);
    std::vector<unsigned char> der(size);
    if(EVP_DigestSign(context.get(),der.data(),&size,reinterpret_cast<const unsigned char*>(input.data()),input.size())!=1)
        throw AcmeError("crypto_failed","Could not sign the ACME request.",503);
    const unsigned char* pointer=der.data();
    Owned<ECDSA_SIG,ECDSA_SIG_free> decoded(d2i_ECDSA_SIG(nullptr,&pointer,static_cast<long>(size)),ECDSA_SIG_free);
    if(!decoded || pointer!=der.data()+size) throw AcmeError("crypto_failed","Invalid ACME signature encoding.",503);
    std::array<unsigned char,64> jose{};
    if(BN_bn2binpad(ECDSA_SIG_get0_r(decoded.get()),jose.data(),32)!=32 ||
       BN_bn2binpad(ECDSA_SIG_get0_s(decoded.get()),jose.data()+32,32)!=32)
        throw AcmeError("crypto_failed","Invalid ACME signature length.",503);
    return base64url({reinterpret_cast<const char*>(jose.data()),jose.size()});
}
std::string csr(EVP_PKEY* key,const std::string& domain) {
    Owned<X509_REQ,X509_REQ_free> request(X509_REQ_new(),X509_REQ_free);
    Owned<X509_NAME,X509_NAME_free> subject(X509_NAME_new(),X509_NAME_free);
    if(!request || !subject || X509_REQ_set_version(request.get(),0)!=1)
        throw AcmeError("crypto_failed","Could not create a certificate signing request.",503);
    // CN is optional and its ASN.1 upper bound is 64 bytes. DNS SAN supports
    // the full hostname length and is authoritative for certificate matching.
    if(domain.size()<=64 && X509_NAME_add_entry_by_txt(subject.get(),"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>(domain.data()),static_cast<int>(domain.size()),-1,0)!=1)
        throw AcmeError("crypto_failed","Could not create the certificate subject.",503);
    if(X509_REQ_set_subject_name(request.get(),subject.get())!=1 || X509_REQ_set_pubkey(request.get(),key)!=1)
        throw AcmeError("crypto_failed","Could not create a certificate signing request.",503);
    STACK_OF(X509_EXTENSION)* extensions=sk_X509_EXTENSION_new_null();
    if(!extensions) throw AcmeError("crypto_failed","Could not allocate certificate extensions.",503);
    const auto san="DNS:"+domain;
    X509_EXTENSION* extension=X509V3_EXT_conf_nid(nullptr,nullptr,NID_subject_alt_name,san.c_str());
    if(!extension || !sk_X509_EXTENSION_push(extensions,extension)) {
        X509_EXTENSION_free(extension);sk_X509_EXTENSION_pop_free(extensions,X509_EXTENSION_free);
        throw AcmeError("crypto_failed","Could not create the certificate domain extension.",503);
    }
    const bool added=X509_REQ_add_extensions(request.get(),extensions)==1;
    sk_X509_EXTENSION_pop_free(extensions,X509_EXTENSION_free);
    if(!added || X509_REQ_sign(request.get(),key,EVP_sha256())<=0)
        throw AcmeError("crypto_failed","Could not sign the certificate request.",503);
    const int size=i2d_X509_REQ(request.get(),nullptr);
    if(size<=0) throw AcmeError("crypto_failed","Could not encode the certificate request.",503);
    std::string der(static_cast<std::size_t>(size),'\0');
    auto* pointer=reinterpret_cast<unsigned char*>(der.data());
    if(i2d_X509_REQ(request.get(),&pointer)!=size) throw AcmeError("crypto_failed","Could not encode the certificate request.",503);
    return base64url(der);
}

#ifdef _WIN32
class PrivateSecurity {
public:
    explicit PrivateSecurity(bool directory=false) {
        HANDLE token=nullptr;
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) throw AcmeError("file_permissions","Cannot read process identity.",503);
        DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);
        std::vector<unsigned char> user(size);
        const bool success=GetTokenInformation(token,TokenUser,user.data(),size,&size)!=0;
        CloseHandle(token);
        if(!success) throw AcmeError("file_permissions","Cannot read process identity.",503);
        LPWSTR sid=nullptr;
        if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,&sid)) throw AcmeError("file_permissions","Cannot read process identity.",503);
        const auto flags=directory ? L"OICI" : L"";
        const auto acl=L"D:P(A;"+std::wstring(flags)+L";FA;;;SY)(A;"+flags+L";FA;;;"+std::wstring(sid)+L")";
        LocalFree(sid);
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&descriptor_,nullptr)) throw AcmeError("file_permissions","Cannot set private file permissions.",503);
        attributes_={sizeof(SECURITY_ATTRIBUTES),descriptor_,FALSE};
    }
    ~PrivateSecurity(){LocalFree(descriptor_);}
    SECURITY_ATTRIBUTES* get(){return &attributes_;}
private:
    PSECURITY_DESCRIPTOR descriptor_=nullptr;
    SECURITY_ATTRIBUTES attributes_{};
};
#endif
void private_directory(const fs::path& path) {
    std::error_code error;
    const auto status=fs::symlink_status(path,error);
    if(fs::exists(status)) {
        if(!fs::is_directory(status) || fs::is_symlink(status)) throw AcmeError("unsafe_storage","Certificate storage must be a directory, not a symbolic link.",503);
        return;
    }
    if(error && error!=std::errc::no_such_file_or_directory) throw AcmeError("unsafe_storage","Cannot inspect certificate storage.",503);
    if(!path.parent_path().empty() && path.parent_path()!=path) private_directory(path.parent_path());
#ifdef _WIN32
    PrivateSecurity security(true);
    if(!CreateDirectoryW(path.c_str(),security.get()) && GetLastError()!=ERROR_ALREADY_EXISTS)
        throw AcmeError("file_permissions","Cannot create the private certificate directory.",503);
#else
    if(::mkdir(path.c_str(),0700)!=0 && errno!=EEXIST) throw AcmeError("file_permissions","Cannot create the private certificate directory.",503);
#endif
    if(!fs::is_directory(fs::symlink_status(path))) throw AcmeError("unsafe_storage","Certificate storage changed while it was being created.",503);
}
void private_write(const fs::path& path,std::string_view contents) {
#ifdef _WIN32
    PrivateSecurity security;
    HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,security.get(),CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) throw AcmeError("file_permissions","Cannot create a private certificate file.",503);
    DWORD written=0;
    const bool saved=WriteFile(file,contents.data(),static_cast<DWORD>(contents.size()),&written,nullptr)!=0 && written==contents.size() && FlushFileBuffers(file)!=0;
    CloseHandle(file);
    if(!saved){DeleteFileW(path.c_str());throw AcmeError("file_permissions","Cannot save a private certificate file.",503);}
#else
    const int file=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(file<0) throw AcmeError("file_permissions","Cannot create a private certificate file.",503);
    bool saved=true;std::size_t offset=0;
    while(offset<contents.size()) {
        const auto count=::write(file,contents.data()+offset,contents.size()-offset);
        if(count<0 && errno==EINTR) continue;
        if(count<=0){saved=false;break;}offset+=static_cast<std::size_t>(count);
    }
    if(::fsync(file)!=0) saved=false;
    if(::close(file)!=0) saved=false;
    if(!saved){::unlink(path.c_str());throw AcmeError("file_permissions","Cannot save a private certificate file.",503);}
#endif
}
struct Cleanup {
    std::vector<fs::path> files;
    ~Cleanup(){for(const auto& path:files){std::error_code ignored;fs::remove(path,ignored);}}
};
Key account_key(const fs::path& directory) {
    const auto path=directory/"account-key.pem";
    if(fs::exists(fs::symlink_status(path))) return read_key(path);
    auto key=generate_key();
    const auto temporary=directory/("account-key-"+random_hex(12)+".tmp");
    private_write(temporary,key_pem(key.get()));
    Cleanup cleanup{{temporary}};
#ifdef _WIN32
    if(MoveFileExW(temporary.c_str(),path.c_str(),MOVEFILE_WRITE_THROUGH)) return key;
    if(GetLastError()!=ERROR_ALREADY_EXISTS && GetLastError()!=ERROR_FILE_EXISTS)
        throw AcmeError("file_permissions","Cannot commit the ACME account key.",503);
#else
    if(::link(temporary.c_str(),path.c_str())==0) return key;
    if(errno!=EEXIST) throw AcmeError("file_permissions","Cannot commit the ACME account key.",503);
#endif
    return read_key(path);
}

AcmeHttpResponse native_http(const std::string& method,const std::string& url,
    const std::map<std::string,std::string>& headers,const std::string& body,Clock::time_point deadline) {
    const auto address=parse_url(url);
    Connection connection(std::chrono::seconds(15));
    connection.set_deadline(deadline);
    connection.connect(address.host,address.port);
    if(address.tls) connection.start_tls_client(address.host);
    std::string request=method+" "+address.target+" HTTP/1.1\r\nHost: "+address.host;
    if(address.port!=(address.tls?443:80)) request+=":"+std::to_string(address.port);
    request+="\r\nUser-Agent: PostPlus-ACME/0.1\r\nConnection: close\r\n";
    for(const auto& [key,value]:headers) request+=key+": "+value+"\r\n";
    if(method=="POST") request+="Content-Length: "+std::to_string(body.size())+"\r\n";
    connection.write(request+"\r\n"+body);
    const auto status_line=connection.line(4096);
    if(!status_line.starts_with("HTTP/1.1 ") && !status_line.starts_with("HTTP/1.0 ")) throw AcmeError("invalid_ca_response","Invalid HTTP response from the certificate authority.",502);
    if(status_line.size()<12) throw AcmeError("invalid_ca_response","Incomplete certificate authority HTTP status.",502);
    AcmeHttpResponse result;
    const auto [end,error]=std::from_chars(status_line.data()+9,status_line.data()+12,result.status);
    if(error!=std::errc{} || end!=status_line.data()+12 || result.status<200 || result.status>599)
        throw AcmeError("invalid_ca_response","Invalid certificate authority HTTP status.",502);
    std::size_t header_bytes=0;
    bool complete=false;
    for(int count=0;count<100;++count) {
        const auto line=connection.line(8192);
        if(line.empty()){complete=true;break;}
        header_bytes+=line.size();
        const auto colon=line.find(':');
        if(header_bytes>32768 || colon==std::string::npos || colon==0 || line.front()==' ' || line.front()=='\t')
            throw AcmeError("invalid_ca_response","Invalid certificate authority HTTP headers.",502);
        const auto name=lower(line.substr(0,colon));
        const auto value=trim(line.substr(colon+1));
        if(value.find('\0')!=std::string::npos || name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-_")!=std::string::npos)
            throw AcmeError("invalid_ca_response","Invalid certificate authority HTTP headers.",502);
        if(result.headers.contains(name)) {
            if(name=="content-length" || name=="transfer-encoding" || name=="location" || name=="replay-nonce")
                throw AcmeError("invalid_ca_response","Duplicate certificate authority HTTP headers.",502);
            result.headers[name]+=", "+value;
        } else result.headers[name]=value;
    }
    if(!complete) throw AcmeError("invalid_ca_response","Certificate authority HTTP headers exceeded their limit.",502);
    if(method=="HEAD" || result.status==204 || result.status==304) return result;
    if(result.headers.contains("transfer-encoding")) {
        if(result.headers.contains("content-length") || lower(result.headers.at("transfer-encoding"))!="chunked")
            throw AcmeError("invalid_ca_response","Unsupported certificate authority response framing.",502);
        for(int chunks=0;chunks<4096;++chunks) {
            const auto line=connection.line(1024);
            const auto field=line.substr(0,line.find(';'));
            std::size_t size=0;
            const auto [last,issue]=std::from_chars(field.data(),field.data()+field.size(),size,16);
            if(issue!=std::errc{} || last!=field.data()+field.size() || field.empty() || size>max_response-result.body.size())
                throw AcmeError("invalid_ca_response","Invalid or oversized certificate authority response chunk.",502);
            if(!size) {
                for(int trailers=0;trailers<32;++trailers) if(connection.line(8192).empty()) return result;
                throw AcmeError("invalid_ca_response","Certificate authority trailers exceeded their limit.",502);
            }
            result.body+=connection.read(size);
            if(connection.read(2)!="\r\n") throw AcmeError("invalid_ca_response","Invalid certificate authority chunk delimiter.",502);
        }
        throw AcmeError("invalid_ca_response","Certificate authority response contained too many chunks.",502);
    }
    if(result.headers.contains("content-length")) {
        const auto& field=result.headers.at("content-length");
        std::size_t size=0;
        const auto [last,issue]=std::from_chars(field.data(),field.data()+field.size(),size);
        if(issue!=std::errc{} || last!=field.data()+field.size() || field.empty() || size>max_response)
            throw AcmeError("invalid_ca_response","Invalid certificate authority response length.",502);
        result.body=connection.read(size);
        return result;
    }
    // HTTP permits close-delimited responses. Read with the same whole-request
    // deadline and size cap; TLS truncation is not treated as a clean EOF.
    while(result.body.size()<=max_response) {
        try {result.body+=connection.read(1);}
        catch(const std::system_error& error_value) {if(error_value.code()==asio::error::eof) return result;throw;}
    }
    throw AcmeError("invalid_ca_response","Certificate authority response exceeded its size limit.",502);
}

Json response_json(const AcmeHttpResponse& response) {
    if(response.body.size()>max_response) throw AcmeError("invalid_ca_response","Certificate authority response exceeded its size limit.",502);
    auto value=Json::parse(response.body,nullptr,false);
    if(value.is_discarded() || !value.is_object()) throw AcmeError("invalid_ca_response","The certificate authority returned invalid JSON.",502);
    return value;
}
[[noreturn]] void ca_failure(const AcmeHttpResponse& response) {
    auto problem=Json::parse(response.body,nullptr,false);
    const auto type=problem.is_object() && problem.contains("type") && problem.at("type").is_string() ? problem.at("type").get<std::string>() : std::string{};
    if(response.status==429 || type.ends_with(":rateLimited"))
        throw AcmeError("rate_limited","The certificate authority rate limit was reached. Wait before trying again; use staging for testing.",429);
    if(type.ends_with(":rejectedIdentifier")) throw AcmeError("invalid_domain","The certificate authority will not issue a certificate for this domain.");
    if(type.ends_with(":userActionRequired")) throw AcmeError("account_action_required","The certificate authority requires account action. Review its current terms before retrying.");
    throw AcmeError("ca_rejected","The certificate authority rejected the request (HTTP "+std::to_string(response.status)+"). Check the domain, contact address and current CA policy.",502);
}

class Protocol {
public:
    Protocol(const AcmeOptions& options,std::string directory,Clock::time_point deadline,std::function<void()> check)
        : options_(options),deadline_(deadline),check_(std::move(check)) {
        url_=options_.test_directory_url.empty() ?
            (directory=="production" ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory") : options_.test_directory_url;
        origin_=parse_url(url_).origin;
    }
    Json directory() {
        const auto response=send("GET",url_,{},"");
        if(response.status!=200) ca_failure(response);
        directory_=response_json(response);
        for(const auto* key:{"newNonce","newAccount","newOrder"}) checked_url(directory_.value(key,std::string{}));
        if(!directory_.contains("meta") || !directory_.at("meta").is_object()) throw AcmeError("invalid_ca_response","The certificate authority did not publish its terms.",502);
        const auto terms=directory_.at("meta").value("termsOfService",std::string{});
        if(!parse_url(terms).tls) throw AcmeError("invalid_ca_response","The certificate authority terms URL must use HTTPS.",502);
        return directory_;
    }
    void account(EVP_PKEY* key,const std::string& email) {
        key_=key;jwk_=public_jwk(key_);
        const auto response=post(directory_.at("newAccount").get<std::string>(),Json{{"termsOfServiceAgreed",true},{"contact",Json::array({"mailto:"+email})}}.dump(),true);
        if(response.status!=200 && response.status!=201) ca_failure(response);
        const auto value=response_json(response);
        if(value.value("status",std::string{})!="valid") throw AcmeError("account_invalid","The certificate authority account is not valid.",502);
        kid_=location(response);
    }
    std::string thumbprint() const {return base64url(sha256(jwk_.dump()));}
    AcmeHttpResponse post(const std::string& url,const std::string& payload,bool use_jwk=false,const std::string& accept="application/json") {
        checked_url(url);
        for(int attempt=0;attempt<3;++attempt) {
            if(nonce_.empty()) {
                const auto response=send("HEAD",directory_.at("newNonce").get<std::string>(),{},"");
                if(response.status!=200 && response.status!=204) ca_failure(response);
                if(nonce_.empty()) throw AcmeError("invalid_ca_response","The certificate authority did not return a replay nonce.",502);
            }
            Json protected_header={{"alg","ES256"},{"nonce",nonce_},{"url",url}};
            nonce_.clear();
            if(use_jwk) protected_header["jwk"]=jwk_; else protected_header["kid"]=kid_;
            const auto encoded=base64url(protected_header.dump()), content=base64url(payload);
            const Json jws={{"protected",encoded},{"payload",content},{"signature",signature(key_,encoded+"."+content)}};
            auto response=send("POST",url,{{"Content-Type","application/jose+json"},{"Accept",accept}},jws.dump());
            if(response.status>=200 && response.status<300) return response;
            const auto problem=Json::parse(response.body,nullptr,false);
            if(response.status==400 && problem.is_object() && problem.value("type",std::string{})=="urn:ietf:params:acme:error:badNonce") continue;
            ca_failure(response);
        }
        throw AcmeError("bad_nonce","The certificate authority repeatedly rejected fresh request nonces. Try again later.",502);
    }
    std::string location(const AcmeHttpResponse& response) const {
        const auto found=response.headers.find("location");
        if(found==response.headers.end()) throw AcmeError("invalid_ca_response","The certificate authority omitted a resource URL.",502);
        checked_url(found->second);return found->second;
    }
    void checked_url(const std::string& url) const {
        const auto value=parse_url(url);
        if(value.origin!=origin_ || (!value.tls && options_.test_directory_url.empty()))
            throw AcmeError("unsafe_ca_url","The certificate authority returned a URL outside its configured HTTPS origin.",502);
    }
    const Json& metadata() const{return directory_;}
private:
    AcmeHttpResponse send(const std::string& method,const std::string& url,const std::map<std::string,std::string>& headers,const std::string& body) {
        check_();checked_url(url);
        if(Clock::now()>=deadline_) throw AcmeError("timeout","Certificate issuance timed out. Verify public DNS and HTTP port 80 before retrying.",504);
        const auto limit=std::min(deadline_,Clock::now()+options_.request_timeout);
        auto response=options_.transport ? options_.transport(method,url,headers,body,limit) : native_http(method,url,headers,body,limit);
        if(response.body.size()>max_response) throw AcmeError("invalid_ca_response","Certificate authority response exceeded its size limit.",502);
        const auto nonce=response.headers.find("replay-nonce");
        if(nonce!=response.headers.end()) {
            if(!url_token(nonce->second)) throw AcmeError("invalid_ca_response","The certificate authority returned an invalid replay nonce.",502);
            nonce_=nonce->second;
        }
        check_();return response;
    }
    const AcmeOptions& options_;
    Clock::time_point deadline_;
    std::function<void()> check_;
    std::string url_,origin_,nonce_,kid_;
    Json directory_,jwk_;
    EVP_PKEY* key_=nullptr;
};

class ChallengeServer {
public:
    ChallengeServer(const AcmeOptions& options,HttpHandler handler):handler_(std::move(handler)),acceptor_(io_) {
        std::error_code error;
        const auto address=asio::ip::make_address(options.challenge_bind,error);
        if(error) throw AcmeError("http_challenge_bind","Invalid HTTP challenge listening address.");
        acceptor_.open(address.is_v6()?tcp::v6():tcp::v4(),error);
#ifndef _WIN32
        // Sequential staging/production requests reuse the same public port.
        // POSIX TIME_WAIT must not prevent the next temporary listener bind.
        if(!error) acceptor_.set_option(tcp::acceptor::reuse_address(true),error);
#endif
        if(!error) acceptor_.bind({address,static_cast<unsigned short>(options.challenge_port)},error);
        if(!error) acceptor_.listen(asio::socket_base::max_listen_connections,error);
        if(error) throw AcmeError("http_challenge_bind","Cannot listen for HTTP-01 on port "+std::to_string(options.challenge_port)+". Allow the port or configure your reverse proxy to forward the challenge route.",409);
        accept();thread_=std::thread([this]{io_.run();});
    }
    ~ChallengeServer(){
        asio::post(io_,[this]{std::error_code ignored;acceptor_.close(ignored);});
        if(thread_.joinable()) thread_.join();
        workers_.join();
    }
private:
    void accept() {
        auto connection=std::make_shared<Connection>(std::chrono::seconds(3));
        acceptor_.async_accept(connection->socket(),[this,connection](std::error_code error){
            if(!error && active_.load()<8) {
                ++active_;
                asio::post(workers_,[this,connection]{
                    try {
                        connection->set_deadline(Clock::now()+std::chrono::seconds(3));
                        const auto line=connection->line(2048);
                        const auto first=line.find(' '),second=first==std::string::npos?std::string::npos:line.find(' ',first+1);
                        if(first==std::string::npos || second==std::string::npos || (line.substr(second+1)!="HTTP/1.1" && line.substr(second+1)!="HTTP/1.0")) throw std::runtime_error("invalid HTTP");
                        HttpRequest request;
                        request.method=line.substr(0,first);request.path=line.substr(first+1,second-first-1);
                        bool complete=false;std::size_t bytes=0;
                        for(int count=0;count<40;++count) {
                            const auto field=connection->line(4096);
                            if(field.empty()){complete=true;break;}
                            bytes+=field.size();const auto colon=field.find(':');
                            if(colon==std::string::npos || bytes>8192) throw std::runtime_error("invalid HTTP headers");
                            const auto name=lower(field.substr(0,colon));
                            if(request.headers.contains(name)) throw std::runtime_error("duplicate HTTP header");
                            request.headers[name]=trim(field.substr(colon+1));
                        }
                        if(!complete) throw std::runtime_error("incomplete HTTP");
                        auto response=handler_(request);
                        const auto reason=response.status==200?"OK":response.status==405?"Method Not Allowed":"Not Found";
                        connection->write("HTTP/1.1 "+std::to_string(response.status)+" "+reason+"\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: "+std::to_string(response.body.size())+"\r\n\r\n"+(request.method=="HEAD"?std::string{}:response.body));
                    } catch(const std::exception&) {}
                    --active_;
                });
            }
            if(acceptor_.is_open()) accept();
        });
    }
    HttpHandler handler_;
    asio::io_context io_;
    tcp::acceptor acceptor_;
    asio::thread_pool workers_{8};
    std::thread thread_;
    std::atomic<int> active_{0};
};

std::string certificate_expiry(const std::string& pem,EVP_PKEY* key,const std::string& domain,bool staging,const fs::path& test_ca) {
    std::vector<Certificate> chain;
    std::size_t position=0;
    while(position<pem.size()) {
        position=pem.find_first_not_of(" \t\r\n",position);
        if(position==std::string::npos) break;
        constexpr std::string_view begin="-----BEGIN CERTIFICATE-----",end="-----END CERTIFICATE-----";
        if(!std::string_view(pem).substr(position).starts_with(begin) || chain.size()>=10)
            throw AcmeError("invalid_certificate","The certificate authority returned an invalid PEM certificate chain.",502);
        const auto last=pem.find(end,position+begin.size());
        if(last==std::string::npos) throw AcmeError("invalid_certificate","The certificate authority returned an incomplete certificate.",502);
        const auto count=last+end.size()-position;
        Bio bio(BIO_new_mem_buf(pem.data()+position,static_cast<int>(count)),BIO_free);
        Certificate certificate(bio?PEM_read_bio_X509(bio.get(),nullptr,nullptr,nullptr):nullptr,X509_free);
        if(!certificate) throw AcmeError("invalid_certificate","The certificate authority returned an unreadable certificate.",502);
        chain.push_back(std::move(certificate));position=last+end.size();
    }
    if(chain.empty()) throw AcmeError("invalid_certificate","The certificate authority returned no certificates.",502);
    X509* leaf=chain.front().get();
    const auto now=std::time(nullptr);
    auto before_limit=now+300,after_limit=now+3600;
    if(X509_check_private_key(leaf,key)!=1 || X509_cmp_time(X509_get0_notBefore(leaf),&before_limit)!=-1 ||
       X509_cmp_time(X509_get0_notAfter(leaf),&after_limit)!=1 || X509_check_purpose(leaf,X509_PURPOSE_SSL_SERVER,0)!=1)
        throw AcmeError("invalid_certificate","The issued certificate does not match its private key, validity period or server purpose.",502);
    GENERAL_NAMES* names=static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(leaf,NID_subject_alt_name,nullptr,nullptr));
    bool matches=names && sk_GENERAL_NAME_num(names)==1;
    if(matches) {
        const auto* name=sk_GENERAL_NAME_value(names,0);
        const auto* value=name->type==GEN_DNS?name->d.dNSName:nullptr;
        matches=value && ASN1_STRING_length(value)==static_cast<int>(domain.size()) &&
            lower(std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),static_cast<std::size_t>(ASN1_STRING_length(value))))==domain;
    }
    GENERAL_NAMES_free(names);
    if(!matches) throw AcmeError("invalid_certificate","The issued certificate must contain exactly the requested DNS name.",502);
    for(std::size_t i=1;i<chain.size();++i) {
        Key issuer(X509_get_pubkey(chain[i].get()),EVP_PKEY_free);
        if(!issuer || X509_check_ca(chain[i].get())<=0 || X509_check_issued(chain[i].get(),chain[i-1].get())!=X509_V_OK ||
           X509_verify(chain[i-1].get(),issuer.get())!=1 ||
           X509_cmp_time(X509_get0_notBefore(chain[i].get()),&before_limit)!=-1 || X509_cmp_time(X509_get0_notAfter(chain[i].get()),&after_limit)!=1)
            throw AcmeError("invalid_certificate","The issued certificate chain has an invalid issuer signature or validity period.",502);
    }
    if(!staging || !test_ca.empty()) {
        Owned<X509_STORE,X509_STORE_free> store(X509_STORE_new(),X509_STORE_free);
        Owned<X509_STORE_CTX,X509_STORE_CTX_free> context(X509_STORE_CTX_new(),X509_STORE_CTX_free);
        if(!store || !context) throw AcmeError("crypto_failed","Could not allocate certificate validation state.",503);
        if(!test_ca.empty()) {
            if(X509_STORE_load_file(store.get(),test_ca.string().c_str())!=1) throw AcmeError("invalid_test_ca","Could not load the local test CA.",503);
        } else {
            if(X509_STORE_set_default_paths(store.get())!=1) throw AcmeError("ca_trust_unavailable","Could not load trusted root certificates.",503);
            add_platform_trust_roots(store.get());
        }
        STACK_OF(X509)* intermediates=sk_X509_new_null();
        if(!intermediates) throw AcmeError("crypto_failed","Could not allocate certificate chain validation state.",503);
        for(std::size_t i=1;i<chain.size();++i) sk_X509_push(intermediates,chain[i].get());
        const bool initialized=X509_STORE_CTX_init(context.get(),store.get(),leaf,intermediates)==1;
        if(initialized) X509_STORE_CTX_set_purpose(context.get(),X509_PURPOSE_SSL_SERVER);
        const bool verified=initialized && X509_verify_cert(context.get())==1;
        sk_X509_free(intermediates);
        if(!verified) throw AcmeError("invalid_certificate","The issued production certificate chain could not be verified against trusted roots.",502);
    }
    std::tm expiry{};
    if(ASN1_TIME_to_tm(X509_get0_notAfter(leaf),&expiry)!=1) throw AcmeError("invalid_certificate","The issued certificate expiry is invalid.",502);
    std::ostringstream output;output<<std::put_time(&expiry,"%Y-%m-%dT%H:%M:%SZ");return output.str();
}

std::chrono::seconds retry_delay(const AcmeHttpResponse& response) {
    const auto found=response.headers.find("retry-after");
    if(found==response.headers.end()) return std::chrono::seconds(1);
    int seconds=0;
    const auto& value=found->second;
    const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),seconds);
    if(error==std::errc{} && end==value.data()+value.size()) return std::chrono::seconds(std::clamp(seconds,1,10));
    std::tm date{};std::istringstream input(value);
    input>>std::get_time(&date,"%a, %d %b %Y %H:%M:%S GMT");
    if(!input.fail()) {
#ifdef _WIN32
        const auto target=_mkgmtime(&date);
#else
        const auto target=timegm(&date);
#endif
        return std::chrono::seconds(static_cast<int>(std::clamp<std::time_t>(target-std::time(nullptr),1,10)));
    }
    return std::chrono::seconds(1);
}
std::string request_text(const Json& request,const std::string& key,std::size_t maximum) {
    if(!request.contains(key) || !request.at(key).is_string()) throw AcmeError("invalid_request","Provide "+key+" as text.");
    const auto value=trim(request.at(key).get<std::string>());
    if(value.empty() || value.size()>maximum || value.find_first_of("\r\n\0",0,3)!=std::string::npos)
        throw AcmeError("invalid_request","Invalid "+key+".");
    return value;
}
void check_directory(const std::string& directory) {
    if(directory!="production" && directory!="staging") throw AcmeError("invalid_directory","Choose the Let's Encrypt production or staging directory.");
}
}

struct AcmeManager::Impl {
    AcmeOptions options;
    mutable std::mutex state_mutex;
    std::mutex control_mutex,wait_mutex;
    std::condition_variable wake;
    std::thread worker;
    std::atomic<bool> cancelled{false};
    Json state={{"ok",true},{"state","idle"}};
    std::map<std::string,std::string> challenges;
    std::string challenge_domain;
    explicit Impl(AcmeOptions value):options(std::move(value)) {}
    ~Impl(){cancelled=true;wake.notify_all();if(worker.joinable()) worker.join();}
    void check() const {
        if(cancelled.load()) throw AcmeError("cancelled","Certificate issuance was cancelled.");
    }
    void progress(const std::string& stage,const std::string& message) {
        std::lock_guard lock(state_mutex);state["state"]=stage;state["message"]=message;
    }
    void wait(const AcmeHttpResponse& response,Clock::time_point deadline) {
        check();
        std::unique_lock lock(wait_mutex);
        wake.wait_until(lock,std::min(deadline,Clock::now()+retry_delay(response)),[this]{return cancelled.load();});
        check();
        if(Clock::now()>=deadline) throw AcmeError("timeout","Certificate issuance timed out. Verify DNS and public HTTP port 80 before retrying.",504);
    }
    std::optional<HttpResponse> challenge(const HttpRequest& request) const {
        if(!request.path.starts_with(challenge_prefix)) return std::nullopt;
        HttpResponse response{404,"text/plain; charset=utf-8","Not found\n",{{"Cache-Control","no-store"},{"X-Content-Type-Options","nosniff"}}};
        if(request.method!="GET" && request.method!="HEAD") {response.status=405;response.body="Method not allowed\n";response.headers["Allow"]="GET, HEAD";return response;}
        const auto token=request.path.substr(challenge_prefix.size());
        if(!url_token(token,22,128)) return response;
        std::lock_guard lock(state_mutex);
        auto host=request.headers.find("host");
        if(host==request.headers.end()) return response;
        auto authority=lower(host->second);
        if(const auto colon=authority.find(':');colon!=std::string::npos) authority=authority.substr(0,colon);
        if(authority!=challenge_domain) return response;
        const auto found=challenges.find(token);
        if(found!=challenges.end()) {response.status=200;response.body=found->second;}
        return response;
    }
    Json issue(const Json& request,const std::string& id) {
        const auto domain=request.at("domain").get<std::string>();
        const auto directory=request.at("directory").get<std::string>();
        const auto deadline=Clock::now()+options.job_timeout;
        std::unique_ptr<ChallengeServer> server;
        if(options.manage_http_listener) server=std::make_unique<ChallengeServer>(options,[this](const HttpRequest& value){
            auto response=challenge(value);return response ? *response : HttpResponse{404,"text/plain; charset=utf-8","Not found\n",{}};
        });
        progress("connecting","Reading the certificate authority directory.");
        Protocol protocol(options,directory,deadline,[this]{check();});
        const auto metadata=protocol.directory();
        if(metadata.at("meta").at("termsOfService")!=request.at("terms_of_service"))
            throw AcmeError("terms_changed","The certificate authority terms changed. Read the current terms and confirm them before retrying.",409);
        const auto storage=fs::absolute(options.storage_directory).lexically_normal()/directory;
        private_directory(storage);
        auto account=account_key(storage);
        protocol.account(account.get(),request.at("email").get<std::string>());
        progress("ordering","Creating an order for the requested domain.");
        auto response=protocol.post(metadata.at("newOrder").get<std::string>(),Json{{"identifiers",Json::array({{{"type","dns"},{"value",domain}}})}}.dump());
        if(response.status!=201 && response.status!=200) ca_failure(response);
        const auto order_url=protocol.location(response);
        auto order=response_json(response);
        const Json expected_identifiers=Json::array({{{"type","dns"},{"value",domain}}});
        if(order.value("identifiers",Json::array())!=expected_identifiers || !order.contains("authorizations") ||
           !order.at("authorizations").is_array() || order.at("authorizations").size()!=1 || !order.at("authorizations")[0].is_string())
            throw AcmeError("invalid_ca_response","The certificate authority order does not match the requested domain.",502);
        const auto authorization_url=order.at("authorizations")[0].get<std::string>();
        const auto finalize_url=order.value("finalize",std::string{});
        protocol.checked_url(authorization_url);protocol.checked_url(finalize_url);
        response=protocol.post(authorization_url,"");
        auto authorization=response_json(response);
        auto verify_authorization=[&](const Json& value) {
            if(value.value("identifier",Json::object())!=Json{{"type","dns"},{"value",domain}} || value.value("wildcard",false))
                throw AcmeError("invalid_ca_response","The certificate authority authorization does not match the requested DNS name.",502);
        };
        verify_authorization(authorization);
        if(authorization.value("status",std::string{})!="valid") {
            if(authorization.value("status",std::string{})!="pending") throw AcmeError("challenge_failed","The domain authorization is not pending or valid. Correct DNS and retry.");
            if(!authorization.contains("challenges") || !authorization.at("challenges").is_array()) throw AcmeError("invalid_ca_response","The certificate authority did not provide domain challenges.",502);
            Json selected;
            for(const auto& challenge:authorization.at("challenges")) if(challenge.is_object() && challenge.value("type",std::string{})=="http-01") {selected=challenge;break;}
            if(selected.is_null()) throw AcmeError("http_challenge_unavailable","The certificate authority did not offer an HTTP-01 challenge for this domain.");
            const auto token=selected.value("token",std::string{}),challenge_url=selected.value("url",std::string{});
            if(!url_token(token,22,128)) throw AcmeError("invalid_ca_response","The certificate authority returned an invalid HTTP-01 token.",502);
            protocol.checked_url(challenge_url);
            {
                std::lock_guard lock(state_mutex);challenges[token]=token+"."+protocol.thumbprint();challenge_domain=domain;
            }
            progress("authorizing","Waiting for the certificate authority to reach this domain over public HTTP port 80.");
            (void)protocol.post(challenge_url,"{}");
            for(int attempt=0;attempt<120;++attempt) {
                response=protocol.post(authorization_url,"");authorization=response_json(response);verify_authorization(authorization);
                const auto status=authorization.value("status",std::string{});
                if(status=="valid") break;
                if(status!="pending" && status!="processing") throw AcmeError("challenge_failed","HTTP-01 domain validation failed. Point this domain's A/AAAA records at this server and make its challenge route reachable on public TCP port 80.");
                wait(response,deadline);
                if(attempt==119) throw AcmeError("timeout","The certificate authority did not complete domain validation.",504);
            }
            {std::lock_guard lock(state_mutex);challenges.clear();}
        }
        for(int attempt=0;attempt<120;++attempt) {
            response=protocol.post(order_url,"");order=response_json(response);
            const auto status=order.value("status",std::string{});
            if(status=="ready") break;
            if(status!="pending") throw AcmeError("order_failed","The certificate order did not become ready for its signing request.",502);
            wait(response,deadline);
            if(attempt==119) throw AcmeError("timeout","The certificate authority did not make the order ready.",504);
        }
        progress("finalizing","Submitting a signed certificate request.");
        auto certificate_key=generate_key();
        response=protocol.post(finalize_url,Json{{"csr",csr(certificate_key.get(),domain)}}.dump());
        order=response_json(response);
        for(int attempt=0;attempt<120;++attempt) {
            const auto status=order.value("status",std::string{});
            if(status=="valid") break;
            if(status!="processing" && status!="ready") throw AcmeError("order_failed","The certificate authority could not finalize this certificate order.",502);
            wait(response,deadline);
            response=protocol.post(order_url,"");order=response_json(response);
            if(attempt==119) throw AcmeError("timeout","The certificate authority did not complete certificate issuance.",504);
        }
        const auto certificate_url=order.value("certificate",std::string{});protocol.checked_url(certificate_url);
        progress("downloading","Downloading and validating the issued certificate chain.");
        const auto chain=protocol.post(certificate_url,"",false,"application/pem-certificate-chain");
        const auto expires=certificate_expiry(chain.body,certificate_key.get(),domain,directory=="staging",options.test_ca_file);
        check();
        // A full 253-byte DNS name plus the job ID exceeds filesystem component
        // limits; keep a readable prefix and the collision-resistant job ID.
        const auto destination=storage/(domain.substr(0,64)+"-"+id);
        private_directory(destination);
        const auto private_key=destination/"private-key.pem",certificate=destination/"fullchain.pem";
        Cleanup cleanup{{private_key,certificate,destination}};
        private_write(private_key,key_pem(certificate_key.get()));
        private_write(certificate,chain.body);
        cleanup.files.clear();
        return {{"tls_certificate",certificate.string()},{"tls_private_key",private_key.string()},{"expires_at",expires},
            {"staging",directory=="staging"},{"restart_required",true},
            {"message",directory=="staging" ? "Staging certificate issued. It is not publicly trusted. Apply the paths and save settings only for testing; restart manually to use it." : "Certificate issued. Apply these paths and save settings, then restart PostPlus manually."}};
    }
};

AcmeManager::AcmeManager(AcmeOptions options):impl_(std::make_unique<Impl>(std::move(options))) {
    auto& value=impl_->options;
    if(value.storage_directory.empty() || value.challenge_port<1 || value.challenge_port>65535 ||
       value.request_timeout<std::chrono::seconds(1) || value.request_timeout>std::chrono::seconds(60) ||
       value.job_timeout<std::chrono::seconds(2) || value.job_timeout>std::chrono::seconds(600))
        throw std::invalid_argument("invalid ACME service options");
    if(static_cast<bool>(value.transport)!=!value.test_directory_url.empty() || (!value.test_ca_file.empty() && !value.transport))
        throw std::invalid_argument("ACME transport overrides are available only with an explicit local test directory");
    if(!value.test_directory_url.empty()) {
        const auto test=parse_url(value.test_directory_url);
        if(test.host!="127.0.0.1" && test.host!="localhost") throw std::invalid_argument("ACME test directory must be loopback");
    }
}
AcmeManager::~AcmeManager()=default;
Json AcmeManager::terms(const std::string& directory) const {
    check_directory(directory);
    Protocol protocol(impl_->options,directory,Clock::now()+impl_->options.request_timeout,[]{});
    const auto metadata=protocol.directory();
    return {{"ok",true},{"directory",directory},{"terms_of_service",metadata.at("meta").at("termsOfService")},
        {"staging",directory=="staging"},{"challenge_type","http-01"},{"public_challenge_port",80}};
}
Json AcmeManager::start(const Json& request) {
    if(!request.is_object()) throw AcmeError("invalid_request","Certificate requests must be JSON objects.");
    const std::set<std::string> keys{"domain","email","directory","agree_terms","terms_of_service"};
    for(const auto& item:request.items()) if(!keys.contains(item.key())) throw AcmeError("invalid_request","Unknown certificate request field.");
    if(!request.contains("agree_terms") || !request.at("agree_terms").is_boolean() || !request.at("agree_terms").get<bool>())
        throw AcmeError("terms_required","Read the certificate authority terms and explicitly agree before requesting a certificate.");
    Json normalized=request;
    const auto domain=lower(request_text(request,"domain",253));
    std::error_code address_error;(void)asio::ip::make_address(domain,address_error);
    if(!dns_name(domain) || domain.find('.')==std::string::npos || !address_error || domain.find('*')!=std::string::npos)
        throw AcmeError("invalid_domain","Use a fully qualified ASCII DNS name you control. Wildcards, IP addresses and local-only names are not supported.");
    const auto email=request_text(request,"email",254);
    if(!valid_address(email)) throw AcmeError("invalid_email","Provide a valid contact email address for the certificate authority.");
    const auto directory=request_text(request,"directory",16);check_directory(directory);
    const auto terms_url=request_text(request,"terms_of_service",4096);
    if(!parse_url(terms_url).tls) throw AcmeError("terms_required","Load and read the certificate authority's current HTTPS terms before agreeing.");
    normalized["domain"]=domain;normalized["email"]=email;normalized["directory"]=directory;normalized["terms_of_service"]=terms_url;
    std::lock_guard control(impl_->control_mutex);
    {
        std::lock_guard lock(impl_->state_mutex);
        const auto current=impl_->state.at("state").get<std::string>();
        if(current!="idle" && current!="succeeded" && current!="failed" && current!="cancelled") throw AcmeError("issuance_busy","Another certificate request is already running.",409);
    }
    if(impl_->worker.joinable()) impl_->worker.join();
    const auto id=random_hex(16);impl_->cancelled=false;
    {
        std::lock_guard lock(impl_->state_mutex);
        impl_->state={{"ok",true},{"job_id",id},{"state","queued"},{"domain",domain},{"directory",directory},{"message","Certificate request queued."}};
        impl_->challenges.clear();impl_->challenge_domain=domain;
    }
    impl_->worker=std::thread([implementation=impl_.get(),normalized,id]{
        try {
            auto result=implementation->issue(normalized,id);
            std::lock_guard lock(implementation->state_mutex);
            implementation->state["state"]="succeeded";implementation->state["message"]=result.at("message");implementation->state["result"]=std::move(result);
        } catch(const AcmeError& error) {
            std::lock_guard lock(implementation->state_mutex);
            implementation->state["state"]=error.code=="cancelled"?"cancelled":"failed";
            implementation->state["code"]=error.code;implementation->state["error"]=error.what();implementation->state["message"]=error.what();
        } catch(const std::exception&) {
            std::lock_guard lock(implementation->state_mutex);
            implementation->state["state"]="failed";implementation->state["code"]="issuance_failed";
            implementation->state["error"]="Could not complete certificate issuance. Check network connectivity, trusted CA roots and certificate directory permissions.";
            implementation->state["message"]=implementation->state.at("error");
        }
        std::lock_guard lock(implementation->state_mutex);implementation->challenges.clear();
    });
    return {{"ok",true},{"job_id",id},{"state","queued"}};
}
Json AcmeManager::status(const std::string& job_id) const {
    std::lock_guard lock(impl_->state_mutex);
    if(!job_id.empty() && impl_->state.value("job_id",std::string{})!=job_id) throw AcmeError("unknown_job","Certificate request was not found.",404);
    return impl_->state;
}
Json AcmeManager::cancel(const std::string& job_id) {
    std::lock_guard control(impl_->control_mutex);
    auto current=status(job_id);
    if(current.at("state")=="idle") throw AcmeError("unknown_job","There is no certificate request to cancel.",404);
    if(current.at("state")=="succeeded" || current.at("state")=="failed" || current.at("state")=="cancelled") return current;
    impl_->cancelled=true;impl_->wake.notify_all();
    current["cancel_requested"]=true;
    return current;
}
std::optional<HttpResponse> AcmeManager::challenge(const HttpRequest& request) const{return impl_->challenge(request);}
}
