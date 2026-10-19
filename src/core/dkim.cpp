#include <postplus/dkim.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace postplus {
namespace {
namespace fs=std::filesystem;
constexpr std::size_t max_key_bytes=16384,max_message_bytes=100*1024*1024,max_header_bytes=65536;
template<class T,auto Free>using Owned=std::unique_ptr<T,decltype(Free)>;
using Key=Owned<EVP_PKEY,EVP_PKEY_free>;
using Bio=Owned<BIO,BIO_free>;
[[noreturn]]void invalid(const char* message){throw std::invalid_argument(message);}
bool wsp(char c){return c==' ' || c=='\t';}
bool labels(std::string_view value) {
    if(value.empty() || value.size()>253)return false;
    std::size_t length=0;char previous=0;
    for(unsigned char c:value) {
        if(c=='.'){if(!length || previous=='-')return false;length=0;}
        else if(!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-') || (!length && c=='-') || ++length>63)return false;
        previous=static_cast<char>(c);
    }
    return length && previous!='-';
}
Key private_key(std::string_view pem) {
    if(pem.empty() || pem.size()>max_key_bytes)invalid("DKIM private key is empty or too large");
    auto text=trim(std::string(pem));
    if(!text.starts_with("-----BEGIN PRIVATE KEY-----") && !text.starts_with("-----BEGIN RSA PRIVATE KEY-----"))invalid("DKIM requires an unencrypted RSA private PEM key");
    Bio bio(BIO_new_mem_buf(text.data(),static_cast<int>(text.size())),BIO_free);
    Key key(bio?PEM_read_bio_PrivateKey(bio.get(),nullptr,[](char*,int,int,void*){return 0;},nullptr):nullptr,EVP_PKEY_free);
    if(!key || EVP_PKEY_is_a(key.get(),"RSA")!=1 || EVP_PKEY_get_bits(key.get())<2048 || EVP_PKEY_get_bits(key.get())>4096)invalid("DKIM requires a valid RSA private key of 2048 to 4096 bits");
    std::array<char,1024> rest{};int count=0;
    while((count=BIO_read(bio.get(),rest.data(),static_cast<int>(rest.size())))>0)
        for(int i=0;i<count;++i)if(!wsp(rest[static_cast<std::size_t>(i)]) && rest[static_cast<std::size_t>(i)]!='\r' && rest[static_cast<std::size_t>(i)]!='\n')invalid("DKIM PEM must contain exactly one private key");
    Owned<EVP_PKEY_CTX,EVP_PKEY_CTX_free> check(EVP_PKEY_CTX_new(key.get(),nullptr),EVP_PKEY_CTX_free);
    if(!check || EVP_PKEY_private_check(check.get())!=1)invalid("DKIM private key failed validation");
    return key;
}
std::string public_record(EVP_PKEY* key) {
    const int size=i2d_PUBKEY(key,nullptr);
    if(size<=0 || size>4096)throw std::runtime_error("cannot encode DKIM public key");
    std::string bytes(static_cast<std::size_t>(size),'\0');auto* out=reinterpret_cast<unsigned char*>(bytes.data());
    if(i2d_PUBKEY(key,&out)!=size)throw std::runtime_error("cannot encode DKIM public key");
    return "v=DKIM1; k=rsa; h=sha256; p="+base64_encode(bytes);
}
std::string normalized_message(std::string_view raw) {
    if(raw.size()>max_message_bytes)invalid("DKIM message exceeds the supported size limit");
    std::string out;out.reserve(raw.size()+2);
    for(std::size_t i=0;i<raw.size();++i) {
        if(raw[i]=='\r') {if(i+1==raw.size() || raw[i+1]!='\n')invalid("DKIM message contains a bare carriage return");out+="\r\n";++i;}
        else if(raw[i]=='\n')out+="\r\n";
        else out+=raw[i];
    }
    if(!out.ends_with("\r\n"))out+="\r\n";
    return out;
}
struct Header{std::string name,value;};
std::vector<Header> headers(std::string_view message,std::size_t& body_start) {
    const auto end=message.find("\r\n\r\n");
    if(end==std::string_view::npos || end>max_header_bytes)invalid("DKIM message requires a bounded header section and separator");
    body_start=end+4;std::vector<Header> result;std::size_t at=0;
    while(at<=end) {
        const auto next=message.find("\r\n",at);const auto line=message.substr(at,next-at);at=next+2;
        if(line.empty() || line.size()>998)invalid("DKIM message contains an invalid header line");
        for(unsigned char c:line)if((c<32 && c!='\t') || c==127)invalid("DKIM message contains an invalid header control byte");
        if(wsp(line.front())) {
            if(result.empty())invalid("DKIM message has an orphan folded header");
            result.back().value+="\r\n";result.back().value+=line;
        } else {
            const auto colon=line.find(':');
            if(colon==std::string_view::npos || !colon || result.size()>=256)invalid("DKIM message has invalid or excessive headers");
            for(unsigned char c:line.substr(0,colon))if(c<=32 || c>=127)invalid("DKIM message has an invalid header name");
            result.push_back({lower(std::string(line.substr(0,colon))),std::string(line.substr(colon+1))});
        }
    }
    return result;
}
std::string relaxed_value(std::string_view value) {
    std::string out;bool space=false;
    for(std::size_t i=0;i<value.size();++i) {
        if(value[i]=='\r' && i+1<value.size() && value[i+1]=='\n'){++i;continue;}
        if(wsp(value[i])){space=true;continue;}
        if(space && !out.empty())out+=' ';space=false;out+=value[i];
    }
    return out;
}
std::string canonical_header(const Header& field){return field.name+":"+relaxed_value(field.value);}
std::string from_domain(const std::vector<Header>& fields) {
    const Header* from=nullptr;
    for(const auto& field:fields)if(field.name=="from"){if(from)invalid("DKIM requires exactly one From header");from=&field;}
    if(!from)invalid("DKIM requires exactly one From header");
    auto address=relaxed_value(from->value);const auto open=address.find('<');
    if(open!=std::string::npos) {
        const auto close=address.find('>',open+1);
        if(close==std::string::npos || address.find('<',open+1)!=std::string::npos || address.find('>')!=close || !trim(address.substr(close+1)).empty())invalid("DKIM From must contain a single mailbox");
        bool quoted=false,escaped=false;unsigned comments=0;
        for(char c:address.substr(0,open)) {
            if(escaped){escaped=false;continue;}
            if(c=='\\' && (quoted || comments)){escaped=true;continue;}
            if(!quoted && c=='('){++comments;continue;}
            if(!quoted && c==')'){if(!comments)invalid("DKIM From contains an invalid display name");--comments;continue;}
            if(comments)continue;
            if(c=='\"'){quoted=!quoted;continue;}
            if(!quoted && (c==',' || c==':' || c==';' || c=='>' || c=='@' || c=='\\'))invalid("DKIM From must contain a single mailbox");
        }
        if(quoted || escaped || comments)invalid("DKIM From contains an invalid display name");
        address=trim(address.substr(open+1,close-open-1));
    }
    if(!valid_address(address))invalid("DKIM From must be a valid mailbox in the configured domain");
    return lower(address.substr(address.rfind('@')+1));
}
std::string relaxed_body(std::string_view body) {
    std::string out;out.reserve(body.size());std::size_t at=0,last_nonempty=0;
    while(at<body.size()) {
        const auto end=body.find("\r\n",at);const auto line=body.substr(at,end==std::string_view::npos?body.size()-at:end-at);
        bool space=false;const auto start=out.size();
        for(char c:line){if(wsp(c)){space=true;continue;}if(space)out+=' ';space=false;out+=c;}
        if(out.size()!=start){out+="\r\n";last_nonempty=out.size();}else out+="\r\n";
        if(end==std::string_view::npos)break;at=end+2;
    }
    out.resize(last_nonempty);return out;
}
std::string body_hash(std::string_view body) {
    const auto canonical=relaxed_body(body);std::array<unsigned char,EVP_MAX_MD_SIZE> digest{};unsigned size=0;
    if(EVP_Digest(canonical.data(),canonical.size(),digest.data(),&size,EVP_sha256(),nullptr)!=1)throw std::runtime_error("cannot hash DKIM body");
    return base64_encode({reinterpret_cast<const char*>(digest.data()),size});
}
const std::vector<std::string> protected_names={"from","sender","reply-to","to","cc","subject","date","message-id","in-reply-to","references","mime-version","content-type","content-transfer-encoding","content-disposition","content-id","content-description","resent-from","resent-sender","resent-to","resent-cc","resent-date","resent-message-id","list-id","list-help","list-unsubscribe","list-unsubscribe-post","list-subscribe","list-post","list-owner","list-archive","auto-submitted"};
std::string rsa_signature(EVP_PKEY* key,std::string_view bytes) {
    Owned<EVP_MD_CTX,EVP_MD_CTX_free> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);EVP_PKEY_CTX* rsa=nullptr;std::size_t size=0;
    if(!context || EVP_DigestSignInit(context.get(),&rsa,EVP_sha256(),nullptr,key)!=1 || EVP_PKEY_CTX_set_rsa_padding(rsa,RSA_PKCS1_PADDING)!=1 ||
       EVP_DigestSign(context.get(),nullptr,&size,reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size())!=1)throw std::runtime_error("cannot initialize DKIM signature");
    std::string signature(size,'\0');
    if(EVP_DigestSign(context.get(),reinterpret_cast<unsigned char*>(signature.data()),&size,reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size())!=1)throw std::runtime_error("cannot create DKIM signature");
    signature.resize(size);return base64_encode(signature);
}
#ifdef _WIN32
struct Handle{HANDLE value=INVALID_HANDLE_VALUE;~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
void private_acl(HANDLE file) {
    PSID owner=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    const auto error=GetSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&descriptor);
    std::unique_ptr<void,decltype(&LocalFree)> holder(descriptor,LocalFree);
    if(error!=ERROR_SUCCESS || !owner || !acl)invalid("cannot validate DKIM private key permissions");
    std::array<unsigned char,SECURITY_MAX_SID_SIZE> system{},admins{};DWORD a=static_cast<DWORD>(system.size()),b=static_cast<DWORD>(admins.size());
    if(!CreateWellKnownSid(WinLocalSystemSid,nullptr,system.data(),&a) || !CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admins.data(),&b))invalid("cannot validate DKIM private key permissions");
    HANDLE token=nullptr;DWORD token_bytes=0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))invalid("cannot validate DKIM private key identity");
    GetTokenInformation(token,TokenUser,nullptr,0,&token_bytes);std::vector<unsigned char> identity(token_bytes);
    const bool identified=GetTokenInformation(token,TokenUser,identity.data(),token_bytes,&token_bytes)!=0;CloseHandle(token);
    if(!identified)invalid("cannot validate DKIM private key identity");
    const auto user=reinterpret_cast<TOKEN_USER*>(identity.data())->User.Sid;
    for(DWORD index=0;index<acl->AceCount;++index) {
        void* raw=nullptr;if(!GetAce(acl,index,&raw))invalid("cannot inspect DKIM private key permissions");
        const auto* header=static_cast<const ACE_HEADER*>(raw);
        if(header->AceType==ACCESS_DENIED_ACE_TYPE)continue;
        if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE)invalid("unsupported DKIM private key permissions");
        const auto* ace=static_cast<const ACCESS_ALLOWED_ACE*>(raw);auto* sid=const_cast<DWORD*>(&ace->SidStart);
        if(!EqualSid(sid,owner) && !EqualSid(sid,user) && !EqualSid(sid,system.data()) && !EqualSid(sid,admins.data()) &&
           (ace->Mask&(GENERIC_ALL|GENERIC_READ|GENERIC_WRITE|FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|DELETE|WRITE_DAC|WRITE_OWNER)))invalid("DKIM private key must exclude unrelated users");
    }
}
#else
struct Descriptor{int value=-1;~Descriptor(){if(value>=0)::close(value);}Descriptor()=default;Descriptor(const Descriptor&)=delete;Descriptor&operator=(const Descriptor&)=delete;};
#endif
}

bool valid_dkim_domain(std::string_view value) {
    if(!labels(value) || value.find('.')==std::string_view::npos)return false;
    const auto name=lower(std::string(value)),suffix=name.substr(name.rfind('.')+1);
    if(suffix=="localhost" || suffix=="local" || suffix=="test" || suffix=="invalid" || suffix=="example" || suffix.find_first_not_of("0123456789")==std::string::npos)return false;
    return true;
}
bool valid_dkim_selector(std::string_view value){return value.size()<=63 && value.find('.')==std::string_view::npos && labels(value);}
bool valid_dkim_record_name(std::string_view domain,std::string_view selector) {
    return valid_dkim_domain(domain) && valid_dkim_selector(selector) && domain.size()+selector.size()+12<=253;
}
DkimKeyPair generate_dkim_key() {
    Owned<EVP_PKEY_CTX,EVP_PKEY_CTX_free> context(EVP_PKEY_CTX_new_from_name(nullptr,"RSA",nullptr),EVP_PKEY_CTX_free);EVP_PKEY* raw=nullptr;
    if(!context || EVP_PKEY_keygen_init(context.get())!=1 || EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(),2048)!=1 || EVP_PKEY_keygen(context.get(),&raw)!=1)throw std::runtime_error("cannot generate DKIM RSA key");
    Key key(raw,EVP_PKEY_free);Bio bio(BIO_new(BIO_s_mem()),BIO_free);
    if(!bio || PEM_write_bio_PrivateKey(bio.get(),key.get(),nullptr,nullptr,0,nullptr,nullptr)!=1)throw std::runtime_error("cannot encode DKIM private key");
    char* bytes=nullptr;const long size=BIO_get_mem_data(bio.get(),&bytes);
    if(size<=0)throw std::runtime_error("cannot encode DKIM private key");
    return {std::string(bytes,static_cast<std::size_t>(size)),public_record(key.get())};
}
std::string dkim_public_record(std::string_view pem){auto key=private_key(pem);return public_record(key.get());}
std::string load_dkim_private_key(const fs::path& path) {
    if(path.empty())invalid("DKIM private key path is empty");const auto absolute=fs::absolute(path).lexically_normal();std::string result;
#ifdef _WIN32
    fs::path current;
    for(const auto& component:absolute){current/=component;const auto attributes=GetFileAttributesW(current.c_str());if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_REPARSE_POINT))invalid("DKIM private key path must not contain symbolic links");}
    Handle file;file.value=CreateFileW(absolute.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    if(file.value==INVALID_HANDLE_VALUE || GetFileType(file.value)!=FILE_TYPE_DISK || !GetFileInformationByHandle(file.value,&info) ||
       (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) || info.nFileSizeHigh || info.nFileSizeLow>max_key_bytes)invalid("DKIM private key must be a bounded regular file");
    private_acl(file.value);std::array<char,1024> buffer{};DWORD count=0;
    while(true){if(!ReadFile(file.value,buffer.data(),static_cast<DWORD>(buffer.size()),&count,nullptr))invalid("cannot read DKIM private key");if(!count)break;if(result.size()+count>max_key_bytes)invalid("DKIM private key is too large");result.append(buffer.data(),count);}
#else
    Descriptor file;file.value=::open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(file.value<0)invalid("cannot open DKIM key directory");
    const auto relative=absolute.relative_path();
    for(auto it=relative.begin();it!=relative.end();++it){auto next=it;++next;const int opened=::openat(file.value,it->c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|(next==relative.end()?O_NONBLOCK:O_DIRECTORY));if(opened<0)invalid("DKIM private key path must be readable and contain no symbolic links");::close(file.value);file.value=opened;}
    struct stat status{};
    if(::fstat(file.value,&status)!=0 || !S_ISREG(status.st_mode) || status.st_size<0 || static_cast<std::uintmax_t>(status.st_size)>max_key_bytes)invalid("DKIM private key must be a bounded regular file");
    if((status.st_mode&(S_IRWXG|S_IRWXO))!=0)invalid("DKIM private key needs owner-only permissions (0600)");
    std::array<char,1024> buffer{};
    while(true){const auto count=::read(file.value,buffer.data(),buffer.size());if(count<0){if(errno==EINTR)continue;invalid("cannot read DKIM private key");}if(!count)break;if(result.size()+static_cast<std::size_t>(count)>max_key_bytes)invalid("DKIM private key is too large");result.append(buffer.data(),static_cast<std::size_t>(count));}
#endif
    (void)private_key(result);return result;
}
std::string dkim_sign(std::string_view raw,std::string_view domain_value,std::string_view selector_value,std::string_view pem) {
    if(!valid_dkim_record_name(domain_value,selector_value))invalid("DKIM requires a public domain and valid selector name");
    const auto domain=lower(std::string(domain_value)),selector=lower(std::string(selector_value));auto key=private_key(pem);
    const auto message=normalized_message(raw);std::size_t body_start=0;const auto fields=headers(message,body_start);
    if(from_domain(fields)!=domain)invalid("DKIM From must be a valid mailbox in the configured domain");
    std::vector<std::string> signed_names;std::string input,h;
    for(const auto& name:protected_names) {
        for(auto it=fields.rbegin();it!=fields.rend();++it)if(it->name==name){signed_names.push_back(name);input+=canonical_header(*it)+"\r\n";}
        // An extra absent occurrence detects insertion of another signed header.
        signed_names.push_back(name);
    }
    std::size_t column=3;
    for(const auto& name:signed_names){if(!h.empty()){h+=':';++column;}if(column+name.size()>74){h+="\r\n\t";column=1;}h+=name;column+=name.size();}
    const auto signature_header="DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; q=dns/txt;\r\n\td="+domain+"; s="+selector+";\r\n\th="+h+";\r\n\tbh="+body_hash(std::string_view(message).substr(body_start))+";\r\n\tb=";
    input+=canonical_header({"dkim-signature",signature_header.substr(signature_header.find(':')+1)});
    const auto signature=rsa_signature(key.get(),input);std::string folded;
    for(std::size_t at=0;at<signature.size();at+=64){if(at)folded+="\r\n\t";folded+=signature.substr(at,64);}
    return signature_header+folded+"\r\n"+message;
}
std::string sign_dkim(const Config& config,std::string_view raw) {
    const auto mode=config.outbound_mode();const auto configured=config.text("dkim_private_key");
    if(mode=="direct" && configured.empty())invalid("Direct delivery requires a DKIM private key");
    if(mode!="direct" && mode!="relay")return std::string(raw);
    if(configured.empty())return std::string(raw);
    fs::path path=configured;if(path.is_relative() && !config.source.empty())path=config.source.parent_path()/path;
    const auto message=normalized_message(raw);std::size_t body_start=0;
    const auto domain=from_domain(headers(message,body_start));
    if(!config.hosts_domain(domain))invalid("DKIM From must belong to a configured mail domain");
    return dkim_sign(raw,domain,config.text("dkim_selector","postplus"),load_dkim_private_key(path));
}
}
