#include <postplus/dkim.hpp>
#include <postplus/mime.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <algorithm>
#include <array>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace postplus;
namespace {
namespace fs=std::filesystem;
void check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
template<class F>void rejects(F fn){bool rejected=false;try{fn();}catch(const std::exception&){rejected=true;}check(rejected,"unsafe DKIM input accepted");}
std::string compact(std::string value){value.erase(std::remove_if(value.begin(),value.end(),[](char c){return c==' ' || c=='\t' || c=='\r' || c=='\n';}),value.end());return value;}
std::string strip(std::string value){const auto first=value.find_first_not_of(" \t\r\n"),last=value.find_last_not_of(" \t\r\n");return first==std::string::npos?"":value.substr(first,last-first+1);}
// Separate verifier: parses the transmitted signature and public DNS TXT,
// independently reconstructs h= selection and RFC 6376 canonical bytes, then
// invokes OpenSSL verification. It never calls signer canonicalization helpers.
struct Field{std::string name,value;};
struct Message{std::vector<Field> fields;std::string body;};
Message read_message(const std::string& raw) {
    Message result;const auto split=raw.find("\r\n\r\n");check(split!=std::string::npos,"verification input has no header separator");
    std::istringstream lines(raw.substr(0,split+2));std::string line;
    while(std::getline(lines,line)) {
        if(!line.empty() && line.back()=='\r')line.pop_back();
        if(!line.empty() && (line.front()==' ' || line.front()=='\t')){check(!result.fields.empty(),"orphan continuation in verifier");result.fields.back().value+="\r\n"+line;}
        else {const auto colon=line.find(':');check(colon!=std::string::npos,"invalid verification header");auto name=line.substr(0,colon);std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});result.fields.push_back({name,line.substr(colon+1)});}
    }
    result.body=raw.substr(split+4);return result;
}
std::string canonical_field(const Field& field) {
    std::string unfolded=std::regex_replace(field.value,std::regex("\r\n"),"");
    const auto reduced=std::regex_replace(unfolded,std::regex("[ \t]+")," ");
    return field.name+":"+strip(reduced);
}
std::string canonical_content(const std::string& body) {
    std::vector<std::string> lines;std::size_t pos=0;
    while(pos<body.size()){const auto end=body.find("\r\n",pos);std::string line=body.substr(pos,end==std::string::npos?body.size()-pos:end-pos);const auto last=line.find_last_not_of(" \t");line=last==std::string::npos?"":line.substr(0,last+1);line=std::regex_replace(line,std::regex("[ \t]+")," ");lines.push_back(line);if(end==std::string::npos)break;pos=end+2;}
    while(!lines.empty() && lines.back().empty())lines.pop_back();std::string output;for(const auto& line:lines)output+=line+"\r\n";return output;
}
std::map<std::string,std::string> tags(std::string value) {
    value=std::regex_replace(value,std::regex("\r\n"),"");std::map<std::string,std::string> result;std::istringstream parts(value);std::string part;
    while(std::getline(parts,part,';')){const auto equals=part.find('=');if(equals==std::string::npos)continue;const auto name=strip(part.substr(0,equals));check(!result.contains(name),"duplicate verifier tag");result[name]=strip(part.substr(equals+1));}return result;
}
std::string digest(const std::string& bytes) {
    std::array<unsigned char,EVP_MAX_MD_SIZE> output{};unsigned length=0;check(EVP_Digest(bytes.data(),bytes.size(),output.data(),&length,EVP_sha256(),nullptr)==1,"verifier hash failed");return base64_encode({reinterpret_cast<const char*>(output.data()),length});
}
bool verify(const std::string& raw,const std::string& txt) {
    try {
        const auto message=read_message(raw);auto signature=std::find_if(message.fields.begin(),message.fields.end(),[](const Field& field){return field.name=="dkim-signature";});if(signature==message.fields.end())return false;
        const auto metadata=tags(signature->value),record=tags(txt);
        if(metadata.at("v")!="1" || metadata.at("a")!="rsa-sha256" || metadata.at("c")!="relaxed/relaxed" || metadata.contains("l") || record.at("k")!="rsa")return false;
        if(compact(metadata.at("bh"))!=digest(canonical_content(message.body)))return false;
        std::string signed_bytes;std::vector<bool> selected(message.fields.size(),false);std::istringstream names(compact(metadata.at("h")));std::string name;bool from=false;
        while(std::getline(names,name,':')) {
            from=from || name=="from";
            for(std::size_t i=message.fields.size();i>0;--i)if(!selected[i-1] && message.fields[i-1].name==name){selected[i-1]=true;signed_bytes+=canonical_field(message.fields[i-1])+"\r\n";break;}
        }
        if(!from)return false;
        // b= is last in production. Remove its value and surrounding FWS as the
        // RFC requires, retaining all preceding tags and their exact content.
        const std::regex b_value("(^|;)\\s*b\\s*=([^;]*)");
        const auto emptied=std::regex_replace(signature->value,b_value,"$1 b=");
        signed_bytes+=canonical_field({"dkim-signature",emptied});
        const auto der=base64_decode(compact(record.at("p")));const auto* pointer=reinterpret_cast<const unsigned char*>(der.data());
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(d2i_PUBKEY(nullptr,&pointer,static_cast<long>(der.size())),EVP_PKEY_free);
        if(!key || pointer!=reinterpret_cast<const unsigned char*>(der.data()+der.size()) || EVP_PKEY_get_bits(key.get())!=2048)return false;
        const auto bytes=base64_decode(compact(metadata.at("b")));std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);EVP_PKEY_CTX* rsa=nullptr;
        if(!context || EVP_DigestVerifyInit(context.get(),&rsa,EVP_sha256(),nullptr,key.get())!=1 || EVP_PKEY_CTX_set_rsa_padding(rsa,RSA_PKCS1_PADDING)!=1)return false;
        return EVP_DigestVerify(context.get(),reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size(),reinterpret_cast<const unsigned char*>(signed_bytes.data()),signed_bytes.size())==1;
    }catch(const std::exception&){return false;}
}
std::string replace_once(std::string text,const std::string& before,const std::string& after){const auto at=text.find(before);check(at!=std::string::npos,"test replacement missing");text.replace(at,before.size(),after);return text;}
void write_private(const fs::path& path,const std::string& bytes,bool public_acl=false) {
#ifdef _WIN32
    HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=0,"test identity unavailable");DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);std::vector<unsigned char> identity(size);check(GetTokenInformation(token,TokenUser,identity.data(),size,&size)!=0,"test identity unavailable");CloseHandle(token);LPWSTR sid=nullptr;check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(identity.data())->User.Sid,&sid)!=0,"test SID unavailable");const std::wstring acl=public_acl?L"D:P(A;;FA;;;WD)":L"D:P(A;;FA;;;SY)(A;;FA;;;"+std::wstring(sid)+L")";LocalFree(sid);PSECURITY_DESCRIPTOR descriptor=nullptr;check(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)!=0,"test ACL unavailable");SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),descriptor,FALSE};const auto file=CreateFileW(path.c_str(),GENERIC_WRITE,0,&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);LocalFree(descriptor);check(file!=INVALID_HANDLE_VALUE,"test key creation failed");DWORD written=0;const bool ok=WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)!=0 && written==bytes.size();CloseHandle(file);check(ok,"test key write failed");
#else
    (void)public_acl;
    const int file=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);check(file>=0,"test key creation failed");const auto written=::write(file,bytes.data(),bytes.size());::close(file);check(written>=0 && static_cast<std::size_t>(written)==bytes.size(),"test key write failed");
#endif
}
}
int main() {
    fs::path directory;
    try {
        const auto key=generate_dkim_key();check(key.private_pem.starts_with("-----BEGIN PRIVATE KEY-----"),"private key encoding");check(key.txt_value==dkim_public_record(key.private_pem),"public TXT/key mismatch");check(key.txt_value.find("PRIVATE")==std::string::npos,"private key exposed in DNS");
        for(const auto* value:{"postplus","selector-2026"})check(valid_dkim_selector(value),"valid selector rejected");
        for(const auto* value:{"","bad_selector","-x","x-","a.b","a..b","x; d=evil.com","x\r\nBad: yes"})check(!valid_dkim_selector(value),"invalid selector accepted");
        check(valid_dkim_selector(std::string(63,'s')) && !valid_dkim_selector(std::string(64,'s')),"selector must be a single label of at most 63 characters");
        const auto longest_domain=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(46,'c')+".com";
        check(valid_dkim_record_name(longest_domain,std::string(63,'s')) && !valid_dkim_record_name(longest_domain+"m",std::string(63,'s')),"full DKIM DNS record name length was not bounded");
        check(valid_dkim_domain("example.com") && valid_dkim_domain("EXAMPLE.COM"),"public domain rejected");for(const auto* value:{"localhost","mail.example.test","127.0.0.1","a..com","a.123","a.com; s=x"})check(!valid_dkim_domain(value),"invalid signing domain accepted");
        const std::string prefix="From: \"Last, First\" <alice@example.com>\r\nTo: bob@example.net\r\nSubject:  A\t folded\r\n\t subject  \r\nSubject: second\r\nDate: Mon, 12 Oct 2026 12:00:00 +0000\r\nMessage-ID: <one@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        const auto original=prefix+"  hello\t world \t\r\n.second\r\n\r\n";const auto signed_mail=dkim_sign(original,"example.com","postplus",key.private_pem);
        check(verify(signed_mail,key.txt_value),"independent RSA verification failed");check(signed_mail.ends_with(original),"signing changed MIME content");check(dkim_sign(original,"example.com","postplus",key.private_pem)==signed_mail,"folding/signature is not deterministic");
        check(!verify(replace_once(signed_mail,"hello","changed"),key.txt_value),"body tamper passed");check(!verify(replace_once(signed_mail,"Subject: second","Subject: changed"),key.txt_value),"header tamper passed");check(!verify(replace_once(signed_mail,"d=example.com","d=evil.com"),key.txt_value),"signature metadata tamper passed");check(!verify(signed_mail,generate_dkim_key().txt_value),"wrong DNS key verified");
        check(!verify("Subject: injected\r\n"+signed_mail,key.txt_value),"duplicate Subject insertion passed oversigning");check(!verify("From: attacker@example.com\r\n"+signed_mail,key.txt_value),"duplicate From insertion passed oversigning");check(!verify("Reply-To: attacker@example.net\r\n"+signed_mail,key.txt_value),"absent-header insertion passed oversigning");
        check(verify("Received: by downstream.example.net; now\r\n"+signed_mail,key.txt_value),"downstream trace header broke signature");
        check(verify(replace_once(signed_mail,"  hello\t world \t"," hello  world"),key.txt_value),"relaxed body whitespace tolerance failed");check(verify(replace_once(signed_mail,"Subject: second","sUbJeCt:\tsecond  "),key.txt_value),"relaxed header whitespace tolerance failed");
        const auto message=read_message(signed_mail);check(tags(message.fields.front().value).at("bh")==digest(" hello world\r\n.second\r\n"),"RFC relaxed canonical body vector differs");
        for(const auto& body:std::vector<std::string>{"","\r\n"," \t\r\n\r\n","x","x\n","x\r\n\r\n","\r\nx\t  \r\n\r\n"}) {
            const auto signed_case=dkim_sign(prefix+body,"example.com","postplus",key.private_pem);check(verify(signed_case,key.txt_value),"empty/newline/body canonicalization failed");
            if(body.empty() || body=="\r\n" || body==" \t\r\n\r\n")check(tags(read_message(signed_case).fields.front().value).at("bh")=="47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=","empty relaxed body must hash zero octets");
        }
        const std::string mime="From: alice@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC/v8=\r\n--x--\r\n";
        const auto signed_mime=dkim_sign(mime,"example.com","postplus",key.private_pem);check(signed_mime.ends_with(mime) && verify(signed_mime,key.txt_value),"MIME attachment changed or failed verification");check(mime::parse(signed_mime).parts[0].body==std::string("\0\1\2\xfe\xff",5),"binary attachment preservation failed");
        const auto lf="From: alice@example.com\nSubject: LF\n\nhello\n";const auto signed_lf=dkim_sign(lf,"example.com","postplus",key.private_pem);check(verify(signed_lf,key.txt_value) && signed_lf.ends_with("From: alice@example.com\r\nSubject: LF\r\n\r\nhello\r\n"),"CRLF transport normalization failed");
        for(const auto& invalid:std::vector<std::string>{"Subject: missing\r\n\r\nx","From: alice@evil.com\r\n\r\nx","From: alice@example.com, bob@example.com\r\n\r\nx","From: alice@example.com\r\nFrom: bob@example.com\r\n\r\nx","From: group: Alice <alice@example.com>;\r\n\r\nx","From: attacker@evil.com <alice@example.com>\r\n\r\nx","From: Alice (unclosed <alice@example.com>\r\n\r\nx","From: Alice <alice@example.com> junk\r\n\r\nx","From: alice@example.com\rInjected: yes\r\n\r\nx","From: alice@example.com\r\nBad Header: x\r\n\r\nx"," continuation\r\nFrom: alice@example.com\r\n\r\nx"})rejects([&]{dkim_sign(invalid,"example.com","postplus",key.private_pem);});
        rejects([&]{dkim_sign(original,"evil.com","postplus",key.private_pem);});rejects([&]{dkim_sign(original,"example.com","x; d=evil.com",key.private_pem);});rejects([&]{dkim_public_record("not a private key");});rejects([&]{dkim_public_record(key.private_pem+key.private_pem);});
        std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)> weak_context(EVP_PKEY_CTX_new_from_name(nullptr,"RSA",nullptr),EVP_PKEY_CTX_free);EVP_PKEY* weak_raw=nullptr;check(weak_context && EVP_PKEY_keygen_init(weak_context.get())==1 && EVP_PKEY_CTX_set_rsa_keygen_bits(weak_context.get(),1024)==1 && EVP_PKEY_keygen(weak_context.get(),&weak_raw)==1,"weak-key fixture failed");std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> weak_key(weak_raw,EVP_PKEY_free);std::unique_ptr<BIO,decltype(&BIO_free)> weak_bio(BIO_new(BIO_s_mem()),BIO_free);check(PEM_write_bio_PrivateKey(weak_bio.get(),weak_key.get(),nullptr,nullptr,0,nullptr,nullptr)==1,"weak-key fixture failed");char* weak_data=nullptr;const auto weak_size=BIO_get_mem_data(weak_bio.get(),&weak_data);rejects([&]{dkim_sign(original,"example.com","postplus",std::string_view(weak_data,static_cast<std::size_t>(weak_size)));});
        directory=fs::current_path()/"build"/("dkim-test-"+random_hex(8));fs::create_directories(directory);const auto file=directory/"key.pem";write_private(file,key.private_pem);check(load_dkim_private_key(file)==key.private_pem,"private key loader changed bytes");rejects([&]{load_dkim_private_key(directory);});write_private(directory/"oversize.pem",std::string(16385,'x'));rejects([&]{load_dkim_private_key(directory/"oversize.pem");});
        std::error_code link_error;fs::create_symlink(file,directory/"link.pem",link_error);if(!link_error)rejects([&]{load_dkim_private_key(directory/"link.pem");});
#ifdef _WIN32
        write_private(directory/"public.pem",key.private_pem,true);rejects([&]{load_dkim_private_key(directory/"public.pem");});
#endif
#ifndef _WIN32
        fs::permissions(file,fs::perms::owner_read|fs::perms::owner_write|fs::perms::group_read);rejects([&]{load_dkim_private_key(file);});fs::permissions(file,fs::perms::owner_read|fs::perms::owner_write);
        fs::create_directory_symlink(directory,directory.parent_path()/(directory.filename().string()+"-link"));rejects([&]{load_dkim_private_key(directory.parent_path()/(directory.filename().string()+"-link")/"key.pem");});fs::remove(directory.parent_path()/(directory.filename().string()+"-link"));
#endif
        Config config;config.source=directory/"config.json";config.values={{"domain","example.com"},{"outbound_mode","direct"},{"dkim_private_key","key.pem"}};check(verify(sign_dkim(config,original),key.txt_value),"config signing/default selector or relative path failed");config.values["dkim_private_key"]="";rejects([&]{sign_dkim(config,original);});config.values["outbound_mode"]="relay";check(sign_dkim(config,original)==original,"relay without key must preserve raw message");config.values["dkim_private_key"]="key.pem";check(verify(sign_dkim(config,original),key.txt_value),"optional relay signing failed");
        config.values["additional_domains"]=Json::array({"example.net"});
        const auto secondary=replace_once(original,"alice@example.com","alice@example.net"),signed_secondary=sign_dkim(config,secondary);
        check(verify(signed_secondary,key.txt_value) && signed_secondary.find("d=example.net;")!=std::string::npos,"secondary domain must sign with matching d= and shared public key");
        rejects([&]{sign_dkim(config,replace_once(original,"alice@example.com","alice@foreign.example.org"));});
        fs::remove_all(directory);std::cout<<"PASS independent DKIM RSA verification, DNS public key, relaxed/relaxed vectors, MIME/CRLF preservation, repeated-header oversigning, tampering, From-domain validation and private-file safety\n";return 0;
    }catch(const std::exception& error){if(!directory.empty()){std::error_code ignored;fs::remove_all(directory,ignored);}std::cerr<<error.what()<<'\n';return 1;}
}
