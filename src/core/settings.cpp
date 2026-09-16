#include <postplus/settings.hpp>
#include <asio/ssl.hpp>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <fstream>
#include <mutex>
#include <set>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace postplus {
namespace {
namespace fs = std::filesystem;
Json fields() {
    Json result = Json::array();
    auto add = [&](std::string key, std::string group, std::string type, Json value,
                   std::string label, std::string help = "", int minimum = 0, int maximum = 0) {
        Json entry = {{"key",key},{"group",group},{"type",type},{"default",value},{"label",label},{"help",help}};
        if (type == "number") { entry["min"] = minimum; entry["max"] = maximum; }
        result.push_back(std::move(entry));
    };
    add("domain","general","text","localhost","Mail domain","Domain used for local recipient addresses; changing it does not rename existing accounts.");
    add("bind","network","text","127.0.0.1","Mail and Webmail listening address","Use 127.0.0.1 for local use or 0.0.0.0 to accept IPv4 connections from other computers.");
    add("admin_bind","network","text","127.0.0.1","Administration listening address","Keep 127.0.0.1 unless remote administration is needed; public access requires TLS.");
    const std::map<std::string,int> ports = {{"smtp",2525},{"pop3",1110},{"imap",1143},{"web",8080},{"admin",8081},{"auth",18081},{"storage",18082},{"filter",18083},{"transfer",18084}};
    const std::map<std::string,std::string> port_labels={{"smtp","SMTP"},{"pop3","POP3"},{"imap","IMAP"},{"web","Webmail"},{"admin","Administration"},{"auth","Authentication"},{"storage","Mail storage"},{"filter","Mail filter"},{"transfer","Mail transfer"}};
    for (const auto& [name,port] : ports) add("ports."+name,"network","number",port,port_labels.at(name)+" port","Every service needs a different port. Internal services listen on loopback.",1,65535);
    add("delivery_lock_port","network","number",18085,"Delivery lock port","Loopback port used to prevent duplicate delivery workers.",1,65535);
    add("allow_insecure_auth","security","boolean",false,"Allow local plaintext authentication","Only loopback clients may authenticate without TLS. Disable for deployment.");
    add("tls_certificate","security","text","","TLS certificate file","Readable PEM certificate chain; paths are relative to the configuration file.");
    add("tls_private_key","security","text","","TLS private key file","Matching unencrypted PEM private key. File contents are never exposed by this API.");
    add("max_auth_attempts","security","number",5,"Authentication attempts per connection","",1,20);
    add("auth_pbkdf2_iterations","security","number",600000,"Password hashing iterations","Applies to newly created or changed passwords.",600000,2000000);
    add("max_password_bytes","security","number",1024,"Maximum password bytes","",12,4096);
    add("web_session_seconds","security","number",3600,"Web session lifetime (seconds)","Applies to both administration and Webmail.",60,86400);
    add("max_web_sessions","security","number",1024,"Maximum web sessions per service","",1,10000);
    add("max_connections","limits","number",32,"Concurrent connections per service","Each active connection uses a worker thread.",1,1024);
    add("timeout_seconds","limits","number",30,"Network timeout (seconds)","",1,300);
    add("smtp_data_timeout_seconds","limits","number",120,"SMTP message upload timeout (seconds)","Total time allowed to upload one message.",1,3600);
    add("max_message_bytes","limits","number",10485760,"Maximum message bytes","10 MiB by default.",1024,104857600);
    add("max_recipients","limits","number",100,"Maximum recipients per message","",1,100);
    add("max_mailbox_bytes","storage","number",1073741824,"Maximum bytes per mailbox","",1024,2147483647);
    add("max_mailbox_messages","storage","number",10000,"Maximum messages per mailbox","",1,100000);
    add("max_queue_bytes","storage","number",1073741824,"Maximum queued message bytes","",1024,2147483647);
    add("max_queue_messages","storage","number",100000,"Maximum queued messages","",1,1000000);
    add("smarthost_host","delivery","text","","Outgoing relay host","Leave blank for local mail only. Use your provider's SMTP relay hostname.");
    add("smarthost_port","delivery","number",587,"Outgoing relay port","",1,65535);
    add("smarthost_tls","delivery","select","starttls","Outgoing relay encryption","Authenticated relays require STARTTLS or implicit TLS.");
    result.back()["options"] = Json::array({"starttls","implicit","none"});
    add("smarthost_timeout_seconds","delivery","number",30,"Outgoing relay timeout (seconds)","",1,300);
    add("smarthost_username","delivery","text","","Outgoing relay username");
    add("smarthost_password_env","delivery","text","POSTPLUS_SMARTHOST_PASSWORD","Relay password environment variable","An explicitly set environment variable takes precedence over the saved password.");
    add("smarthost_password","delivery","password","","Outgoing relay password","Leave blank to keep the saved password. New passwords are saved in a private secret file.");
    add("clamav_host","filter","text","","ClamAV host","Leave blank to use baseline filtering only. Install and run clamd separately.");
    add("clamav_port","filter","number",3310,"ClamAV port","",1,65535);
    add("clamav_timeout_seconds","filter","number",15,"ClamAV scan timeout (seconds)","",1,120);
    add("spam_threshold","filter","number",5,"Spam rejection score","Messages at or above this score are rejected.",1,1000);
    add("blocked_terms","filter","lines",Json::array(),"Blocked terms","One term per line; a match rejects the message.");
    add("spam_rules","filter","json",Json::array({{{"term","lottery winner"},{"weight",3}},{{"term","urgent money transfer"},{"weight",3}},{{"term","free money"},{"weight",2}},{{"term","viagra"},{"weight",2}},{{"term","click here"},{"weight",1}}}),"Weighted spam rules","JSON array of objects with term and positive weight.");
    add("log_level","logging","select","info","Minimum log level");
    result.back()["options"] = Json::array({"debug","info","warn","error"});
    add("log_max_bytes","logging","number",5242880,"Maximum bytes per log file","",1024,104857600);
    add("log_backups","logging","number",3,"Rotated log files per service","",1,10);
    for (const auto* key : {"data_dir","web_root","log_dir"}) {
        add(key,"paths","text","",key,"Configured during initial setup. Stop PostPlus and follow the configuration guide before changing filesystem paths.");
        result.back()["readonly"] = true;
    }
    return result;
}
const Json* get(const Json& object, const std::string& key) {
    const auto dot = key.find('.');
    if (dot == std::string::npos) return object.contains(key) ? &object.at(key) : nullptr;
    const auto parent = key.substr(0,dot), leaf = key.substr(dot+1);
    return object.contains(parent) && object.at(parent).is_object() && object.at(parent).contains(leaf) ? &object.at(parent).at(leaf) : nullptr;
}
void put(Json& object,const std::string& key,const Json& value) {
    const auto dot=key.find('.');
    if (dot==std::string::npos) object[key]=value;
    else object[key.substr(0,dot)][key.substr(dot+1)]=value;
}
std::string read_file(const fs::path& path) {
    std::error_code error;
    const auto status=fs::symlink_status(path,error);
    if (error || !fs::is_regular_file(status) || fs::is_symlink(status) || fs::file_size(path)>1048576)
        throw SettingsError("", "Configuration must be a regular file no larger than 1 MiB.",409);
    std::ifstream file(path,std::ios::binary);
    if (!file) throw SettingsError("", "Cannot read configuration file.",503);
    return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
}
std::string revision(const std::string& contents) {
    std::array<unsigned char,EVP_MAX_MD_SIZE> digest{};
    unsigned int size=0;
    if (EVP_Digest(contents.data(),contents.size(),digest.data(),&size,EVP_sha256(),nullptr)!=1)
        throw std::runtime_error("cannot calculate configuration revision");
    constexpr char digits[]="0123456789abcdef";
    std::string output;
    for (unsigned int i=0;i<size;++i) { output+=digits[digest[i]>>4]; output+=digits[digest[i]&15]; }
    return output;
}
void private_write(const fs::path& path,std::string_view contents) {
#ifdef _WIN32
    HANDLE token=nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) throw std::runtime_error("cannot read process identity");
    DWORD size=0; GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> user(size);
    const bool identified=GetTokenInformation(token,TokenUser,user.data(),size,&size)!=0;
    CloseHandle(token);
    if (!identified) throw std::runtime_error("cannot read process identity");
    LPWSTR sid=nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,&sid)) throw std::runtime_error("cannot read process identity");
    const std::wstring acl=L"D:P(A;;FA;;;SY)(A;;FA;;;"+std::wstring(sid)+L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) throw std::runtime_error("cannot create private file permissions");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),descriptor,FALSE};
    HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    LocalFree(descriptor);
    if (file==INVALID_HANDLE_VALUE) throw std::runtime_error("cannot create private configuration file");
    DWORD written=0;
    const bool saved=WriteFile(file,contents.data(),static_cast<DWORD>(contents.size()),&written,nullptr)!=0 && written==contents.size() && FlushFileBuffers(file)!=0;
    CloseHandle(file);
    if (!saved) { DeleteFileW(path.c_str()); throw std::runtime_error("cannot save private configuration file"); }
#else
    int flags=O_WRONLY|O_CREAT|O_EXCL;
#ifdef O_NOFOLLOW
    flags|=O_NOFOLLOW;
#endif
    const int file=::open(path.c_str(),flags,S_IRUSR|S_IWUSR);
    if (file<0) throw std::runtime_error("cannot create private configuration file");
    std::size_t offset=0; bool saved=true;
    while (offset<contents.size()) {
        const auto count=::write(file,contents.data()+offset,contents.size()-offset);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) {saved=false;break;} offset+=static_cast<std::size_t>(count);
    }
    if (::fsync(file)!=0) saved=false;
    if (::close(file)!=0) saved=false;
    if (!saved) {::unlink(path.c_str());throw std::runtime_error("cannot save private configuration file");}
#endif
}
struct RemoveOnExit {
    fs::path path;
    ~RemoveOnExit() { if(!path.empty()) {std::error_code ignored;fs::remove(path,ignored);} }
};
class ConfigLock {
public:
    explicit ConfigLock(const fs::path& destination) {
        const auto path=destination.parent_path()/(destination.filename().string()+".settings-lock");
        std::error_code error;
        if(!fs::exists(fs::symlink_status(path,error))) {
            try {private_write(path,"");} catch(const std::exception&) {
                if(!fs::is_regular_file(fs::symlink_status(path))) throw;
            }
        }
        const auto status=fs::symlink_status(path);
        if(!fs::is_regular_file(status) || fs::is_symlink(status)) throw SettingsError("","Unsafe configuration lock file.",503);
#ifdef _WIN32
        handle_=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(handle_==INVALID_HANDLE_VALUE) throw SettingsError("","Cannot open configuration lock.",503);
        if(!LockFileEx(handle_,LOCKFILE_EXCLUSIVE_LOCK,0,1,0,&overlapped_)) {
            CloseHandle(handle_);handle_=INVALID_HANDLE_VALUE;throw SettingsError("","Cannot lock configuration.",503);
        }
#else
        descriptor_=::open(path.c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW);
        if(descriptor_<0) throw SettingsError("","Cannot open configuration lock.",503);
        if(::flock(descriptor_,LOCK_EX)!=0) {::close(descriptor_);descriptor_=-1;throw SettingsError("","Cannot lock configuration.",503);}
#endif
    }
    ~ConfigLock() {
#ifdef _WIN32
        if(handle_!=INVALID_HANDLE_VALUE) {UnlockFileEx(handle_,0,1,0,&overlapped_);CloseHandle(handle_);}
#else
        if(descriptor_>=0) {::flock(descriptor_,LOCK_UN);::close(descriptor_);}
#endif
    }
private:
#ifdef _WIN32
    HANDLE handle_=INVALID_HANDLE_VALUE;
    OVERLAPPED overlapped_{};
#else
    int descriptor_=-1;
#endif
};
void safe_text(const std::string& key,const Json& value,std::size_t maximum=2048) {
    if (!value.is_string()) throw SettingsError(key,"Expected text for "+key+".");
    const auto& text=value.get_ref<const std::string&>();
    if (text.size()>maximum || text.find_first_of("\r\n\0",0,3)!=std::string::npos)
        throw SettingsError(key,"Invalid text for "+key+".");
}
}

Json settings_schema(const Config&) { return fields(); }

std::string settings_url(const Config& config,const std::string& service) {
    const bool tls=!config.text("tls_certificate").empty();
    auto host=config.text(service=="admin" ? "admin_bind" : "bind","127.0.0.1");
    if (host=="0.0.0.0" || host=="::") host=tls ? config.text("domain","localhost") : "127.0.0.1";
    if(tls && (host=="127.0.0.1" || host=="::1")) host="localhost";
    if (host.find(':')!=std::string::npos) host="["+host+"]";
    return std::string(tls ? "https://" : "http://")+host+":"+std::to_string(config.port(service))+"/";
}

Json settings_view(const Config& config) {
    Config current=config;
    std::string version;
    if (!config.source.empty()) {
        const auto raw=read_file(config.source);
        current=Config::from_file(config.source);
        if(read_file(config.source)!=raw) throw SettingsError("","Configuration changed while it was being read. Reload the page.",409);
        version=revision(raw);
    }
    Json values=Json::object();
    for (const auto& entry:fields()) {
        const auto key=entry.at("key").get<std::string>();
        if(entry.at("type")=="password") {put(values,key,"");continue;}
        const auto* value=get(current.values,key);
        put(values,key,value ? *value : entry.at("default"));
    }
    return {{"ok",true},{"values",values},{"revision",version},{"schema",settings_schema(current)},
        {"restart_required",!config.source.empty() && current.values!=config.values},
        {"secret_status",{{"smarthost_password",!current.text("smarthost_password_file").empty()}}},
        {"admin_url",settings_url(current,"admin")},{"web_url",settings_url(current,"web")}};
}

Config validate_settings(const Config& existing,const Json& patch) {
    if (!patch.is_object()) throw SettingsError("","Configuration values must be a JSON object.");
    Config result=existing;
    std::map<std::string,Json> schema;
    for (const auto& entry:fields()) schema.emplace(entry.at("key").get<std::string>(),entry);
    auto apply=[&](const std::string& key,const Json& value) {
        auto found=schema.find(key);
        if (found==schema.end()) throw SettingsError(key,"Unknown configuration field: "+key+".");
        const auto& entry=found->second;
        if(entry.value("readonly",false)) throw SettingsError(key,"This path cannot be changed through the web interface.");
        const auto type=entry.at("type").get<std::string>();
        if(type=="number") {
            if(!value.is_number_integer() || value.get<std::int64_t>()<entry.at("min").get<std::int64_t>() || value.get<std::int64_t>()>entry.at("max").get<std::int64_t>())
                throw SettingsError(key,key+" must be a whole number from "+entry.at("min").dump()+" to "+entry.at("max").dump()+".");
        } else if(type=="boolean") {
            if(!value.is_boolean()) throw SettingsError(key,"Expected true or false for "+key+".");
        } else if(type=="select") {
            if(!value.is_string() || std::find(entry.at("options").begin(),entry.at("options").end(),value)==entry.at("options").end()) throw SettingsError(key,"Choose a supported value for "+key+".");
        } else if(type=="lines") {
            if(!value.is_array() || value.size()>1000) throw SettingsError(key,"Provide at most 1000 blocked terms.");
            for(const auto& term:value) {safe_text(key,term,256); if(trim(term.get<std::string>()).empty()) throw SettingsError(key,"Blocked terms cannot be empty.");}
        } else if(type=="json") {
            if(!value.is_array() || value.size()>1000) throw SettingsError(key,"Provide at most 1000 spam rules.");
            for(const auto& rule:value) {
                if(!rule.is_object() || rule.size()!=2 || !rule.contains("term") || !rule.contains("weight") || !rule.at("weight").is_number()) throw SettingsError(key,"Spam rules require term and weight.");
                safe_text(key,rule.at("term"),256);
                const auto weight=rule.at("weight").get<double>();
                if(trim(rule.at("term").get<std::string>()).empty() || !std::isfinite(weight) || weight<=0 || weight>1000) throw SettingsError(key,"Each spam rule needs a term and a weight greater than 0 and at most 1000.");
            }
        } else { safe_text(key,value,type=="password" ? 4096 : 2048); }
        if(type!="password") put(result.values,key,value);
    };
    for(const auto& item:patch.items()) {
        if(item.key()=="clear_smarthost_password") {
            if(!item.value().is_boolean()) throw SettingsError(item.key(),"Expected true or false for clear_smarthost_password.");
        } else if(item.key()=="ports") {
            if(!item.value().is_object()) throw SettingsError("ports","Service ports must be a JSON object.");
            for(const auto& port:item.value().items()) apply("ports."+port.key(),port.value());
        } else apply(item.key(),item.value());
    }
    for (const auto& [key,entry]:schema) {
        if(entry.value("readonly",false) || entry.at("type")=="password") continue;
        const auto* value=get(result.values,key);
        apply(key,value ? *value : entry.at("default"));
    }
    const auto domain=lower(trim(result.text("domain","localhost")));
    if (!valid_address("postmaster@"+domain)) throw SettingsError("domain","Enter a valid ASCII mail domain, such as example.com.");
    result.values["domain"]=domain;
    const auto parent=result.source.empty() ? fs::current_path() : result.source.parent_path();
    for(const auto* field:{"tls_certificate","tls_private_key"}) {
        const auto value=trim(result.text(field));
        if(!value.empty()) {const fs::path path(value);result.values[field]=(path.is_relative()?parent/path:path).lexically_normal().string();}
    }
    const bool certificate=!result.text("tls_certificate").empty();
    if(certificate!=!result.text("tls_private_key").empty()) throw SettingsError("tls_certificate","Provide both a TLS certificate and private key.");
    for(const auto* field:{"bind","admin_bind"}) {
        std::error_code error;
        const auto address=asio::ip::make_address(result.text(field,"127.0.0.1"),error);
        if(error) throw SettingsError(field,"The listening address must be an IPv4 or IPv6 address.");
        if(!address.is_loopback() && (!certificate || result.flag("allow_insecure_auth"))) throw SettingsError(field,"Public listening addresses require TLS and disabled insecure authentication.");
    }
    if(!certificate && !result.flag("allow_insecure_auth")) throw SettingsError("tls_certificate","Provide TLS files or explicitly enable local plaintext authentication.");
    if(certificate) {
        try {
            asio::ssl::context tls(asio::ssl::context::tls_server);
            tls.set_password_callback([](std::size_t,asio::ssl::context::password_purpose){return std::string{};});
            tls.use_certificate_chain_file(result.text("tls_certificate"));
            tls.use_private_key_file(result.text("tls_private_key"),asio::ssl::context::pem);
            if(SSL_CTX_check_private_key(tls.native_handle())!=1) throw std::runtime_error("TLS mismatch");
        } catch(const std::exception&) {throw SettingsError("tls_certificate","TLS files must be readable PEM files with a matching, unencrypted private key.");}
    }
    std::set<int> ports;
    for(const auto* service:{"auth","storage","filter","transfer","smtp","pop3","imap","web","admin"})
        if(!ports.insert(result.port(service)).second) throw SettingsError("ports."+std::string(service),"Every PostPlus service must use a different port.");
    if(!ports.insert(result.number("delivery_lock_port",18085)).second) throw SettingsError("delivery_lock_port","Every PostPlus service must use a different port.");
    for(const auto* key:{"smarthost_host","smarthost_username","clamav_host"}) if(result.text(key).size()>253) throw SettingsError(key,"Hostnames and usernames must not exceed 253 bytes.");
    const auto env=result.text("smarthost_password_env");
    if(env.empty() || (env.front()>='0' && env.front()<='9') || env.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")!=std::string::npos) throw SettingsError("smarthost_password_env","Use a valid environment variable name for the relay password.");
    if(result.text("smarthost_tls")=="none" && !result.text("smarthost_username").empty()) throw SettingsError("smarthost_tls","An authenticated relay requires TLS.");
    for(const auto* key:{"max_mailbox_bytes","max_queue_bytes"})
        if(result.number(key,1073741824)<result.number("max_message_bytes",10485760)) throw SettingsError(key,"Storage byte limits must be at least the maximum message size.");
    return result;
}

void replace_config_file(const fs::path& destination,const std::string& expected,const std::string& replacement) {
    if(replacement.size()>1048576) throw SettingsError("","Configuration must not exceed 1 MiB.");
    static std::mutex writes;
    std::lock_guard guard(writes);
    ConfigLock file_lock(destination);
    if(read_file(destination)!=expected) throw SettingsError("","Configuration changed since it was opened. Reload before saving.",409);
    const auto suffix=random_hex(12);
    const auto temporary=destination.parent_path()/(destination.filename().string()+".save-"+suffix+".tmp");
    RemoveOnExit cleanup{temporary};
    private_write(temporary,replacement);
    const auto backup=destination.parent_path()/(destination.filename().string()+".backup-"+suffix);
    private_write(backup,expected);
    if(read_file(destination)!=expected) throw SettingsError("","Configuration changed since it was opened. Reload before saving.",409);
#ifdef _WIN32
    if(!MoveFileExW(temporary.c_str(),destination.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) throw SettingsError("","Cannot replace the configuration file. Check permissions.",503);
#else
    if(::rename(temporary.c_str(),destination.c_str())!=0) throw SettingsError("","Cannot replace the configuration file. Check permissions.",503);
    const int directory=::open(destination.parent_path().c_str(),O_RDONLY);
    if(directory>=0) {(void)::fsync(directory);::close(directory);}
#endif
}

Json save_settings(const Config& config,const Json& request) {
    static std::mutex saves;
    std::lock_guard guard(saves);
    if(!request.is_object() || request.size()!=2 || !request.contains("revision") || !request.at("revision").is_string() || !request.contains("values"))
        throw SettingsError("","Send a configuration revision and values object.");
    const auto raw=read_file(config.source);
    if(!secure_equal(request.at("revision").get<std::string>(),revision(raw))) throw SettingsError("","Configuration changed since it was opened. Reload before saving.",409);
    auto current=Config::from_file(config.source);
    if(read_file(config.source)!=raw) throw SettingsError("","Configuration changed while it was being read. Reload the page.",409);
    auto updated=validate_settings(current,request.at("values"));
    const auto& values=request.at("values");
    if(values.value("clear_smarthost_password",false)) {
        if(!values.value("smarthost_password",std::string{}).empty()) throw SettingsError("smarthost_password","Choose either a new relay password or removal of the saved password.");
        // Keep old secret files so a private configuration backup remains usable.
        updated.values.erase("smarthost_password_file");
    }
    // Check genuinely new ports now; old service ports are released together
    // by the supervisor, allowing deliberate port swaps within PostPlus.
    std::set<int> active_ports{config.number("delivery_lock_port",18085)};
    for(const auto* service:{"auth","storage","filter","transfer","smtp","pop3","imap","web","admin"}) active_ports.insert(config.port(service));
    asio::io_context context;
    for(const auto* service:{"auth","storage","filter","transfer","smtp","pop3","imap","web","admin","delivery"}) {
        const std::string name(service);
        const int port=name=="delivery" ? updated.number("delivery_lock_port",18085) : updated.port(name);
        if(active_ports.contains(port)) continue;
        const bool internal=name=="auth" || name=="storage" || name=="filter" || name=="transfer" || name=="delivery";
        const auto address=asio::ip::make_address(internal ? "127.0.0.1" : updated.text(name=="admin" ? "admin_bind" : "bind","127.0.0.1"));
        tcp::acceptor probe(context);
        std::error_code error;
        probe.open(address.is_v6()?tcp::v6():tcp::v4(),error);
        if(!error) probe.bind({address,static_cast<unsigned short>(port)},error);
        if(error) throw SettingsError(name=="delivery" ? "delivery_lock_port" : "ports."+name,"The requested service port is unavailable. Choose another port or check listening permissions.");
    }
    RemoveOnExit secret_cleanup;
    if(values.contains("smarthost_password") && !values.at("smarthost_password").get<std::string>().empty()) {
        const auto secret=config.source.parent_path()/(config.source.filename().string()+".relay-password-"+random_hex(12));
        private_write(secret,values.at("smarthost_password").get<std::string>());
        secret_cleanup.path=secret;
        updated.values["smarthost_password_file"]=secret.string();
    }
    replace_config_file(config.source,raw,updated.values.dump(2)+"\n");
    secret_cleanup.path.clear();
    log("admin","administrator saved server settings; restart required");
    return {{"ok",true},{"restart_required",true},{"admin_url",settings_url(updated,"admin")},{"web_url",settings_url(updated,"web")}};
}
}
