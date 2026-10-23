#include <postplus/domain_tls.hpp>
#include <postplus/domains.hpp>
#include <postplus/settings.hpp>
#include <postplus/restart.hpp>
#include <postplus/tls.hpp>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <set>

namespace postplus {
namespace {
std::string digest(std::string_view text) {
    std::array<unsigned char,EVP_MAX_MD_SIZE> bytes{};unsigned size=0;
    if(EVP_Digest(text.data(),text.size(),bytes.data(),&size,EVP_sha256(),nullptr)!=1)
        throw std::runtime_error("cannot calculate TLS configuration revision");
    std::string output;constexpr char alphabet[]="0123456789abcdef";
    for(unsigned index=0;index<size;++index){output+=alphabet[bytes[index]>>4];output+=alphabet[bytes[index]&15];}
    return output;
}
std::string contents(const std::filesystem::path& path) {
    std::error_code error;const auto status=std::filesystem::symlink_status(path,error);
    if(error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status) || std::filesystem::file_size(path)>1048576)
        throw SettingsError("","Configuration must be a regular file no larger than 1 MiB.",409);
    std::ifstream file(path,std::ios::binary);if(!file)throw SettingsError("","Cannot read configuration file.",503);
    return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
}
struct Snapshot {Config config;std::string raw,revision;};
Snapshot snapshot(const Config& running) {
    Snapshot result;
    if(running.source.empty()){result.config=running;result.raw=running.values.dump();}
    else {result.raw=contents(running.source);result.config=Config::from_file(running.source);
        if(contents(running.source)!=result.raw)throw SettingsError("","Configuration changed while it was read. Reload the page.",409);}
    result.revision=digest(result.raw);return result;
}
std::map<std::string,std::vector<std::string>> hostnames(const Config& config,const std::string& domain) {
    bool known=config.hosts_domain(domain);
    if(const auto entries=config.values.find("domain_registry");entries!=config.values.end() && entries->is_object())known=known || entries->contains(domain);
    if(!known)throw SettingsError("domain","Add this mail domain before managing its certificates.",404);
    std::map<std::string,std::vector<std::string>> result;
    auto append=[&](const std::string& host,const char* role){if(!host.empty())result[host].push_back(role);};
    append(domain,"domain");append(webmail_hostname(config,domain),"webmail");
    // Shared service hostnames are managed from the primary domain, and from
    // their owning suffix when it is also hosted by this server.
    const bool primary=domain==config.text("domain","localhost");
    auto shared=[&](const std::string& host,const char* role){
        if(primary || host==domain || host.ends_with("."+domain))append(host,role);
    };
    shared(lower(trim(config.mail_hostname())),"mail");
    shared(lower(trim(config.text("admin_hostname"))),"admin");
    shared(lower(trim(config.text("webmail_shared_hostname"))),"shared_webmail");
    return result;
}
std::string path_field(const Json& request,const char* key,const Config& config) {
    if(!request.contains(key) || !request.at(key).is_string())throw SettingsError(key,"Provide a certificate file path and private key file path.");
    const auto value=trim(request.at(key).get<std::string>());
    if(value.size()>4096 || value.find('\0')!=std::string::npos)throw SettingsError(key,"The certificate file path is invalid.");
    if(value.empty())return {};
    auto path=std::filesystem::path(value);
    if(path.is_relative())path=config.source.parent_path()/path;
    return path.lexically_normal().string();
}
void validate_pair(const std::string& hostname,const std::string& certificate,const std::string& key) {
    try {
        const auto pair=load_tls_certificate_pair(certificate,key);
        auto* leaf=pair.get();
        if(!leaf || X509_check_host(leaf,hostname.c_str(),hostname.size(),X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,nullptr)!=1)
            throw SettingsError("tls_certificate","The certificate does not cover the selected hostname.");
        if(X509_cmp_current_time(X509_get0_notBefore(leaf))>=0 || X509_cmp_current_time(X509_get0_notAfter(leaf))<=0)
            throw SettingsError("tls_certificate","The certificate is expired or is not yet valid.");
    }catch(const SettingsError&){throw;}
    catch(const std::exception&){throw SettingsError("tls_certificate","TLS files must be readable PEM files with a matching, unencrypted private key.");}
}
Json view(const Snapshot& state,const std::string& domain) {
    Json entries=Json::array();const auto configured=state.config.values.value("domain_tls",Json::object());
    for(const auto& [host,roles]:hostnames(state.config,domain)) {
        const bool overridden=configured.contains(host);
        const auto certificate=overridden?configured.at(host).at("tls_certificate").get<std::string>():state.config.text("tls_certificate");
        const auto key=overridden?configured.at(host).at("tls_private_key").get<std::string>():state.config.text("tls_private_key");
        entries.push_back({{"hostname",host},{"roles",roles},{"configured",!certificate.empty()},{"inherited",!overridden},
            {"tls_certificate",certificate},{"tls_private_key",key}});
    }
    return {{"ok",true},{"domain",domain},{"revision",state.revision},{"hostnames",entries}};
}
}
void normalize_domain_tls(Config& config) {
    auto entries=config.values.find("domain_tls");if(entries==config.values.end())return;
    if(!entries->is_object())throw SettingsError("domain_tls","Domain TLS certificates must be an object keyed by hostname.");
    for(auto& entry:entries->items()) {
        if(entry.key()!=lower(trim(entry.key())) || !valid_address("postmaster@"+entry.key()) || !entry.value().is_object() || entry.value().size()!=2)
            throw SettingsError("domain_tls","Each domain TLS entry needs a lowercase hostname and certificate/key paths.");
        for(const auto* key:{"tls_certificate","tls_private_key"}) {
            const auto path=path_field(entry.value(),key,config);
            if(path.empty())throw SettingsError("domain_tls","Each domain TLS entry requires both a certificate and private key.");
            entry.value()[key]=path;
        }
    }
}
Json domain_tls_view(const Config& running,const std::string& domain) {return view(snapshot(running),lower(trim(domain)));}
Json save_domain_tls(const Config& running,const Json& request) {
    static const std::set<std::string> fields{"revision","domain","hostname","tls_certificate","tls_private_key"};
    if(!request.is_object())throw SettingsError("","Send a TLS configuration object.");
    for(const auto& entry:request.items())if(!fields.contains(entry.key()))throw SettingsError(entry.key(),"Unknown certificate field.");
    if(running.source.empty())throw SettingsError("","A saved configuration file is required.",409);
    if(supervisor_restart_busy(running))throw SettingsError("","Wait for the service restart to finish before changing certificates.",409);
    auto state=snapshot(running);
    if(!request.contains("revision") || !request.at("revision").is_string())throw SettingsError("revision","Send the current configuration revision.");
    if(!secure_equal(request.at("revision").get<std::string>(),state.revision))throw SettingsError("revision","Configuration changed since it was opened. Reload before saving.",409);
    for(const auto* field:{"domain","hostname"})if(!request.contains(field) || !request.at(field).is_string())throw SettingsError(field,"Select a domain and certificate hostname.");
    const auto domain=lower(trim(request.at("domain").get<std::string>()));
    const auto hostname=lower(trim(request.at("hostname").get<std::string>()));
    if(!hostnames(state.config,domain).contains(hostname))throw SettingsError("hostname","Select a hostname configured for this mail domain.");
    const auto certificate=path_field(request,"tls_certificate",state.config),key=path_field(request,"tls_private_key",state.config);
    if(certificate.empty()!=key.empty())throw SettingsError("tls_certificate","Provide both a TLS certificate and private key, or clear both paths.");
    if(!certificate.empty())validate_pair(hostname,certificate,key);
    auto& entries=state.config.values["domain_tls"];if(entries.is_null())entries=Json::object();
    const bool establish_default=state.config.text("tls_certificate").empty() && !certificate.empty();
    if(certificate.empty())entries.erase(hostname);
    else {
        entries[hostname]={{"tls_certificate",certificate},{"tls_private_key",key}};
        // Only the first certificate establishes the compatibility default.
        // An existing default may cover other portal names, so changing one
        // hostname must never replace that shared certificate implicitly.
        if(establish_default){state.config.values["tls_certificate"]=certificate;state.config.values["tls_private_key"]=key;}
    }
    normalize_domain_tls(state.config);
    // Enabling TLS changes implicit listener defaults (notably Webmail from
    // port 80 to 443). Apply the normal cross-field checks before writing, but
    // do not materialize unrelated settings defaults in this domain update.
    if(establish_default)(void)validate_settings(state.config,Json::object());
    const auto replacement=state.config.values.dump(2)+"\n";
    replace_config_file(state.config.source,state.raw,replacement);
    state.revision=digest(replacement);
    auto result=view(state,domain);
    result["hostname"]=hostname;
    result["restart_required"]=!restart_plan(supervisor_running_config(running).value_or(running),state.config,"changed").empty();
    return result;
}
}
