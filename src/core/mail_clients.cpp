#include <postplus/mail_clients.hpp>
#include <postplus/settings.hpp>
#include <algorithm>
#include <regex>

namespace postplus {
namespace {
std::string xml(std::string_view input) {
    std::string result;
    for (const auto ch : input) {
        switch (ch) {
        case '&': result += "&amp;"; break;
        case '<': result += "&lt;"; break;
        case '>': result += "&gt;"; break;
        case '\"': result += "&quot;"; break;
        case '\'': result += "&apos;"; break;
        default: result += ch;
        }
    }
    return result;
}
std::string decode_query(std::string_view input) {
    std::string result;
    auto hex = [](char ch) { if (ch >= '0' && ch <= '9') return ch-'0'; if (ch >= 'a' && ch <= 'f') return ch-'a'+10; if (ch >= 'A' && ch <= 'F') return ch-'A'+10; return -1; };
    for (std::size_t i = 0; i < input.size(); ++i) {
        unsigned char ch = input[i];
        if (ch == '%') {
            if (i+2 >= input.size() || hex(input[i+1]) < 0 || hex(input[i+2]) < 0) throw std::invalid_argument("query");
            ch = static_cast<unsigned char>(hex(input[i+1])*16+hex(input[i+2])); i += 2;
        } else if (ch == '+') ch = ' ';
        if (ch < 32 || ch == 127) throw std::invalid_argument("query");
        result += static_cast<char>(ch);
    }
    return result;
}
bool local_email(const Config& config, const std::string& email) {
    return config.local_address(email);
}
HttpResponse failure(int status, const std::string& message) {
    return {status, "text/plain; charset=utf-8", message, {{"Cache-Control", "no-store"}}};
}
Json preferred(const Json& listeners, const std::string& protocol) {
    for (const auto& name : protocol == "smtp" ? std::vector<std::string>{"submission", "smtps", "smtp"} :
             protocol == "imap" ? std::vector<std::string>{"imaps", "imap"} : std::vector<std::string>{"pop3s", "pop3"})
        for (const auto& listener : listeners) if (listener.at("name") == name) return listener;
    return Json();
}
}

Json mail_client_settings(const Config& config) {
    const bool tls = !config.text("tls_certificate").empty() && !config.text("tls_private_key").empty();
    auto listeners = Json::array();
    for (const auto& service : {"smtp", "imap", "pop3"})
        for (const auto& listener : config.listeners(service))
            listeners.push_back({{"name", listener.name}, {"protocol", service}, {"port", listener.port},
                {"security", listener.implicit_tls ? "SSL/TLS" : tls ? "STARTTLS" : "none"}});
    const bool discovery = tls && config.port("web") == 443;
    const auto origin = settings_url(config, "web");
    return {{"hostname", config.mail_hostname()}, {"domains",config.mail_domains()}, {"tls", tls}, {"username", "full_email_address"},
        {"listeners", listeners}, {"discovery", {{"enabled", discovery}, {"aliases", false},
        {"autoconfig_url", origin + ".well-known/autoconfig/mail/config-v1.1.xml"},
        {"autodiscover_url", origin + "autodiscover/autodiscover.xml"}}}};
}

std::optional<HttpResponse> mail_client_discovery(const Config& config, const HttpRequest& request) {
    const auto path = lower(request.path.substr(0, request.path.find('?')));
    const bool autoconfig = path == "/mail/config-v1.1.xml" || path == "/.well-known/autoconfig/mail/config-v1.1.xml";
    const bool autodiscover = path == "/autodiscover/autodiscover.xml";
    if (!autoconfig && !autodiscover) return std::nullopt;
    if (!request.encrypted) return failure(403, "HTTPS is required for mail client discovery.");
    const auto settings = mail_client_settings(config);
    if (!settings.at("tls").get<bool>()) return failure(503, "Configure a mail server TLS certificate first.");
    if (request.path.size() > 4096 || request.body.size() > 4096) return failure(413, "Discovery request is too large.");
    std::string email;
    if (autoconfig) {
        if (request.method != "GET") return failure(405, "Use GET for autoconfig.");
        const auto question = request.path.find('?');
        if (question != std::string::npos) {
            auto query = std::string_view(request.path).substr(question+1);
            bool seen = false;
            try {
                while (!query.empty()) {
                    const auto end = query.find('&'); const auto item = query.substr(0, end);
                    const auto equal = item.find('=');
                    if (equal == std::string_view::npos) return failure(400, "Invalid discovery query.");
                    if (decode_query(item.substr(0, equal)) == "emailaddress") {
                        if (seen) return failure(400, "Duplicate email address.");
                        email = lower(trim(decode_query(item.substr(equal+1)))); seen = true;
                    }
                    if (end == std::string_view::npos) break;
                    query.remove_prefix(end+1);
                }
            } catch (const std::exception&) { return failure(400, "Invalid discovery query."); }
        }
    } else {
        if (request.method != "POST") return failure(405, "Use POST for autodiscover.");
        // This endpoint only extracts one literal address. DTDs, entities and
        // external resources are never interpreted by an XML parser.
        if (request.body.find("<!") != std::string::npos || request.body.find('&') != std::string::npos)
            return failure(400, "Unsupported discovery XML.");
        static const std::regex address(R"(<(?:[A-Za-z_][\w.-]*:)?EMailAddress\s*>\s*([^<>]+)\s*</(?:[A-Za-z_][\w.-]*:)?EMailAddress\s*>)", std::regex::icase);
        std::sregex_iterator first(request.body.begin(), request.body.end(), address), end;
        if (first == end) return failure(400, "An email address is required.");
        email = lower(trim((*first)[1].str()));
        if (++first != end) return failure(400, "Duplicate email address.");
    }
    if ((!email.empty() && !local_email(config, email)) || (autodiscover && email.empty()))
        return failure(404, "This server does not host that email domain.");
    const auto hostname = xml(config.mail_hostname());
    const auto domain = xml(config.text("domain", "localhost"));
    const auto username = xml(email.empty() ? "%EMAILADDRESS%" : email);
    std::string body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
    if (autoconfig) {
        body += "<clientConfig version=\"1.1\"><emailProvider id=\""+domain+"\">";
        for(const auto& mail:config.mail_domains())body+="<domain>"+xml(mail)+"</domain>";
        body+="<displayName>PostPlus</displayName><displayShortName>PostPlus</displayShortName>";
        for (const auto& protocol : {"imap", "pop3", "smtp"}) {
            const auto listener = preferred(settings.at("listeners"), protocol);
            if (listener.is_null()) continue;
            const std::string tag = std::string(protocol) == "smtp" ? "outgoingServer" : "incomingServer";
            body += "<"+tag+" type=\""+protocol+"\"><hostname>"+hostname+"</hostname><port>"+
                std::to_string(listener.at("port").get<int>())+"</port><socketType>"+
                (listener.at("security") == "SSL/TLS" ? "SSL" : "STARTTLS")+
                "</socketType><authentication>password-cleartext</authentication><username>"+username+"</username></"+tag+">";
        }
        body += "</emailProvider></clientConfig>";
    } else {
        body += "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\"><Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\"><Account><AccountType>email</AccountType><Action>settings</Action>";
        for (const auto& protocol : {"imap", "pop3", "smtp"}) {
            const auto listener = preferred(settings.at("listeners"), protocol);
            if (listener.is_null()) continue;
            const std::string type = std::string(protocol) == "imap" ? "IMAP" : std::string(protocol) == "pop3" ? "POP3" : "SMTP";
            body += "<Protocol><Type>"+type+"</Type><Server>"+hostname+"</Server><Port>"+
                std::to_string(listener.at("port").get<int>())+"</Port><LoginName>"+username+
                "</LoginName><SSL>"+(listener.at("security") == "SSL/TLS" ? "on" : "off")+
                "</SSL><Encryption>"+(listener.at("security") == "SSL/TLS" ? "SSL" : "TLS")+
                "</Encryption><SPA>off</SPA><AuthRequired>on</AuthRequired></Protocol>";
        }
        body += "</Account></Response></Autodiscover>";
    }
    return HttpResponse{200, "application/xml; charset=utf-8", std::move(body), {{"Cache-Control", "no-store"}}};
}
}
