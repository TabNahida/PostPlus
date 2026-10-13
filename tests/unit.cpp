#include <postplus/core.hpp>
#include <postplus/settings.hpp>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace postplus;
namespace {
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template<class F> void rejects(F operation) {
    bool rejected = false;
    try { operation(); } catch (const std::exception&) { rejected = true; }
    check(rejected,"malformed input accepted");
}
}
int main() {
    try {
        check(valid_address("alice+tag@example.test"),"valid email rejected");
        check(valid_address("postmaster@localhost"),"local email rejected");
        for (const auto* value : {"a\r\nRCPT TO:x@y", "@x", "a@", "a@@b", "a@-b", "a@b-", "a@b..c", ".a@b", "a.@b", "a b@c", "a@b_"}) check(!valid_address(value),"invalid email accepted");
        for (const auto& value : {std::string{},std::string("f"),std::string("fo"),std::string("foo"),std::string("\0\xff\x01",3)}) check(base64_decode(base64_encode(value)) == value,"binary base64 roundtrip");
        for (const auto* value : {"abc", "====", "AA=A", "AA==junk", "AB==", "aGVsbG8=\n"}) rejects([&] { base64_decode(value); });
        check(secure_equal("secret","secret") && !secure_equal("secret","secreT") && !secure_equal("secret","secrets"),"secret comparison");
        check(random_hex().size() == 32 && random_hex() != random_hex(),"random ID");
        Config legacy;legacy.values={{"domain","example.com"}};
        for (const auto& field : settings_schema(Config{}))
            if (field.at("key")=="ports.web") check(field.at("default")==80,"empty configuration schema default");
        check(legacy.port("smtp")==25,"default SMTP must receive Internet mail on port 25");
        check(legacy.port("pop3")==110 && legacy.port("imap")==143 && legacy.port("web")==80,"standard cleartext protocol ports");
        check(legacy.port("submission")==587 && legacy.port("smtps")==465 && legacy.port("pop3s")==995 && legacy.port("imaps")==993,"standard encrypted client ports");
        check(legacy.listeners("smtp").size()==1 && legacy.listeners("imap").size()==1,"TLS-only listeners disabled without credentials");
        legacy.values["tls_certificate"]="certificate.pem"; legacy.values["tls_private_key"]="key.pem";
        check(legacy.port("web")==443 && legacy.listeners("smtp").size()==3 && legacy.listeners("pop3").size()==2,"TLS protocol defaults");
        check(legacy.listeners("smtp")[1].name=="submission" && !legacy.listeners("smtp")[1].implicit_tls && legacy.listeners("smtp")[2].implicit_tls,"submission encryption modes");
        legacy.values["ports"]={{"submission",0},{"smtps",0},{"pop3s",0},{"imaps",0},{"web",8080}};
        check(legacy.listeners("smtp").size()==1 && legacy.listeners("pop3").size()==1 && legacy.port("web")==8080,"explicit disable and custom Web port");
        legacy.values.erase("tls_certificate"); legacy.values.erase("tls_private_key");
        legacy.values["ports"]={{"smtp",2525}};
        check(legacy.port("smtp")==2525,"explicit legacy SMTP port must be preserved");
        for (const auto& value : {Json(-1), Json(65536), Json(4294967297ULL), Json(1.5), Json("587"), Json(true)}) {
            Config malformed; malformed.values["ports"]={{"submission",value}};
            rejects([&] { malformed.port("submission"); });
        }
        Config malformed; malformed.values["ports"]={{"smtp",0}};
        rejects([&] { malformed.port("smtp"); });
        Config hostname; hostname.values["domain"]="mail.example.com";
        check(hostname.mail_hostname()=="mail.example.com","mail hostname duplicated prefix");
        hostname.values["domain"]="localhost";
        check(hostname.mail_hostname()=="localhost","localhost mail hostname");
        check(legacy.outbound_mode()=="disabled","legacy blank relay must remain disabled");
        legacy.values["smarthost_host"]="smtp.example.com";
        check(legacy.outbound_mode()=="relay" && legacy.mail_hostname()=="mail.example.com","relay mode and public hostname default");
        legacy.values["outbound_mode"]="direct";
        check(legacy.mail_hostname()=="mail.example.com","direct EHLO default hostname");
        legacy.values["outbound_mode"]="disabled";
        check(legacy.outbound_mode()=="disabled","explicit outbound disable ignored");
        legacy.values.erase("outbound_mode");legacy.values["allow_insecure_auth"]=true;
        check(validate_settings(legacy,{{"log_level","debug"}}).outbound_mode()=="relay","partial settings save disabled legacy relay");
        // Exercise real TCP framing, buffered command boundaries and exact byte reads.
        asio::io_context io;
        tcp::acceptor acceptor(io,{tcp::v4(),0});
        const int port = acceptor.local_endpoint().port();
        std::exception_ptr failure;
        std::thread server([&] {
            try {
                Connection peer;
                acceptor.accept(peer.socket());
                check(peer.line() == "one","line one");
                check(peer.line() == "two","line two");
                check(peer.read(3) == std::string("\0x\xff",3),"binary bytes");
                peer.write("OK\r\n");
            } catch (...) { failure = std::current_exception(); }
        });
        try {
            Connection client;
            client.connect("127.0.0.1",port);
            client.write(std::string("one\r\ntwo\r\n\0x\xff",13));
            check(client.line() == "OK","reply");
        } catch (...) { server.join(); throw; }
        server.join();
        if (failure) std::rethrow_exception(failure);
        std::cout << "Core tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
