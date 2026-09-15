#include <postplus/core.hpp>
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
