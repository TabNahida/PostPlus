#include <postplus/remote_image.hpp>
#include <atomic>
#include <iostream>
#include <sstream>
#include <thread>

using namespace postplus;
namespace {
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<unsigned char>;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F function) {
    try { function(); } catch (const RemoteImageError&) { return; }
    throw std::runtime_error("Unsafe remote image was accepted");
}
void number(Bytes& data, unsigned value) { data.push_back(static_cast<unsigned char>(value >> 8)); data.push_back(static_cast<unsigned char>(value)); }
struct Dns {
    std::string address = "93.184.216.34";
    unsigned requests = 0;
    Bytes send(const Bytes& question) {
        ++requests; std::size_t end = 12;
        while (question.at(end)) end += question.at(end) + 1;
        ++end; const unsigned type = (question.at(end) << 8) | question.at(end + 1); end += 4;
        const auto ip = postplus::ip::make_address(address); const bool answer = (type == 1 && ip.is_v4()) || (type == 28 && ip.is_v6());
        Bytes result{question[0], question[1]}; number(result, 0x8180); number(result, 1); number(result, answer ? 1 : 0); number(result, 0); number(result, 0);
        result.insert(result.end(), question.begin() + 12, question.begin() + static_cast<std::ptrdiff_t>(end));
        if (answer) {
            number(result, 0xc00c); number(result, type); number(result, 1); result.insert(result.end(), {0, 0, 0, 60});
            if (ip.is_v4()) { const auto bytes = ip.to_v4().to_bytes(); number(result, 4); result.insert(result.end(), bytes.begin(), bytes.end()); }
            else { const auto bytes = ip.to_v6().to_bytes(); number(result, 16); result.insert(result.end(), bytes.begin(), bytes.end()); }
        }
        return result;
    }
    DnsOptions options() { DnsOptions result; result.transport = [this](const auto& wire, auto) { return send(wire); }; return result; }
};
class Server {
    SocketListener acceptor_{{ip::address_v4::loopback(),0}};
    std::thread thread_;
    std::exception_ptr failure_;
public:
    template<class F> explicit Server(F handler) {
        thread_ = std::thread([this, handler] { try {
            Connection peer(std::chrono::seconds(2));
            acceptor_.accept(peer,std::chrono::seconds(5));
            peer.set_deadline(Clock::now() + std::chrono::seconds(4)); handler(peer);
        } catch (...) { failure_ = std::current_exception(); } });
    }
    ~Server() { acceptor_.close(); if (thread_.joinable()) thread_.join(); }
    int port() const { return acceptor_.local_endpoint().port(); }
    void finish() { if (thread_.joinable()) thread_.join(); if (failure_) std::rethrow_exception(failure_); }
};
const std::string png = base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jw1sAAAAASUVORK5CYII=");
std::string request(Connection& peer) {
    std::string result;
    for (;;) { const auto line = peer.line(); if (line.empty()) return result; result += line + "\r\n"; }
}
RemoteImageOptions options(Dns& dns, Server& server, bool tls = true) {
    RemoteImageOptions result; result.dns = dns.options();
    result.connect = [&server, tls](Connection& peer, const tcp::endpoint& destination, const std::string& host, bool secure) {
        check(host == "images.example.com" && is_public_mail_address(destination.address()), "DNS endpoint was not pinned to a public address");
        check(destination.port() == (tls ? 443 : 80) && secure == tls, "Wrong remote image transport");
        // Offline native fixture maps a verified destination to our local peer.
        peer.connect({ip::address_v4::loopback(), static_cast<unsigned short>(server.port())});
    }; return result;
}
void response(Connection& peer, const std::string& headers, const std::string& body = png) {
    (void)request(peer); peer.write("HTTP/1.1 200 OK\r\n" + headers + "\r\n" + body);
}
void accepted_length() {
    Dns dns; std::string received;
    Server server([&](Connection& peer) { received = request(peer); peer.write("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: " + std::to_string(png.size()) + "\r\nCross-Origin-Resource-Policy: same-origin\r\nSet-Cookie: remote=discard\r\n\r\n" + png); });
    const auto value = fetch_remote_image("https://images.example.com/logo.png?x=1&y=2", options(dns, server)); server.finish();
    check(value.content_type == "image/png" && value.body == png && dns.requests == 2, "Raster fetch/CORP-compatible bytes changed");
    check(received.starts_with("GET /logo.png?x=1&y=2 HTTP/1.1\r\nHost: images.example.com\r\n"), "Wrong image target or TLS hostname");
    for (const auto* header : {"Cookie:", "Authorization:", "Referer:", "Origin:"}) check(received.find(header) == received.npos, "Browser credentials leaked to remote image");
}
void accepted_chunks() {
    Dns dns; Server server([](Connection& peer) { (void)request(peer);
        peer.write("HTTP/1.1 200 OK\r\nContent-Type: IMAGE/PNG; ignored=parameter\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n" + png.substr(0, 8) + "\r\n");
        const auto tail = png.substr(8); std::ostringstream size; size << std::hex << tail.size(); peer.write(size.str() + "\r\n" + tail + "\r\n0\r\n\r\n");
    });
    const auto value = fetch_remote_image("http://images.example.com:80/logo.png", options(dns, server, false)); server.finish(); check(value.body == png, "Chunked raster fetch failed");
}
void rejected_responses() {
    for (const auto& item : std::vector<std::pair<std::string, std::string>>{
        {"Content-Type: image/svg+xml\r\nContent-Length: 6\r\n", "<svg/>"},
        {"Content-Type: image/png\r\nContent-Length: 13\r\n", "<html></html>"},
        {"Content-Type: image/png\r\nContent-Length: 2097153\r\n", ""},
        {"Content-Type: image/png\r\nContent-Length: 4\r\nContent-Length: 4\r\n", "aaaa"},
        {"Content-Type: image/png\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n", "aaaa"},
        {"Content-Type: image/png\r\nContent-Length: 4\r\nContent-Encoding: gzip\r\n", "aaaa"},
        {"Content-Type: image/png\r\nContent-Length: 4\r\nContent-Type: image/jpeg\r\n", "aaaa"},
        {"Content-Type: image/png\r\nTransfer-Encoding: chunked\r\n", "200001\r\n"},
        {"Content-Type: image/png\r\n", ""}}) {
        Dns dns; Server server([&](Connection& peer) { response(peer, item.first, item.second); });
        rejects([&] { (void)fetch_remote_image("https://images.example.com/a", options(dns, server)); }); server.finish();
    }
    Dns dns; Server server([](Connection& peer) { (void)request(peer); peer.write("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\n\r\n"); });
    rejects([&] { (void)fetch_remote_image("https://images.example.com/a", options(dns, server)); }); server.finish(); check(dns.requests == 2, "Redirect unexpectedly performed a second DNS lookup");
}
void blocked_destinations() {
    for (const auto* target : {"https://127.0.0.1/a", "http://[::1]/a", "https://user@images.example.com/a", "http://localhost/a", "https://images.local/a", "https://images.example.com:444/a", "http://images.example.com:443/a", "ftp://images.example.com/a", "https://images.example.com/a#x", "https://images.example.com/a\r\nCookie: x", "https://images.example.com\\@127.0.0.1/a"}) {
        Dns dns; RemoteImageOptions opts; opts.dns = dns.options(); rejects([&] { (void)fetch_remote_image(target, opts); }); check(!dns.requests, "Invalid URL reached DNS");
    }
    for (const auto* ip : {"127.0.0.1", "10.0.0.1", "172.16.1.2", "192.168.1.3", "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "2001:db8::1"}) {
        Dns dns; dns.address = ip; RemoteImageOptions opts; opts.dns = dns.options(); bool connected = false;
        opts.connect = [&](auto&, const auto&, const auto&, auto) { connected = true; throw std::runtime_error("Private connection"); };
        rejects([&] { (void)fetch_remote_image("https://images.example.com/a", opts); }); check(!connected, "Private or special address reached connector");
    }
}
void extraction() {
    const auto urls = extract_remote_image_urls("<!-- <img src='https://bad.example.com/hidden'> --><script>\"<img src='https://bad.example.com/script'>\"</script><style>.a{background:url(https://bad.example.com/css)}</style><a href='https://bad.example.com/link'>x</a><img src='https://images.example.com/a?x=1&amp;y=2'><IMG SRC='https&#58;//images.example.com/b'><img src='cid:logo'><img src='data:image/png;base64,x'><img src='https://images.example.com/a?x=1&amp;y=2'><img src='http://127.0.0.1/a'><img src='https://images.example.com/first' src='https://bad.example.com/duplicate'><imgfoo src='https://bad.example.com/nonimage'>");
    check(urls == std::vector<std::string>{"https://images.example.com/a?x=1&y=2", "https://images.example.com/b", "https://images.example.com/first"}, "Image-only extraction/entity decoding or duplicate attributes changed");
    std::string many; for (unsigned index = 0; index < 100; ++index) many += "<img src='https://images.example.com/" + std::to_string(index) + "'>";
    check(extract_remote_image_urls(many).size() == 64, "Remote image count limit failed");
}
void concurrent_readers() {
    std::atomic<unsigned> ready{0}, failed{0}, current{0}, peak{0};
    std::vector<std::thread> readers;
    for (unsigned index = 0; index < 5; ++index) readers.emplace_back([&] {
        try {
            Dns dns; Server server([&](Connection& peer) {
                (void)request(peer); const auto active = ++current;
                auto previous = peak.load(); while (previous < active && !peak.compare_exchange_weak(previous, active)) {}
                std::this_thread::sleep_for(std::chrono::milliseconds(80));
                --current;
                peer.write("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: " + std::to_string(png.size()) + "\r\n\r\n" + png);
            });
            ++ready; while (ready.load() < 5) std::this_thread::yield();
            const auto image = fetch_remote_image("https://images.example.com/a", options(dns, server));
            server.finish(); if (image.body != png) ++failed;
        } catch (...) { ++failed; }
    });
    for (auto& reader : readers) reader.join();
    check(failed == 0, "A fifth reader lost its image instead of waiting for a bounded slot");
    check(peak <= 4, "Remote image connection concurrency limit exceeded");
}
}
int main(int argc, char** argv) {
    const char* stage = "extraction";
    try {
        // Optional explicit public fixture check; regular tests remain offline.
        if (argc == 2 && std::string_view(argv[1]) == "--public-fixture") {
            stage = "public image";
            const auto image = fetch_remote_image("https://claude.ai/images/email/claude_logo_chip.png");
            check(image.content_type == "image/png" && image.body.size() > 8, "Public raster image missing");
            std::cout << "public PNG fetched: " << image.body.size() << " bytes\n"; return 0;
        }
        extraction(); stage = "content-length"; accepted_length(); stage = "chunked"; accepted_chunks(); stage = "response validation"; rejected_responses(); stage = "destination validation"; blocked_destinations(); stage = "concurrent readers"; concurrent_readers(); std::cout << "remote image tests passed\n"; return 0;
    }
    catch (const std::exception& error) { std::cerr << stage << ": " << error.what() << '\n'; return 1; }
}
