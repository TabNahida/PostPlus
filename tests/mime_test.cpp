#include "postplus/mime.hpp"
#include <iostream>
#include <stdexcept>

using namespace postplus::mime;
void check(bool condition, const char* reason) { if (!condition) throw std::runtime_error(reason); }
template<class F> void rejects(F fn) { bool rejected = false; try { fn(); } catch (const std::invalid_argument&) { rejected = true; } check(rejected, "malformed input accepted"); }
int main() {
    try {
        auto message = parse("Subject: hello\r\n world\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhello=20world=21=\r\nnext");
        check(header(message, "Subject") == "hello world", "header unfolding");
        check(message.body == "hello world!next", "quoted printable");
        auto multi = parse("Content-Type: multipart/mixed; boundary=\"a;b\"\r\n\r\npreamble\r\n--a;b\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--a;b\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--a;b--\r\nepilogue");
        check(multi.parts.size() == 2 && multi.parts[0].body == "hello" && multi.parts[1].body == "second", "multipart decoding");
        const std::string subject = "PostPlus UTF-8 \xe9\x82\xae\xe4\xbb\xb6 and a long subject that must fold safely across encoded words";
        auto raw = compose("alice@example.test", {"bob@example.test"}, subject, "hello\n.world\n");
        auto roundtrip = parse(raw);
        check(decode_header(header(roundtrip, "subject")) == subject, "encoded subject roundtrip");
        check(roundtrip.body == "hello\n.world\n", "body roundtrip");
        check(decode_header("=?UTF-8?Q?hello_world=21?=") == "hello world!", "Q header decoding");
        rejects([] { parse("Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\nx"); });
        rejects([] { parse("Content-Transfer-Encoding: base64\r\n\r\n###"); });
        rejects([] { parse("Content-Transfer-Encoding: quoted-printable\r\n\r\n=ZZ"); });
        rejects([] { parse("Content-Transfer-Encoding: 8bit\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8="); });
        rejects([] { parse("Content-Type: multipart/mixed; boundary=a; boundary=b\r\n\r\n--a\r\n\r\nx\r\n--a--\r\n"); });
        rejects([] { parse("Content-Type: message/rfc822\r\n\r\nContent-Type: message/rfc822\r\n\r\nSubject: nested\r\n\r\nx", Limits{1024, 256, 1}); });
        rejects([] { parse("X: y\r\n\r\nabc", Limits{2}); });
        rejects([] { parse("Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\nx\r\n--x--\r\n", Limits{1024, 1}); });
        rejects([] { compose("alice@example.test", {"bob@example.test"}, "subject\r\nBcc: bad@example.test", "text"); });
        std::cout << "MIME tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
