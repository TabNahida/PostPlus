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
        const std::string chinese = "\xe4\xb8\xad\xe6\x96\x87";
        const std::string supplementary = "\xf0\xa0\x80\x80";
        const std::string replacement = "\xef\xbf\xbd";
        const std::string gbk = "\xd6\xd0\xce\xc4";
        auto legacy = parse("Subject: =?GB2312?B?1tDOxA==?=\r\nContent-Type: text/plain; charset=\"Gb_2312-80\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=D6=D0=CE=C4");
        check(decode_text(legacy) == chinese && legacy.body == gbk, "GB2312 display conversion preserves source bytes");
        check(header(legacy, "content-type").find("Gb_2312-80") != std::string::npos, "charset header preserved");
        check(decode_header(header(legacy, "subject")) == chinese, "GB2312 B subject");
        check(decode_header("=?GBK?Q?=D6=D0=CE=C4?=") == chinese, "GBK Q subject");
        check(decode_header("=?GBK?B?1tDOxA==?= \r\n\t=?windows-1252?Q?_=80?=") == chinese + " \xe2\x82\xac", "adjacent encoded words with different charsets");
        check(decode_header("=?GBK?B?1tDOxA==?= \x96") == chinese + " \xe2\x80\x93", "legacy plain span does not corrupt decoded UTF8 word");
        check(decode_header("=?UTF-8?B?###?= plain") == "=?UTF-8?B?###?= plain", "malformed encoded word preserved");
        check(decode_header("=?unknown?Q?caf=E9?=") == "caf\xc3\xa9", "unknown header charset fallback");
        check(decode_header("=?UTF-8?Q?=FF?=") == replacement, "invalid UTF8 encoded word replacement");
        struct TextCase { const char* charset; std::string bytes; std::string expected; };
        const TextCase cases[] = {
            {"GBK", gbk, chinese},
            {"GB18030", gbk + "\x95\x32\x82\x36", chinese + supplementary},
            {"GB18030", "\x81\x30\x81\x30", "\xc2\x80"},
            {"GB18030", "\x90\x30\x81\x30", "\xf0\x90\x80\x80"},
            {"GB18030", "\xe3\x32\x9a\x35", "\xf4\x8f\xbf\xbf"},
            {"GB18030", std::string("\x95\x32\x82\x36") + "\xff" + gbk + "\x95\x32\x82\x36",
                supplementary + replacement + chinese + supplementary},
            {"Big5", "\xa4\xa4\xa4\xe5", chinese},
            {"WINDOWS-1252", "caf\xe9 \x97 \x80", "caf\xc3\xa9 \xe2\x80\x94 \xe2\x82\xac"},
            {"ISO-8859-1", "caf\xe9\x80", "caf\xc3\xa9\xc2\x80"},
            {"ISO-8859-2", "\xa1", "\xc4\x84"},
            {"ISO-8859-15", "\xa4", "\xe2\x82\xac"},
            {"UTF-8", chinese, chinese},
            {"UTF-8", "\xef\xbb\xbf" + chinese, chinese},
            {"UTF-8", "\xf0(\x8c(", replacement + "(" + replacement + "("},
            {"US-ASCII", "ok\xff", "ok" + replacement},
            {"GBK", "ok\xd6", "ok" + replacement},
            {"GBK", gbk + "\xff" + gbk, chinese + replacement + chinese},
            {"GB18030", "\x95\x32", replacement + "2"},
            {"UTF-16LE", "\x2d\x4e\x87\x65", chinese},
            {"UTF-16BE", std::string("\x4e\x2d\x65\x87\xd8\x3d\xde\0", 8), chinese + "\xf0\x9f\x98\x80"},
            {"UTF-16", "\xff\xfe\x2d\x4e\x87\x65", chinese},
            {"UTF-16LE", std::string("\0\xd8\x41\0\x01", 5), replacement + "A" + replacement},
            {"unrecognized", chinese, chinese},
            {"unrecognized", "caf\xe9", "caf\xc3\xa9"},
            {"UTF-8//IGNORE", "caf\xe9", "caf\xc3\xa9"},
            {"", "caf\xe9", "caf\xc3\xa9"},
            {"", "\xff\xfe\x2d\x4e\x87\x65", chinese},
            {"", std::string("\xff\xfe\0\0\0\0\x02\0", 8), supplementary}
        };
        for (const auto& fixture : cases) {
            auto part = parse(std::string("Content-Type: text/plain; charset=\"") + fixture.charset + "\"\r\n\r\n" + fixture.bytes);
            auto actual = decode_text(part);
            if (actual != fixture.expected) {
                std::cerr << fixture.charset << " actual UTF8 bytes:" << std::hex;
                for (unsigned char ch : actual) std::cerr << ' ' << static_cast<unsigned int>(ch);
                std::cerr << " expected:";
                for (unsigned char ch : fixture.expected) std::cerr << ' ' << static_cast<unsigned int>(ch);
                std::cerr << std::dec << '\n';
                check(false, "charset display conversion");
            }
            check(part.body == fixture.bytes, "display conversion mutated source body");
        }
        auto damaged = parse("Content-Type: text/plain; charset=GBK\r\n\r\n" + std::string(8192, 'a') + gbk + "\xff" + gbk + std::string(8192, 'z'));
        check(decode_text(damaged) == std::string(8192, 'a') + chinese + replacement + chinese + std::string(8192, 'z'), "damaged legacy charset preserves valid text across conversion blocks");
        const std::string html = "<html><head><META CHARSET='GBK'></head><body>" + gbk + "</body></html>";
        auto html_part = parse("Content-Type: text/html\r\n\r\n" + html);
        check(decode_text(html_part) == "<html><head><META CHARSET='GBK'></head><body>" + chinese + "</body></html>", "HTML charset meta");
        const std::string equiv = "<!-- <meta charset='windows-1252'> --><meta content=\"text/html; charset=gb18030\" http-equiv='Content-Type'><p>";
        check(decode_text(parse("Content-Type: text/html\r\n\r\n" + equiv + "\x95\x32\x82\x36")) == equiv + supplementary, "HTML http-equiv and commented meta");
        const std::string script_meta = "<script>var x = '<meta charset=gbk>';</script><meta charset=utf-8>";
        check(decode_text(parse("Content-Type: text/html\r\n\r\n" + script_meta + chinese)) == script_meta + chinese, "HTML script text is not charset declaration");
        const std::string declared = "<meta charset='GBK'><p>caf\xe9</p>";
        check(decode_text(parse("Content-Type: text/html; charset=windows-1252\r\n\r\n" + declared)) == "<meta charset='GBK'><p>caf\xc3\xa9</p>", "MIME charset takes precedence over HTML meta");
        check(decode_text(parse("Content-Type: text/html\r\n\r\n\xef\xbb\xbf<meta charset='GBK'>" + chinese)) == "<meta charset='GBK'>" + chinese, "Unicode BOM takes precedence over HTML meta");
        auto forwarded = parse(compose("alice@example.test", {"bob@example.test"}, decode_header(header(legacy, "subject")), decode_text(legacy)));
        check(decode_header(header(forwarded, "subject")) == chinese && decode_text(forwarded) == chinese, "forwarded legacy mail UTF8 roundtrip");
        check(legacy.body == gbk && forwarded.body == chinese, "forwarding leaves original byte encoding intact");
        check(parameter("multipart/related; START=\"<root@example.test>\"; boundary=x", "start") == "<root@example.test>", "related start parameter");
        check(parameter("text/plain; name=\"a;\\\"b.txt\"", "NAME") == "a;\"b.txt", "quoted parameter escaping and case");
        auto digest = parse("Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: nested\r\n\r\nforwarded text\r\n--d\r\nContent-Type: text/plain\r\n\r\nexplicit text\r\n--d--\r\n");
        check(digest.parts.size() == 2 && digest.parts[0].content_type == "message/rfc822", "digest defaults to nested message");
        check(digest.parts[0].parts.size() == 1 && header(digest.parts[0].parts[0], "subject") == "nested" && digest.parts[0].parts[0].body == "forwarded text", "digest nested message parsed");
        check(digest.parts[1].content_type == "text/plain" && digest.parts[1].body == "explicit text", "digest explicit type retained");
        rejects([] { parameter("text/plain; charset=utf-8; CHARSET=gbk", "charset"); });
        rejects([] { Part large; large.body.assign(16 * 1024 * 1024 + 1, 'x'); decode_text(large); });
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
