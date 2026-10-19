#include <postplus/verification_code.hpp>
#include <postplus/core.hpp>
#include <chrono>
#include <iostream>
#include <stdexcept>
using namespace postplus;
namespace {
std::string message(std::string_view body, std::string_view subject = "Account notification", std::string_view type = "text/plain; charset=UTF-8") {
    return "From: Security <security@example.com>\r\nSubject: " + std::string(subject) +
        "\r\nMIME-Version: 1.0\r\nContent-Type: " + std::string(type) + "\r\n\r\n" + std::string(body);
}
void expect(std::string_view raw, std::string_view expected, const char* label) {
    const auto result = extract_verification_code(raw);
    if (expected.empty() ? result.has_value() : !result || result->code != expected)
        throw std::runtime_error(std::string(label) + ": " + (result ? result->code : "no code"));
}
void expect_link(std::string_view raw, std::string_view expected, const char* label) {
    const auto result = extract_verification_link(raw);
    if (expected.empty() ? result.has_value() : !result || result->url != expected)
        throw std::runtime_error(std::string(label) + ": " + (result ? result->url : "no link"));
}
}
int main() {
    try {
        expect(message("Your verification code is: 012345. It expires in 10 minutes."), "012345", "preserve leading zeros");
        expect(message("验证码是：987654，请勿向他人透露。"), "987654", "Chinese verification code");
        expect(message("您的动态码为【1234】"), "1234", "Chinese four digit code");
        expect(message("One-time password: 123 456"), "123456", "grouped six digit code");
        expect(message("Your security code is 1234-5678."), "12345678", "grouped eight digit code");
        expect(message("Sign-in code: AB12cD"), "AB12cD", "mixed alphanumeric code");
        expect(message("Your passcode is ０１２３４５"), "012345", "fullwidth code and passcode cue");
        expect(message("Verification-code: 1 2 3 4 5 6"), "123456", "individually spaced digits");
        expect(message("OTP: 123\xc2\xa0" "456"), "123456", "nonbreaking group separator");
        expect(message("验证代码：1\xe2\x80\x8b" "2\xe2\x80\x8b" "3456"), "123456", "zero-width OTP typography");
        expect(message("1 2 3 4 5 6 7 8 9", "Your verification code"), "", "overlong spaced number rejected");
        expect(message("2026", "Your verification code"), "", "unlabelled year not promoted by subject");
        expect(message("OTP: 2026"), "2026", "explicit four digit code preserved");
        expect(message("678901 is your verification code."), "678901", "code before label");
        expect(message("Hello,\n\n004455\n\nExpires in ten minutes.", "Your login code"), "004455", "subject contextual standalone code");
        expect(message("Order number: 123456\nDate: 2026-10-13\nAmount: 1234.56", "Your order"), "", "ordinary numeric identifiers");
        expect(message("Order number: 123456\nDate: 2026-10-13", "Your verification code"), "", "context does not select an arbitrary number");
        expect(message("OTP expires in 1800 seconds. Ticket: 123456"), "", "expiry and ticket are not codes");
        expect(message("Your verification code expires on 2026-10-13."), "", "date after context");
        expect(message("Security code: https://example.com/123456?code=654321"), "", "URL numbers ignored");
        expect(message("Verification code: user123456@example.com"), "", "email identifier ignored");
        expect(message("Your verification code is 1234567890123456"), "", "long account number rejected");
        expect(message("Your verification code is onlyletters"), "", "arbitrary word rejected");
        expect(message("Security code: 123456\nLogin code: 654321"), "", "multiple clear codes ambiguous");
        expect(message("111111\nYour verification code is 222222", "Your login code"), "222222", "clear current label preferred over unrelated standalone number");
        expect(message("Your verification code: 123456\n-----Original Message-----\nVerification code: 654321"), "123456", "ignore original quoted message");
        expect(message("> Verification code: 123456\nPlease review the previous message."), "", "quoted line ignored");
        expect(message("Verification code: 123456", "Fwd: Your verification code"), "", "forwarded subject ignored");
        expect(message("<p>Your verification code is</p><div><b>456789</b></div>", "Verify your email", "text/html; charset=UTF-8"), "456789", "HTML visible code");
        expect(message("<p>Verification code: &#48;&#48;&#49;&#50;&#51;&#52;</p>", "Security", "text/html; charset=UTF-8"), "001234", "HTML numeric entities");
        expect(message("<script>Verification code: 111111</script><style>OTP:222222</style><div style='display: none'>Security code:333333</div><p>Verification code:444444</p>", "Security", "text/html; charset=UTF-8"), "444444", "hidden scripts and styles excluded");
        expect(message("<script>const x = '<span';</script><style>p:before {content: '<span';}</style><title>OTP:999999</title><p>Verification code: 123456</p>", "Security", "text/html"), "123456", "raw script/style/title content cannot hide visible code");
        expect(message("<div title='greater > sign' style='display:none'>OTP:111111</div><p>OTP:222222</p>", "Security", "text/html; charset=UTF-8"), "222222", "quoted angle bracket in attributes");
        expect(message("<div class='gmail_quote'>OTP:111111</div><blockquote>OTP:222222</blockquote><p>Verification code:333333</p>", "Security", "text/html; charset=UTF-8"), "333333", "quoted HTML excluded");
        expect(message("<p><a href='https://example.com/code/111111'>Continue</a></p>", "Verification code", "text/html; charset=UTF-8"), "", "link attributes are not content");
        const auto chinese = "您的验证码是：006789。";
        expect("Subject: =?UTF-8?B?" + base64_encode("邮箱验证") + "?=\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64_encode(chinese), "006789", "real MIME base64 body and encoded header");
        expect("Subject: Security\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nVerification code: =30=30=35=36=37=38\r\n", "005678", "real MIME quoted printable");
        const auto mixed = message("--mix\r\nContent-Type: text/plain\r\n\r\nVerification code: 003456\r\n--mix\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=otp.txt\r\n\r\nVerification code: 777777\r\n--mix\r\nContent-Type: message/rfc822\r\n\r\nSubject: Login code\r\n\r\nVerification code: 888888\r\n--mix--\r\n", "Security", "multipart/mixed; boundary=mix");
        expect(mixed, "003456", "attachments and embedded forwarded messages excluded");
        expect(message("--alt\r\nContent-Type: text/plain\r\n\r\nRead HTML to verify.\r\n--alt\r\nContent-Type: text/html\r\n\r\n<p>Verification code: 345678</p>\r\n--alt--\r\n", "Security", "multipart/alternative; boundary=alt"), "345678", "HTML fallback in alternative MIME");
        expect(message("--alt\r\nContent-Type: text/plain\r\n\r\nVerification code: 123456\r\n--alt\r\nContent-Type: text/html\r\n\r\n<p>Verification code: 654321</p>\r\n--alt--\r\n", "Security", "multipart/alternative; boundary=alt"), "", "conflicting MIME alternatives ambiguous");
        expect(message(std::string(65537, 'x') + "Verification code:123456"), "", "oversized display text bounded");
        const std::string verify = "https://accounts.example.com/verify?token=secret&email=you%40example.com";
        expect_link(message("Please verify your email: " + verify), verify, "plain action link preserves query");
        expect_link(message("Verify your email using the link below:\n\n" + verify), verify, "plain link below action context");
        expect_link(message("验证邮箱：" + verify + "。"), verify, "Chinese punctuation after plain link");
        expect_link(message("<p>Welcome.</p><a href='https://accounts.example.com/verify?token=secret&amp;email=you%40example.com'><b>Verify your email</b></a>", "Welcome", "text/html"), verify, "HTML CTA and encoded URL query");
        expect_link(message("<script>const x = '<span';</script><a href='https://accounts.example.com/verify?token=help&amp;redirect=%2Fdashboard&amp;state=tracking'>Verify your email</a>", "Welcome", "text/html"), "https://accounts.example.com/verify?token=help&redirect=%2Fdashboard&state=tracking", "raw script and opaque query values do not suppress CTA");
        expect_link(message("<a href=https://accounts.example.com/activate?t=123>激活账号</a>", "Welcome", "text/html"), "https://accounts.example.com/activate?t=123", "unquoted href and Chinese CTA");
        expect_link(message("<a href='https://accounts.example.com/opaque?t=one'>Reset your password</a>", "Security", "text/html"), "https://accounts.example.com/opaque?t=one", "explicit CTA permits opaque endpoint");
        expect_link(message("<a href='https://www.facebook.com/confirmemail.php?token=one'>Confirm your email</a>", "Security", "text/html"), "https://www.facebook.com/confirmemail.php?token=one", "social service account verification is supported");
        expect_link(message("<a href='https://www.facebook.com/example'>Follow us</a>", "Verify your email", "text/html"), "", "ordinary social footer lacks verification evidence");
        expect_link(message("<a href='https://accounts.example.com/verify?t=one'>Continue</a>", "Verify your email", "text/html"), "https://accounts.example.com/verify?t=one", "subject and route support generic label");
        expect_link(message("Click here: https://accounts.example.com/verify?t=one", "Verify your email"), "https://accounts.example.com/verify?t=one", "plain link subject context");
        for (const auto url : {"javascript:alert(1)", "data:text/html,bad", "//accounts.example.com/verify", "/verify?token=secret",
                              "https://accounts.example.com@evil.example/verify", "https://accounts.example.com\\@evil.example/verify",
                              "https://accounts.example.com/verify%0d%0aLocation:evil", "https://accounts.example.com:99999/verify",
                              "https://accounts.example.com/unsubscribe?verify=true", "https://tracking.example.com/click?url=https://accounts.example.com/verify",
                              "https://accounts.example.com/privacy"})
            expect_link(message("<a href='" + std::string(url) + "'>Verify your email</a>", "Verify your email", "text/html"), "", "unsafe or unrelated link rejected");
        expect_link(message("<a href='https://accounts.example.com/verify?t=one'>Unsubscribe</a>", "Verify your email", "text/html"), "", "unsubscribe label overrides route");
        expect_link(message("<a href='https://accounts.example.com/verify?a' href='https://evil.example/verify'>Verify your email</a>", "Security", "text/html"), "", "duplicate href rejected");
        expect_link(message("<div hidden><a href='https://accounts.example.com/verify'>Verify your email</a></div><script>https://accounts.example.com/verify</script>", "Verify your email", "text/html"), "", "hidden action links ignored");
        expect_link(message("<div aria-hidden = 'true'><a href='https://accounts.example.com/verify'>Verify your email</a></div>", "Verify your email", "text/html"), "", "spaced aria-hidden attribute ignored");
        expect_link(message("<p>&gt; <a href='https://accounts.example.com/verify'>Verify your email</a></p>", "Verify your email", "text/html"), "", "HTML quoted line action ignored");
        expect_link(message("<blockquote><a href='https://accounts.example.com/verify'>Verify your email</a></blockquote>", "Verify your email", "text/html"), "", "quoted action link ignored");
        expect_link(message("-----Original Message-----\nVerify your email: " + verify), "", "forwarded plain link ignored");
        expect_link(message("<p>-----Original Message-----</p><a href='https://accounts.example.com/verify'>Verify your email</a>", "Security", "text/html"), "", "forwarded HTML link ignored");
        expect_link(message("Verify your email: " + verify, "Fwd: Verify your email"), "", "forwarded link subject ignored");
        expect_link(message("<a href='https://accounts.example.com/verify?a'>Verify your email</a><a href='https://accounts.example.com/verify?b'>Verify your email</a>", "Security", "text/html"), "", "competing action links ambiguous");
        expect_link(message("<a href='https://accounts.example.com/verify?a'>Verify your email</a><a href='https://accounts.example.com/verify?a'>Verify your email</a>", "Security", "text/html"), "https://accounts.example.com/verify?a", "duplicate same action deduplicated");
        expect_link(message("https://accounts.example.com/support", "Your verification code"), "", "code subject cannot promote arbitrary URL");
        std::string deeply_nested = "<a href='https://accounts.example.com/verify'></a>";
        for (int depth = 0; depth < 65; ++depth) deeply_nested += "<span>";
        expect_link(message(deeply_nested, "Verify your email", "text/html"), "", "HTML depth budget discards previously collected links");
        expect_link(message("--mix\r\nContent-Type: text/plain\r\n\r\nWelcome.\r\n--mix\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename=verify.html\r\n\r\n<a href='https://accounts.example.com/verify'>Verify your email</a>\r\n--mix--\r\n", "Verify your email", "multipart/mixed; boundary=mix"), "", "attached action link ignored");
        expect_link("Subject: Verify your email\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64_encode("Verify your email: " + verify), verify, "MIME encoded action link");
        const auto start = std::chrono::steady_clock::now();
        std::string hostile;
        for (int i = 0; i < 5000; ++i) hostile += "OTP:123456 ";
        expect(message(hostile), "", "repeated context complexity bound");
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(2)) throw std::runtime_error("bounded extraction too slow");
        std::cout << "Verification code tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
