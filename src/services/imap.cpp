#include "postplus/core.hpp"
#include "postplus/mime.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <locale>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>

using namespace postplus;
namespace {
struct Bad : std::runtime_error { using std::runtime_error::runtime_error; };
std::string upper(std::string value) { for (char& c : value) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c))); return value; }
std::uint64_t integer(std::string_view text, bool zero = false) {
    std::uint64_t n = 0;
    auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), n);
    if (text.empty() || ec != std::errc{} || end != text.data() + text.size() || (!zero && !n)) throw Bad("Invalid number");
    return n;
}
std::string quote(std::string_view value) {
    std::string out = "\"";
    for (char c : value) {
        if (c == '\r' || c == '\n' || c == '\0') throw Bad("Invalid string byte");
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out + '"';
}
std::string read_command(Connection& c) {
    auto command = c.line(8192);
    for (unsigned literals = 0; !command.empty() && command.back() == '}'; ++literals) {
        auto start = command.rfind('{');
        if (start == std::string::npos || literals == 8) throw Bad("Invalid literal framing");
        auto size = integer(std::string_view(command).substr(start + 1, command.size() - start - 2), true);
        if (size > 16384 || command.size() + size > 65536) throw Bad("Literal too large");
        c.write("+ Ready for literal data\r\n");
        auto literal = c.read(static_cast<std::size_t>(size));
        command.resize(start); command += quote(literal); command += c.line(8192);
        if (command.size() > 65536) throw Bad("Command too large");
    }
    return command;
}
std::vector<std::string> tokenize(std::string_view line) {
    std::vector<std::string> result;
    for (std::size_t i = 0; i < line.size();) {
        if (line[i] == ' ' || line[i] == '\t') { ++i; continue; }
        if (result.size() >= 256) throw Bad("Too many arguments");
        if (line[i] == '(' || line[i] == ')') { result.emplace_back(1, line[i++]); continue; }
        if (line[i] == '"') {
            ++i; std::string value; bool closed = false;
            while (i < line.size()) {
                char ch = line[i++];
                if (ch == '"') { closed = true; break; }
                if (ch == '\\') { if (i == line.size()) throw Bad("Invalid quoted string"); ch = line[i++]; }
                if (static_cast<unsigned char>(ch) < 32 || ch == 127) throw Bad("Invalid string byte");
                value += ch;
            }
            if (!closed || (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != ')')) throw Bad("Invalid quoted string");
            result.push_back(std::move(value)); continue;
        }
        auto start = i; unsigned brackets = 0;
        while (i < line.size()) {
            auto ch = line[i];
            if (!brackets && (ch == ' ' || ch == '\t' || ch == '(' || ch == ')')) break;
            if (static_cast<unsigned char>(ch) < 32 || ch == 127 || ch == '"' || ch == '{' || ch == '}') throw Bad("Invalid atom");
            if (ch == '[') ++brackets;
            if (ch == ']') { if (!brackets) throw Bad("Invalid section"); --brackets; }
            ++i;
        }
        if (brackets || start == i) throw Bad("Unclosed section");
        result.emplace_back(line.substr(start, i - start));
    }
    return result;
}
struct Sequence {
    struct Range { std::uint64_t a, b; bool astar, bstar; };
    std::vector<Range> ranges;
    explicit Sequence(std::string_view value) {
        std::size_t offset = 0;
        while (offset < value.size()) {
            auto end = value.find(',', offset); if (end == std::string_view::npos) end = value.size();
            auto item = value.substr(offset, end - offset); auto colon = item.find(':');
            auto a = item.substr(0, colon), b = colon == std::string_view::npos ? a : item.substr(colon + 1);
            bool astar = a == "*", bstar = b == "*";
            auto av = astar ? 0 : integer(a), bv = bstar ? 0 : integer(b);
            if (av > 4294967295ULL || bv > 4294967295ULL) throw Bad("Sequence number exceeds uint32");
            ranges.push_back({av, bv, astar, bstar});
            if (end == value.size()) break;
            offset = end + 1; if (offset == value.size()) throw Bad("Invalid sequence set");
        }
        if (ranges.empty()) throw Bad("Empty sequence set");
    }
    bool includes(std::uint64_t value, std::uint64_t maximum) const {
        for (auto r : ranges) { auto a = r.astar ? maximum : r.a, b = r.bstar ? maximum : r.b; if (value >= std::min(a, b) && value <= std::max(a, b)) return true; }
        return false;
    }
};
std::string key(const Json& message) { return message.at("id").dump() + ":" + message.at("uid").dump(); }
constexpr std::array<const char*, 6> mailboxes{"INBOX", "Sent", "Trash", "Drafts", "Junk", "Archive"};
std::string mailbox_name(const std::string& value) {
    for (const auto* name : mailboxes) if (upper(value) == upper(name)) return name;
    return {};
}
std::pair<std::string, std::string> split_body(const std::string& raw) {
    auto end = raw.find("\r\n\r\n"); std::size_t count = 4;
    if (end == std::string::npos) { end = raw.find("\n\n"); count = 2; }
    if (end == std::string::npos) return {raw + "\r\n\r\n", ""};
    return {raw.substr(0, end + count), raw.substr(end + count)};
}
std::string select_headers(const std::string& raw, const std::set<std::string>& fields, bool invert) {
    auto headers = split_body(raw).first;
    std::string selected; std::size_t at = 0; bool keep = false;
    while (at < headers.size()) {
        auto end = headers.find('\n', at); if (end == std::string::npos) end = headers.size();
        auto line = headers.substr(at, end - at); if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        if (line.front() != ' ' && line.front() != '\t') {
            auto colon = line.find(':'); keep = colon != std::string::npos && (fields.contains(upper(line.substr(0, colon))) != invert);
        }
        if (keep) selected += line + "\r\n";
        at = end == headers.size() ? end : end + 1;
    }
    return selected + "\r\n";
}
struct FetchItem {
    std::string name, section;
    bool literal = false, mark_seen = false, partial = false, exclude_fields = false;
    std::uint64_t offset = 0, count = 0;
    std::set<std::string> fields;
};
FetchItem fetch_item(std::string token) {
    token = upper(token); FetchItem item; item.name = token;
    if (token == "FLAGS" || token == "UID" || token == "RFC822.SIZE" || token == "INTERNALDATE") return item;
    item.literal = true;
    if (token == "RFC822" || token == "RFC822.HEADER" || token == "RFC822.TEXT") {
        item.section = token == "RFC822.HEADER" ? "HEADER" : token == "RFC822.TEXT" ? "TEXT" : "";
        item.mark_seen = token != "RFC822.HEADER"; return item;
    }
    bool peek = token.rfind("BODY.PEEK[", 0) == 0;
    if (!peek && token.rfind("BODY[", 0) != 0) throw Bad("Unsupported FETCH attribute");
    auto start = token.find('['), end = token.find(']', start);
    if (end == std::string::npos) throw Bad("Invalid BODY section");
    item.section = token.substr(start + 1, end - start - 1); item.name = "BODY[" + item.section + "]"; item.mark_seen = !peek;
    if (!item.section.empty() && item.section != "HEADER" && item.section != "TEXT") {
        auto opening = item.section.find('('), closing = item.section.find(')');
        auto prefix = opening == std::string::npos ? item.section : trim(item.section.substr(0, opening));
        if ((prefix != "HEADER.FIELDS" && prefix != "HEADER.FIELDS.NOT") || opening == std::string::npos || closing != item.section.size() - 1) throw Bad("Unsupported BODY section");
        item.exclude_fields = prefix == "HEADER.FIELDS.NOT";
        std::istringstream names(item.section.substr(opening + 1, closing - opening - 1)); std::string name;
        while (names >> name) {
            if (name.empty() || name.find_first_of("()[]:\\") != std::string::npos) throw Bad("Invalid header field name");
            item.fields.insert(name);
        }
        if (item.fields.empty()) throw Bad("Empty header fields");
    }
    if (end + 1 < token.size()) {
        auto tail = token.substr(end + 1); auto dot = tail.find('.');
        if (tail.front() != '<' || tail.back() != '>' || dot == std::string::npos) throw Bad("Invalid partial FETCH");
        item.offset = integer(std::string_view(tail).substr(1, dot - 1), true);
        item.count = integer(std::string_view(tail).substr(dot + 1, tail.size() - dot - 2)); item.partial = true;
        item.name += "<" + std::to_string(item.offset) + ">";
    }
    return item;
}
struct Search {
    std::string operation, a, b;
    std::vector<Search> children;
};
Search search_key(const std::vector<std::string>& args, std::size_t& pos, unsigned depth = 0) {
    if (pos == args.size() || depth > 16) throw Bad("Invalid SEARCH expression");
    Search result; result.operation = upper(args[pos++]);
    auto take = [&] { if (pos == args.size()) throw Bad("Missing SEARCH argument"); return args[pos++]; };
    auto op = result.operation;
    if (op == "(") {
        result.operation = "AND";
        while (pos < args.size() && args[pos] != ")") result.children.push_back(search_key(args, pos, depth + 1));
        if (pos == args.size() || result.children.empty()) throw Bad("Unclosed SEARCH group");
        ++pos;
    } else if (op == "NOT" || op == "OR") {
        result.children.push_back(search_key(args, pos, depth + 1));
        if (op == "OR") result.children.push_back(search_key(args, pos, depth + 1));
    } else if (op == "UID") { result.a = take(); Sequence validate(result.a); }
    else if (op == "HEADER") { result.a = take(); result.b = lower(take()); }
    else if (op == "FROM" || op == "TO" || op == "CC" || op == "BCC" || op == "SUBJECT" || op == "BODY" || op == "TEXT") result.a = lower(take());
    else if (op == "LARGER" || op == "SMALLER") { result.a = take(); integer(result.a, true); }
    else if (op == "ALL" || op == "SEEN" || op == "UNSEEN" || op == "DELETED" || op == "UNDELETED" || op == "RECENT" || op == "OLD" || op == "NEW") {}
    else { Sequence validate(op); result.operation = "SEQUENCE"; result.a = op; }
    return result;
}
bool wildcard(std::string pattern, const std::string& value) {
    pattern = upper(pattern); std::vector<bool> before(value.size() + 1), after(value.size() + 1); before[0] = true;
    for (char ch : pattern) {
        std::fill(after.begin(), after.end(), false);
        if (ch == '*' || ch == '%') { after[0] = before[0]; for (std::size_t j = 1; j <= value.size(); ++j) after[j] = before[j] || after[j - 1]; }
        else for (std::size_t j = 1; j <= value.size(); ++j) after[j] = before[j - 1] && ch == value[j - 1];
        before.swap(after);
    }
    return before.back();
}
void imap(Connection& c, const Config& cfg) {
    std::string user, selected_folder = "INBOX"; bool selected = false, readonly = false;
    unsigned auth_failures = 0;
    const auto auth_limit = static_cast<unsigned>(std::clamp(cfg.number("max_auth_attempts", 5), 1, 20));
    std::vector<Json> messages; std::set<std::string> deleted;
    auto allowed = [&] { return c.encrypted() || (cfg.flag("allow_insecure_auth") && c.socket().remote_endpoint().address().is_loopback()); };
    auto tls = [&] { return !cfg.text("tls_certificate").empty() && !cfg.text("tls_private_key").empty(); };
    auto capability = [&] {
        std::string value = "IMAP4rev1";
        if (user.empty()) { if (allowed()) value += " AUTH=PLAIN"; else value += " LOGINDISABLED"; if (!c.encrypted() && tls()) value += " STARTTLS"; }
        return value;
    };
    auto list = [&](const std::string& target) {
        auto result = rpc(cfg, "storage", {{"op", "list"}, {"username", user}, {"folder", target}});
        if (!result.value("ok", false)) throw std::runtime_error("Mailbox unavailable");
        return result;
    };
    auto flags = [&](const Json& message) {
        std::string out = "("; if (message.value("seen", false)) out += "\\Seen";
        if (deleted.contains(key(message))) { if (out.size() > 1) out += ' '; out += "\\Deleted"; }
        return out + ')';
    };
    auto refresh = [&] {
        auto current = list(selected_folder).at("messages").get<std::vector<Json>>();
        auto previous_count = messages.size();
        for (std::size_t i = 0; i < messages.size();) {
            auto id = key(messages[i]);
            if (std::none_of(current.begin(), current.end(), [&](const Json& m) { return key(m) == id; })) {
                c.write("* " + std::to_string(i + 1) + " EXPUNGE\r\n"); deleted.erase(id); messages.erase(messages.begin() + static_cast<std::ptrdiff_t>(i));
            } else ++i;
        }
        bool changed = previous_count != current.size() || messages.size() != current.size();
        messages = std::move(current);
        if (changed) c.write("* " + std::to_string(messages.size()) + " EXISTS\r\n");
    };
    auto raw_message = [&](const Json& message) {
        auto result = rpc(cfg, "storage", {{"op", "get"}, {"username", user}, {"id", message.at("id")},
            {"folder", selected_folder}, {"uid", message.at("uid")}});
        if (!result.value("ok", false)) throw std::runtime_error("Message unavailable");
        return result.at("raw").get<std::string>();
    };
    auto expunge = [&](bool announce) {
        if (readonly || deleted.empty()) return;
        Json ids = Json::array(), expected_uids = Json::object();
        for (const auto& message : messages) if (deleted.contains(key(message))) {
            ids.push_back(message.at("id")); expected_uids[message.at("id").get<std::string>()] = message.at("uid");
        }
        auto result = rpc(cfg, "storage", {{"op", "delete"}, {"username", user}, {"ids", ids},
            {"permanent", true}, {"folder", selected_folder}, {"expected_uids", expected_uids}});
        if (!result.value("ok", false)) throw std::runtime_error("Deletion failed");
        for (std::size_t i = 0; i < messages.size();) {
            if (deleted.contains(key(messages[i]))) { if (announce) c.write("* " + std::to_string(i + 1) + " EXPUNGE\r\n"); messages.erase(messages.begin() + static_cast<std::ptrdiff_t>(i)); }
            else ++i;
        }
        deleted.clear();
    };
    c.write("* OK [CAPABILITY " + capability() + "] PostPlus IMAP ready\r\n");
    for (;;) {
        std::string line;
        try { line = read_command(c); }
        catch (...) { c.write("* BYE Invalid or oversized command framing\r\n"); return; }
        std::string tag = "*", cmd;
        try {
            auto args = tokenize(line);
            if (args.size() < 2) throw Bad("Missing tag or command");
            tag = args[0];
            if (tag.empty() || tag == "*" || tag.find_first_of(" (){%*\"\\]+\r\n\t") != std::string::npos) { tag = "*"; throw Bad("Invalid tag"); }
            cmd = upper(args[1]); args.erase(args.begin(), args.begin() + 2);
            auto done = [&](const std::string& text = "completed") { c.write(tag + " OK " + cmd + " " + text + "\r\n"); };
            auto require_count = [&](std::size_t count) { if (args.size() != count) throw Bad("Wrong number of arguments"); };
            if (cmd == "LOGOUT") { require_count(0); c.write("* BYE Goodbye\r\n"); done(); return; }
            if (cmd == "CAPABILITY") { require_count(0); c.write("* CAPABILITY " + capability() + "\r\n"); done(); continue; }
            if (cmd == "NOOP") { require_count(0); if (selected) refresh(); done(); continue; }
            if (cmd == "STARTTLS") {
                require_count(0);
                if (!user.empty() || c.encrypted() || !tls()) { c.write(tag + " NO STARTTLS unavailable\r\n"); continue; }
                c.write(tag + " OK Begin TLS negotiation\r\n");
                try { c.start_tls_server(cfg); } catch (...) { return; }
                continue;
            }
            if (cmd == "LOGIN" || cmd == "AUTHENTICATE") {
                if (!user.empty()) { c.write(tag + " BAD Already authenticated\r\n"); continue; }
                if (!allowed()) { c.write(tag + " NO [PRIVACYREQUIRED] TLS required\r\n"); continue; }
                std::string candidate, password;
                if (cmd == "LOGIN") { require_count(2); candidate = lower(args[0]); password = args[1]; }
                else {
                    require_count(1); if (upper(args[0]) != "PLAIN") throw Bad("Unsupported authentication mechanism");
                    c.write("+ \r\n"); auto encoded = c.line(8192);
                    if (encoded == "*") { c.write(tag + " BAD Authentication canceled\r\n"); continue; }
                    std::string decoded; try { decoded = base64_decode(encoded); } catch (...) { throw Bad("Invalid authentication encoding"); }
                    auto a = decoded.find('\0'), b = a == std::string::npos ? a : decoded.find('\0', a + 1);
                    if (a == std::string::npos || b == std::string::npos || decoded.find('\0', b + 1) != std::string::npos) throw Bad("Invalid PLAIN authentication");
                    candidate = lower(decoded.substr(a + 1, b - a - 1)); password = decoded.substr(b + 1);
                    if (a && lower(decoded.substr(0, a)) != candidate) throw Bad("Authorization identity mismatch");
                }
                auto result = rpc(cfg, "auth", {{"op", "verify"}, {"username", candidate}, {"password", password}});
                if (!result.value("ok", false)) {
                    c.write(tag + " NO [AUTHENTICATIONFAILED] Invalid credentials\r\n");
                    if (++auth_failures >= auth_limit) { c.write("* BYE Too many failed authentication attempts\r\n"); return; }
                    continue;
                }
                user = result.value("username", candidate); done(); continue;
            }
            if (user.empty()) { c.write(tag + " NO Authenticate first\r\n"); continue; }
            if (cmd == "LIST" || cmd == "LSUB") {
                require_count(2);
                if (args[1].empty()) c.write("* " + cmd + " (\\Noselect) \"/\" \"\"\r\n");
                else for (const auto* name : mailboxes)
                    if (wildcard(args[0] + args[1], upper(name))) c.write("* " + cmd + " () \"/\" " + quote(name) + "\r\n");
                done(); continue;
            }
            if (cmd == "SELECT" || cmd == "EXAMINE") {
                require_count(1); selected = false; messages.clear(); deleted.clear();
                selected_folder = mailbox_name(args[0]);
                if (selected_folder.empty()) { c.write(tag + " NO No such mailbox\r\n"); continue; }
                auto mailbox = list(selected_folder); messages = mailbox.at("messages").get<std::vector<Json>>(); selected = true; readonly = cmd == "EXAMINE";
                c.write("* FLAGS (\\Seen \\Deleted)\r\n* " + std::to_string(messages.size()) + " EXISTS\r\n* 0 RECENT\r\n");
                c.write("* OK [UIDVALIDITY " + std::to_string(mailbox.at("uidvalidity").get<std::uint64_t>()) + "] Stable mailbox identifier\r\n");
                c.write("* OK [UIDNEXT " + std::to_string(mailbox.at("uidnext").get<std::uint64_t>()) + "] Next UID\r\n");
                c.write(std::string("* OK [PERMANENTFLAGS ") + (readonly ? "()" : "(\\Seen)") + "] Supported persistent flags\r\n");
                for (std::size_t i = 0; i < messages.size(); ++i) if (!messages[i].value("seen", false)) { c.write("* OK [UNSEEN " + std::to_string(i + 1) + "] First unseen\r\n"); break; }
                c.write(tag + " OK [" + (readonly ? "READ-ONLY" : "READ-WRITE") + "] " + cmd + " completed\r\n"); continue;
            }
            if (cmd == "STATUS") {
                if (args.size() < 4 || args[1] != "(" || args.back() != ")") throw Bad("Invalid STATUS arguments");
                const auto target = mailbox_name(args[0]);
                if (target.empty()) { c.write(tag + " NO No such mailbox\r\n"); continue; }
                auto mailbox = list(target); auto records = mailbox.at("messages"); std::string response = "* STATUS " + quote(target) + " (";
                for (std::size_t i = 2; i + 1 < args.size(); ++i) {
                    auto item = upper(args[i]); std::uint64_t value = 0;
                    if (item == "MESSAGES") value = records.size();
                    else if (item == "RECENT") value = 0;
                    else if (item == "UIDNEXT") value = mailbox.at("uidnext").get<std::uint64_t>();
                    else if (item == "UIDVALIDITY") value = mailbox.at("uidvalidity").get<std::uint64_t>();
                    else if (item == "UNSEEN") { for (const auto& message : records) if (!message.value("seen", false)) ++value; }
                    else throw Bad("Unsupported STATUS item");
                    if (i > 2) response += ' '; response += item + " " + std::to_string(value);
                }
                c.write(response + ")\r\n"); done(); continue;
            }
            if (!selected) { c.write(tag + " NO Select a mailbox first\r\n"); continue; }
            if (cmd == "CHECK") { require_count(0); done(); continue; }
            if (cmd == "CLOSE") { require_count(0); expunge(false); selected = false; messages.clear(); deleted.clear(); done(); continue; }
            if (cmd == "EXPUNGE") { require_count(0); if (readonly) { c.write(tag + " NO Mailbox is read-only\r\n"); continue; } expunge(true); done(); continue; }
            bool uid_mode = cmd == "UID";
            if (uid_mode) { if (args.empty()) throw Bad("Missing UID command"); cmd = upper(args.front()); args.erase(args.begin()); }
            // Sequence numbers remain fixed during FETCH/STORE/SEARCH as required by IMAP.
            auto max_uid = messages.empty() ? 0 : messages.back().at("uid").get<std::uint64_t>();
            if (cmd == "FETCH") {
                if (args.size() < 2) throw Bad("Missing FETCH arguments");
                Sequence sequence(args[0]); std::vector<std::string> attribute_names(args.begin() + 1, args.end());
                if (attribute_names.front() == "(") { if (attribute_names.back() != ")") throw Bad("Unclosed FETCH attributes"); attribute_names.erase(attribute_names.begin()); attribute_names.pop_back(); }
                else if (attribute_names.size() != 1) throw Bad("FETCH attributes require parentheses");
                if (attribute_names.size() == 1 && upper(attribute_names[0]) == "FAST") attribute_names = {"FLAGS", "INTERNALDATE", "RFC822.SIZE"};
                if (attribute_names.empty() || attribute_names.size() > 64) throw Bad("Invalid FETCH attributes");
                std::vector<FetchItem> items; bool has_uid = false;
                for (const auto& name : attribute_names) { auto item = fetch_item(name); has_uid = has_uid || item.name == "UID"; items.push_back(std::move(item)); }
                if (uid_mode && !has_uid) items.insert(items.begin(), fetch_item("UID"));
                for (std::size_t i = 0; i < messages.size(); ++i) {
                    auto& message = messages[i]; auto uid = message.at("uid").get<std::uint64_t>();
                    if (!sequence.includes(uid_mode ? uid : i + 1, uid_mode ? max_uid : messages.size())) continue;
                    bool need_raw = std::any_of(items.begin(), items.end(), [](const FetchItem& item) { return item.literal; });
                    auto raw = need_raw ? raw_message(message) : "";
                    bool seen_changed = false;
                    if (!readonly && !message.value("seen", false) && std::any_of(items.begin(), items.end(), [](const FetchItem& item) { return item.mark_seen; })) {
                        auto result = rpc(cfg, "storage", {{"op", "flags"}, {"username", user}, {"id", message.at("id")}, {"uid", message.at("uid")}, {"seen", true}});
                        if (!result.value("ok", false)) throw std::runtime_error("Flag update failed");
                        message["seen"] = true; seen_changed = true;
                    }
                    std::string response = "* " + std::to_string(i + 1) + " FETCH ("; bool first = true;
                    for (const auto& item : items) {
                        if (!first) response += ' '; first = false;
                        response += item.name + " ";
                        if (item.name == "FLAGS") response += flags(message);
                        else if (item.name == "UID") response += std::to_string(uid);
                        else if (item.name == "RFC822.SIZE") response += std::to_string(message.at("size").get<std::uint64_t>());
                        else if (item.name == "INTERNALDATE") {
                            if (!message.contains("internal_date")) throw Bad("INTERNALDATE unavailable for this message");
                            auto epoch = static_cast<std::time_t>(message.at("internal_date").get<std::int64_t>()); std::tm utc{};
#ifdef _WIN32
                            gmtime_s(&utc, &epoch);
#else
                            gmtime_r(&epoch, &utc);
#endif
                            std::ostringstream date; date.imbue(std::locale::classic()); date << std::put_time(&utc, "%d-%b-%Y %H:%M:%S +0000"); response += quote(date.str());
                        } else {
                            std::string body;
                            if (!item.fields.empty()) body = select_headers(raw, item.fields, item.exclude_fields);
                            else if (item.section == "HEADER") body = split_body(raw).first;
                            else if (item.section == "TEXT") body = split_body(raw).second;
                            else body = raw;
                            if (item.partial) body = item.offset >= body.size() ? "" : body.substr(static_cast<std::size_t>(item.offset), static_cast<std::size_t>(std::min<std::uint64_t>(item.count, body.size() - item.offset)));
                            const auto response_limit = static_cast<std::size_t>(cfg.number("max_message_bytes", 10485760)) + 65536;
                            if (body.size() > response_limit - std::min(response_limit, response.size())) throw Bad("FETCH response exceeds size limit");
                            response += "{" + std::to_string(body.size()) + "}\r\n" + body;
                        }
                    }
                    if (seen_changed && std::none_of(items.begin(), items.end(), [](const FetchItem& item) { return item.name == "FLAGS"; })) response += " FLAGS " + flags(message);
                    c.write(response + ")\r\n");
                }
                done(); continue;
            }
            if (cmd == "STORE") {
                if (args.size() < 3) throw Bad("Missing STORE arguments");
                if (readonly) { c.write(tag + " NO Mailbox is read-only\r\n"); continue; }
                Sequence sequence(args[0]); auto operation = upper(args[1]); bool silent = operation.ends_with(".SILENT");
                if (silent) operation.resize(operation.size() - 7);
                if (operation != "FLAGS" && operation != "+FLAGS" && operation != "-FLAGS") throw Bad("Unsupported STORE operation");
                std::vector<std::string> flag_names(args.begin() + 2, args.end());
                if (flag_names.front() == "(") { if (flag_names.back() != ")") throw Bad("Unclosed STORE flags"); flag_names.erase(flag_names.begin()); flag_names.pop_back(); }
                else if (flag_names.size() != 1) throw Bad("Invalid STORE flags");
                bool seen = false, erased = false;
                for (auto flag : flag_names) { flag = upper(flag); if (flag == "\\SEEN") seen = true; else if (flag == "\\DELETED") erased = true; else throw Bad("Only Seen and Deleted flags are supported"); }
                for (std::size_t i = 0; i < messages.size(); ++i) {
                    auto& message = messages[i]; auto uid = message.at("uid").get<std::uint64_t>();
                    if (!sequence.includes(uid_mode ? uid : i + 1, uid_mode ? max_uid : messages.size())) continue;
                    auto id = key(message); bool old_seen = message.value("seen", false), old_deleted = deleted.contains(id);
                    bool new_seen = operation == "FLAGS" ? seen : operation == "+FLAGS" ? old_seen || seen : old_seen && !seen;
                    bool new_deleted = operation == "FLAGS" ? erased : operation == "+FLAGS" ? old_deleted || erased : old_deleted && !erased;
                    if (old_seen != new_seen) {
                        auto result = rpc(cfg, "storage", {{"op", "flags"}, {"username", user}, {"id", message.at("id")}, {"uid", message.at("uid")}, {"seen", new_seen}});
                        if (!result.value("ok", false)) throw std::runtime_error("Flag update failed"); message["seen"] = new_seen;
                    }
                    if (new_deleted) deleted.insert(id); else deleted.erase(id);
                    if (!silent) c.write("* " + std::to_string(i + 1) + " FETCH (" + (uid_mode ? "UID " + std::to_string(uid) + " " : "") + "FLAGS " + flags(message) + ")\r\n");
                }
                done(); continue;
            }
            if (cmd == "SEARCH") {
                if (args.empty()) throw Bad("Missing SEARCH criteria");
                std::size_t position = 0;
                if (upper(args[0]) == "CHARSET") {
                    if (args.size() < 3) throw Bad("Missing SEARCH charset or criteria");
                    if (upper(args[1]) != "UTF-8" && upper(args[1]) != "US-ASCII") { c.write(tag + " NO [BADCHARSET (US-ASCII UTF-8)] Unsupported charset\r\n"); continue; }
                    position = 2;
                }
                Search expression; expression.operation = "AND";
                while (position < args.size()) expression.children.push_back(search_key(args, position));
                std::string response = "* SEARCH";
                for (std::size_t i = 0; i < messages.size(); ++i) {
                    const auto& message = messages[i]; auto uid = message.at("uid").get<std::uint64_t>(); std::string raw; bool loaded = false;
                    std::optional<mime::Part> parsed;
                    auto get_raw = [&]() -> const std::string& { if (!loaded) { raw = raw_message(message); loaded = true; } return raw; };
                    auto get_mime = [&]() -> const mime::Part& {
                        if (!parsed) parsed = mime::parse(get_raw(), mime::Limits{static_cast<std::size_t>(cfg.number("max_message_bytes", 10485760))});
                        return *parsed;
                    };
                    std::function<bool(const mime::Part&, const std::string&)> body_contains = [&](const mime::Part& part, const std::string& needle) {
                        if (lower(part.body).find(needle) != std::string::npos) return true;
                        return std::any_of(part.parts.begin(), part.parts.end(), [&](const mime::Part& child) { return body_contains(child, needle); });
                    };
                    std::function<bool(const Search&)> match = [&](const Search& query) {
                        auto op = query.operation;
                        if (op == "AND") return std::all_of(query.children.begin(), query.children.end(), match);
                        if (op == "OR") return match(query.children[0]) || match(query.children[1]);
                        if (op == "NOT") return !match(query.children[0]);
                        if (op == "ALL" || op == "OLD") return true;
                        if (op == "RECENT" || op == "NEW") return false;
                        if (op == "SEEN" || op == "UNSEEN") return message.value("seen", false) == (op == "SEEN");
                        if (op == "DELETED" || op == "UNDELETED") return deleted.contains(key(message)) == (op == "DELETED");
                        if (op == "UID") return Sequence(query.a).includes(uid, max_uid);
                        if (op == "SEQUENCE") return Sequence(query.a).includes(i + 1, messages.size());
                        if (op == "LARGER") return message.at("size").get<std::uint64_t>() > integer(query.a, true);
                        if (op == "SMALLER") return message.at("size").get<std::uint64_t>() < integer(query.a, true);
                        if (op == "BODY") return body_contains(get_mime(), query.a);
                        if (op == "TEXT") {
                            if (body_contains(get_mime(), query.a)) return true;
                            for (const auto& [name, value] : get_mime().headers) if (lower(name + ": " + mime::decode_header(value)).find(query.a) != std::string::npos) return true;
                            return false;
                        }
                        auto name = op == "HEADER" ? query.a : lower(op); auto needle = op == "HEADER" ? query.b : query.a;
                        for (const auto& [header_name, value] : get_mime().headers) if (header_name == lower(name) && lower(mime::decode_header(value)).find(needle) != std::string::npos) return true;
                        return false;
                    };
                    if (match(expression)) response += " " + std::to_string(uid_mode ? uid : i + 1);
                }
                c.write(response + "\r\n"); done(); continue;
            }
            throw Bad("Command not implemented");
        } catch (const Bad& error) { c.write(tag + " BAD " + error.what() + "\r\n"); }
        catch (const std::exception&) { c.write(tag + " NO Temporary service failure\r\n"); }
    }
}
}
int main(int argc, char** argv) {
    return service_main("imap", argc, argv, [](const Config& cfg) { serve_tcp(cfg, "imap", [&](Connection& c) { imap(c, cfg); }); });
}
