#include <postplus/core.hpp>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

using namespace postplus;
namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F operation) {
    bool rejected = false;
    try { operation(); } catch (const std::invalid_argument&) { rejected = true; }
    check(rejected,"unsafe log query accepted");
}
}
int main() {
    const auto directory = std::filesystem::temp_directory_path() / ("postplus-logs-" + random_hex());
    try {
        std::filesystem::create_directory(directory);
        const auto secret = random_hex(32);
        const auto token_file = directory / "service-token";
        { std::ofstream file(token_file); file << secret; }
        const auto relay_secret = " relay-" + random_hex(12) + " ";
        const auto relay_file = directory / "relay-password";
        { std::ofstream file(relay_file, std::ios::binary); file << relay_secret << "\r\n"; }
        Config config;
        config.source = directory / "config.json";
        config.values = {{"data_dir",directory.string()},{"log_dir",(directory / "logs").string()},
                         {"service_token_file",token_file.string()},{"service_token_env","POSTPLUS_UNUSED_LOG_TEST_TOKEN"},
                         {"smarthost_password_file",relay_file.string()},
                         {"smarthost_password_env","POSTPLUS_UNUSED_LOG_TEST_RELAY"},
                         {"log_max_bytes",1024},{"log_backups",2},{"log_level","info"}};
        check(config.token() == secret,"secret-file authentication failed");
        check(config.relay_password() == relay_secret,"relay password file did not preserve spaces");
        configure_logging(config,"auth");
        log("auth","must not be recorded","debug");
        check(read_logs(config).at("entries").empty(),"minimum severity ignored");
        log("auth","credential " + secret + " relay " + relay_secret + "\r\nsecond line","warn");
        auto entries = read_logs(config,"auth","warn").at("entries");
        check(entries.size() == 1,"structured warning missing");
        const auto message = entries[0].at("message").get<std::string>();
        check(message.find(secret) == std::string::npos && message.find("[REDACTED]") != std::string::npos,"service token leaked");
        check(message.find(relay_secret) == std::string::npos,"relay password leaked");
        check(message.find_first_of("\r\n") == std::string::npos,"control character escaped console line");
        std::ostringstream console;
        auto* previous = std::cerr.rdbuf(console.rdbuf());
        log("auth",std::string(8180,'x') + secret,"warn");
        std::cerr.rdbuf(previous);
        check(console.str().find(secret.substr(0,12)) == std::string::npos,"partial secret leaked through truncation");
        std::vector<std::thread> writers;
        for (int thread = 0; thread < 3; ++thread) writers.emplace_back([thread] {
            for (int line = 0; line < 12; ++line)
                log("auth","concurrent " + std::to_string(thread) + "/" + std::to_string(line),"info");
        });
        for (auto& writer : writers) writer.join();
        check(std::filesystem::exists(directory / "logs/auth.jsonl.2"),"rotation did not retain backups");
        check(!std::filesystem::exists(directory / "logs/auth.jsonl.3"),"rotation exceeded backup count");
        for (const auto& file : std::filesystem::directory_iterator(directory / "logs")) {
            if (file.path().extension() == ".lock") continue;
            check(file.file_size() <= 1024,"log file exceeded configured bound");
            std::ifstream input(file.path());
            for (std::string line; std::getline(input,line);) check(Json::parse(line).is_object(),"concurrent writes corrupted JSONL");
        }
        check(read_logs(config,"smtp").at("entries").empty(),"service filter ignored");
        auto limited = read_logs(config,"auth","info",2);
        check(limited.at("entries").size() == 2 && limited.at("truncated") == true,"log query bound ignored");
        rejects([&] { read_logs(config,"../config"); });
        rejects([&] { read_logs(config,"auth","fatal"); });
        rejects([&] { read_logs(config,"auth","",0); });
        rejects([&] { read_logs(config,"auth","",501); });
        rejects([&] { read_logs(config,"auth","",100,std::string(257,'x')); });
        rejects([&] { read_logs(config,"auth","",100,"","invalid"); });
        // Pages reach beyond the old 64 KiB tail, tolerate append and rotation,
        // and retain distinct events even when timestamps are identical.
        const auto logs=directory/"logs";
        for (const auto& item:std::filesystem::directory_iterator(logs))
            if (item.path().filename().string().starts_with("auth.jsonl")) std::filesystem::remove(item.path());
        {
            std::ofstream file(logs/"auth.jsonl");
            for (int i=0;i<1800;++i) file << Json{{"timestamp","2026-10-14T12:00:00.000Z"},{"service","auth"},{"level",i%2?"info":"warn"},
                {"pid",42},{"message","Event " + std::to_string(i) + (i==7?" 验证码":"")}}.dump() << '\n';
        }
        auto first=read_logs(config,"auth","",100);
        check(first["entries"][0]["message"]=="Event 1799" && !first["next_cursor"].get<std::string>().empty(),"first log page ordering failed");
        {
            std::ofstream file(logs/"auth.jsonl",std::ios::app);
            file << Json{{"timestamp","2026-10-14T12:01:00.000Z"},{"service","auth"},{"level","info"},{"pid",42},{"message","appended"}}.dump() << '\n';
        }
        std::filesystem::rename(logs/"auth.jsonl",logs/"auth.jsonl.1");
        {std::ofstream file(logs/"auth.jsonl");file << Json{{"timestamp","2026-10-14T12:02:00.000Z"},{"service","auth"},{"level","info"},{"pid",42},{"message","new log"}}.dump() << '\n';}
        auto page=first;std::size_t count=first["entries"].size();int expected=1699;
        while (!page["next_cursor"].get<std::string>().empty()) {
            page=read_logs(config,"auth","",100,"",page["next_cursor"]);
            for (const auto& item:page["entries"]) {
                const auto text=item["message"].get<std::string>();
                check(text=="Event " + std::to_string(expected)+(expected==7?" 验证码":""),"pagination skipped or repeated an event");
                --expected;++count;
            }
        }
        check(count==1800 && expected==-1,"older retained events were inaccessible");
        const auto found=read_logs(config,"auth","warn",100,"验证码");
        check(found["entries"].empty(),"search ignored severity");
        auto search=read_logs(config,"auth","info",100,"验证码");
        check(search["entries"].size()==1 && search["entries"][0]["message"]=="Event 7 验证码","search did not inspect older log data");
        rejects([&] { read_logs(config,"auth","warn",100,"",first["next_cursor"]); });
        std::filesystem::remove_all(directory);
        std::cout << "Logging tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
