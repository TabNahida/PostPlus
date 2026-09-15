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
        Config config;
        config.source = directory / "config.json";
        config.values = {{"data_dir",directory.string()},{"log_dir",(directory / "logs").string()},
                         {"service_token_file",token_file.string()},{"service_token_env","POSTPLUS_UNUSED_LOG_TEST_TOKEN"},
                         {"log_max_bytes",1024},{"log_backups",2},{"log_level","info"}};
        check(config.token() == secret,"secret-file authentication failed");
        configure_logging(config,"auth");
        log("auth","must not be recorded","debug");
        check(read_logs(config).at("entries").empty(),"minimum severity ignored");
        log("auth","credential " + secret + "\r\nsecond line","warn");
        auto entries = read_logs(config,"auth","warn").at("entries");
        check(entries.size() == 1,"structured warning missing");
        const auto message = entries[0].at("message").get<std::string>();
        check(message.find(secret) == std::string::npos && message.find("[REDACTED]") != std::string::npos,"service token leaked");
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
        std::filesystem::remove_all(directory);
        std::cout << "Logging tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
