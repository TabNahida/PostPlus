#include <postplus/process.hpp>

#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string_view>
#include <thread>

using namespace postplus;
namespace {
volatile std::sig_atomic_t child_stopping = 0;
void child_stop(int) { child_stopping = 1; }
const std::string quoted_argument = "spaces, embedded \"quotes\", and a slash before a quote: \\\"";

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

std::string read_state(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::string state;
    std::getline(input, state);
    return state;
}

std::string argument_path(const std::filesystem::path& path) {
    const auto text = path.u8string();
    return {reinterpret_cast<const char*>(text.data()), text.size()};
}

struct TemporaryDirectory {
    std::filesystem::path path;
    TemporaryDirectory() {
        std::random_device random;
        for (int attempts = 0; attempts < 10; ++attempts) {
            path = std::filesystem::temp_directory_path() /
                ("postplus process tests " + std::to_string(random()) + " " + std::to_string(random()));
            if (std::filesystem::create_directory(path)) return;
        }
        throw std::runtime_error("cannot create unique process test directory");
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
};
}

int main(int argc, char** argv) {
    if (argc > 1 && std::string_view(argv[1]) == "--child") {
        if (argc != 6 || argv[2] != quoted_argument || std::string_view(argv[3]) != "" ||
            std::string_view(argv[4]) != "path with spaces\\") return 9;
        std::signal(SIGTERM, child_stop);
        std::signal(SIGINT, child_stop);
        std::ofstream(argv[5]) << "ready";
        while (!child_stopping && !process_stop_requested())
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::ofstream(argv[5]) << "stopped";
        return 0;
    }
    if (argc > 1 && std::string_view(argv[1]) == "--early") return 7;
    if (argc > 1 && std::string_view(argv[1]) == "--hang") {
        std::signal(SIGTERM, SIG_IGN);
        for (;;) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    try {
        TemporaryDirectory directory;
        const auto own_executable = executable_path(argv[0]);
        const auto executable = directory.path / ("helper with spaces" + own_executable.extension().string());
        std::filesystem::copy_file(own_executable, executable);
        const auto record = directory.path / "child state.txt";
        ProcessGroup children;
        children.start("child", executable,
                       {"--child", quoted_argument, "", "path with spaces\\", argument_path(record)});
        bool ready = false;
        for (int attempt = 0; attempt < 500; ++attempt) {
            require(!children.exited(), "child exited before readiness (argument quoting failed)");
            if (read_state(record) == "ready") { ready = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        require(ready, "child did not become ready");
        children.stop(std::chrono::seconds(3));
        require(read_state(record) == "stopped", "child did not stop gracefully");

        children.start("early", executable, {"--early"});
        std::optional<std::pair<std::string, int>> exited;
        for (int attempt = 0; attempt < 500 && !(exited = children.exited()); ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        require(exited && exited->first == "early" && exited->second == 7, "child exit status was not preserved");
        children.stop();

        children.start("hang", executable, {"--hang"});
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const auto started = std::chrono::steady_clock::now();
        children.stop(std::chrono::milliseconds(100));
        require(std::chrono::steady_clock::now() - started < std::chrono::seconds(5), "forced shutdown exceeded its bound");

        bool missing_failed = false;
        try { children.start("missing", directory.path / "missing executable", {}); }
        catch (const std::exception&) { missing_failed = true; }
        require(missing_failed, "starting a missing executable must fail");
        std::cout << "Process tests passed: executable and argument paths with spaces, quotes, empty arguments, "
                     "graceful shutdown, exit status, bounded force stop, and missing executable.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Process test failed: " << error.what() << '\n';
        return 1;
    }
}
