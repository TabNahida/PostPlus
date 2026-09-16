#include <postplus/core.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/settings.hpp>
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>

namespace fs = std::filesystem;
namespace {
constexpr std::array<const char*, 8> database_files{
    "auth.sqlite3", "auth.sqlite3-wal", "auth.sqlite3-shm", "auth.sqlite3-journal",
    "storage.sqlite3", "storage.sqlite3-wal", "storage.sqlite3-shm", "storage.sqlite3-journal"};
bool regular_target(const fs::path& path) {
    postplus::require_plain_path(path);
    std::error_code error;
    const auto status = fs::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory) return false;
    if (error) throw std::runtime_error("cannot inspect cleanup target: " + path.string());
    if (!fs::exists(status)) return false;
    if (!fs::is_regular_file(status)) throw std::runtime_error("refusing non-regular cleanup target: " + path.string());
    if (fs::hard_link_count(path) != 1) throw std::runtime_error("refusing hard-linked cleanup target: " + path.string());
    return true;
}
}

int main(int argc, char** argv) {
    try {
        fs::path config_path = "config/postplus.json";
        bool dry_run = false;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--config") {
                if (++i == argc) throw std::invalid_argument("--config requires a path");
                config_path = argv[i];
            } else if (arg == "--dry-run") dry_run = true;
            else if (arg == "--help" || arg == "-h") {
                std::cout << "Usage: postplus-clean-data [--config PATH] [--dry-run]\n"
                    "Stop PostPlus first. Removes the authentication and mail databases, queue and mailbox data.\n"
                    "Keeps configuration, secret files, logs and certificates; enables first-run setup again.\n";
                return 0;
            } else throw std::invalid_argument("unknown option: " + arg);
        }
        config_path = fs::absolute(config_path).lexically_normal();
        if (!regular_target(config_path)) {
            std::cout << "No configuration found at " << config_path.string()
                << ". No data removed. Use --config PATH to select an existing configuration.\n";
            return 0;
        }
        config_path = fs::canonical(config_path);
        if (fs::file_size(config_path) > 1048576) throw std::runtime_error("configuration must not exceed 1 MiB");
        std::ifstream input(config_path, std::ios::binary);
        if (!input) throw std::runtime_error("cannot read configuration");
        const std::string original{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        input.close();
        auto config = postplus::Json::parse(original);
        if (!config.is_object()) throw std::invalid_argument("configuration must be a JSON object");
        fs::path directory = config.value("data_dir", std::string("../data"));
        if (directory.empty()) directory = "../data";
        if (directory.is_relative()) directory = config_path.parent_path() / directory;
        directory = fs::absolute(directory).lexically_normal();
        postplus::require_plain_path(directory);
        directory = fs::weakly_canonical(directory);
        if (directory == directory.root_path()) throw std::runtime_error("data_dir must not be a filesystem root");

        // Take the lease before inspecting any database or changing setup state.
        // Auth and storage hold shared leases even between SQLite transactions.
        std::unique_ptr<postplus::DataDirectoryLock> lease;
        if (!dry_run && !fs::exists(directory)) fs::create_directories(directory);
        if (fs::exists(directory)) lease = std::make_unique<postplus::DataDirectoryLock>(directory, true);
        std::vector<fs::path> targets;
        for (const auto* name : database_files) {
            const auto target = (directory / name).lexically_normal();
            if (target.parent_path() != directory) throw std::runtime_error("cleanup target escaped data directory");
            if (regular_target(target)) targets.push_back(target);
        }
        std::cout << "Data directory: " << directory.string() << '\n';
        for (const auto& target : targets)
            std::cout << (dry_run ? "Would remove: " : "Removing: ") << target.string() << '\n';
        if (dry_run) {
            std::cout << "Dry run: " << targets.size() << " database files; no files removed or configuration changed.\n";
            return 0;
        }
        // A crash after the config write still leads into setup rather than
        // starting a server whose administrator account may have been removed.
        config["setup_required"] = true;
        postplus::replace_config_file(config_path, original, config.dump(2) + "\n");
        for (const auto& target : targets) {
            if (regular_target(target) && !fs::remove(target))
                throw std::runtime_error("cannot remove cleanup target: " + target.string());
        }
        std::cout << "Removed " << targets.size() << " database files. Configuration, secrets, logs and certificates were kept.\n"
            "Start PostPlus again to create the administrator account through first-run setup.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "clean-data: " << error.what() << '\n';
        return 1;
    }
}
