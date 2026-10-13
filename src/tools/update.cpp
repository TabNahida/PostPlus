#include <postplus/update.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/process.hpp>
#include <charconv>
#include <iostream>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace postplus;
namespace {
namespace fs = std::filesystem;
struct Options {
    UpdateOptions update;
    fs::path config;
    std::string id, operation;
    std::uint64_t parent = 0;
};
Options parse(const std::vector<std::string>& arguments) {
    Options result;
    for (std::size_t i = 1; i < arguments.size(); ++i) {
        const auto& argument = arguments[i];
        if (argument == "--apply" || argument == "--rollback" || argument == "--commit" || argument == "--takeover" || argument == "--recover-launcher") {
            if (!result.operation.empty()) throw std::invalid_argument("Choose exactly one updater operation.");
            result.operation = argument.substr(2); continue;
        }
        if (argument != "--job" && argument != "--install" && argument != "--web" && argument != "--state" && argument != "--config" && argument != "--parent")
            throw std::invalid_argument("Unknown updater option: " + argument);
        if (++i == arguments.size()) throw std::invalid_argument("Updater option requires a value.");
        const auto& value = arguments[i];
        if (argument == "--job") result.id = value;
        else if (argument == "--install") result.update.install_directory = fs::u8path(value);
        else if (argument == "--web") result.update.web_directory = fs::u8path(value);
        else if (argument == "--state") result.update.storage_directory = fs::u8path(value);
        else if (argument == "--config") result.config = fs::u8path(value);
        else {
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), result.parent);
            if (error != std::errc{} || end != value.data() + value.size() || !result.parent) throw std::invalid_argument("Invalid parent process identifier.");
        }
    }
    if (result.operation == "recover-launcher") {
        if (result.config.empty()) throw std::invalid_argument("Launcher recovery requires --config.");
        const auto config = Config::from_file(fs::absolute(result.config).lexically_normal());
        if (result.update.install_directory.empty()) result.update.install_directory = executable_path(arguments[0].c_str()).parent_path();
        if (result.update.web_directory.empty()) result.update.web_directory = fs::path(config.text("web_root", (result.update.install_directory / "web").string()));
        if (result.update.storage_directory.empty()) result.update.storage_directory = fs::path(config.text("data_dir")) / ".updates";
    }
    if (result.operation.empty() || (result.id.empty() && result.operation != "recover-launcher") || result.update.install_directory.empty() || result.update.storage_directory.empty())
        throw std::invalid_argument("Updater requires an operation, --job, --install and --state.");
    if (result.operation == "takeover" && (result.config.empty() || !result.parent)) throw std::invalid_argument("Takeover requires --config and --parent.");
    result.update.current_version = update_build_version(); return result;
}
#ifdef _WIN32
struct Handle { HANDLE value = nullptr; ~Handle() { if (value) CloseHandle(value); } };
std::wstring quote(const std::wstring& value) {
    std::wstring result = L"\""; std::size_t slashes = 0;
    for (const auto ch : value) {
        if (ch == L'\\') { ++slashes; continue; }
        result.append(slashes * (ch == L'\"' ? 2 : 1), L'\\'); slashes = 0;
        if (ch == L'\"') result += L'\\'; result += ch;
    }
    result.append(slashes * 2, L'\\'); return result + L'\"';
}
void stop_launcher(HANDLE process, DWORD pid) {
    const auto name = L"Local\\PostPlus.Stop." + std::to_wstring(pid);
    Handle stop; stop.value = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
    if (stop.value) SetEvent(stop.value);
    if (WaitForSingleObject(process, 150000) == WAIT_TIMEOUT) {
        if (!TerminateProcess(process, 1) || WaitForSingleObject(process, 30000) != WAIT_OBJECT_0)
            throw std::runtime_error("Cannot stop the failed launcher before restoring its modules.");
    }
}
bool launch_and_wait(const Options& options, bool restoring) {
    const auto root = fs::absolute(options.update.install_directory).lexically_normal();
    const auto launcher = root / "postplus.exe"; require_plain_path(launcher);
    auto command = quote(launcher.native()) + L" --config " + quote(fs::absolute(options.config).native());
    const auto log = fs::absolute(options.update.storage_directory) / options.id / "launcher.log";
    require_plain_path(log);
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle output; output.value = CreateFileW(log.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (output.value == INVALID_HANDLE_VALUE) { output.value = nullptr; throw std::runtime_error("Cannot open private launcher recovery log."); }
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    startup.wShowWindow = SW_HIDE; startup.hStdOutput = output.value; startup.hStdError = output.value; startup.hStdInput = nullptr;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(launcher.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, root.c_str(), &startup, &process)) throw std::runtime_error("Cannot start the updated launcher.");
    Handle child; child.value = process.hProcess; CloseHandle(process.hThread);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(240);
    try {
        while (std::chrono::steady_clock::now() < deadline && WaitForSingleObject(child.value, 100) == WAIT_TIMEOUT) {
            const auto job = update_job_status(options.update, options.id);
            if (!restoring && job.value("state", "") == "complete") return true;
            // The old launcher acknowledges a restored generation only after all
            // services are ready; it clears the persisted relaunch record.
            if (restoring && !pending_update_relaunch(options.update)) return true;
            if (!restoring && job.value("state", "") == "failed") break;
        }
    } catch (...) { stop_launcher(child.value, process.dwProcessId); throw; }
    stop_launcher(child.value, process.dwProcessId); return false;
}
void takeover(const Options& options) {
    if (options.parent > MAXDWORD || options.parent == GetCurrentProcessId()) throw std::invalid_argument("Invalid parent process identifier.");
    Handle parent; parent.value = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(options.parent));
    if (!parent.value) throw std::runtime_error("Cannot pin the original launcher process.");
    const auto pending = pending_update_relaunch(options.update);
    if (!pending || pending->at("job_id") != options.id || pending->at("config") != fs::absolute(options.config).lexically_normal().string())
        throw std::runtime_error("Launcher takeover does not match its private handoff.");
    mark_update_takeover_ready(options.update, options.id);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    for (;;) {
        const auto record = pending_update_relaunch(options.update);
        if (!record || record->at("job_id") != options.id)
            throw std::runtime_error("Launcher takeover was cancelled before installation.");
        if (WaitForSingleObject(parent.value, 100) == WAIT_OBJECT_0) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            finish_update_relaunch(options.update, options.id);
            throw std::runtime_error("Original launcher did not stop before takeover timeout.");
        }
    }
    try {
        (void)apply_staged_update(options.update, options.id);
        if (launch_and_wait(options, false)) return;
        throw std::runtime_error("Updated launcher failed its startup readiness acknowledgement.");
    } catch (const std::exception& error) {
        const auto reason = std::string(error.what());
        (void)rollback_staged_update(options.update, options.id);
        if (!launch_and_wait(options, true)) {
            fail_staged_update(options.update, options.id, reason + " Original modules were restored, but the old launcher also failed to become ready.");
            throw std::runtime_error("Original launcher failed recovery; review launcher.log.");
        }
    }
}
#endif
int run(const std::vector<std::string>& arguments) {
    if (arguments.size() == 2 && arguments[1] == "--help") {
        std::cout << "PostPlus verified update helper\n"
            "  --apply|--rollback|--commit --job ID --install DIR --web DIR --state DIR\n"
            "  --takeover --parent PID --config PATH --job ID --install DIR --web DIR --state DIR\n"
            "  --recover-launcher --config PATH [--install DIR --web DIR --state DIR]\n"
            "Takeover is Windows-only. Unix installs before exec/systemd relaunch and uses a durable startup handoff.\n";
        return 0;
    }
    const auto options = parse(arguments);
    try {
        Json result;
        if (options.operation == "apply") result = apply_staged_update(options.update, options.id);
        else if (options.operation == "rollback") result = rollback_staged_update(options.update, options.id);
        else if (options.operation == "commit") result = commit_staged_update(options.update, options.id);
        else if (options.operation == "recover-launcher") result = recover_launcher_update(options.update, options.config);
        else {
#ifdef _WIN32
            takeover(options); result = update_job_status(options.update, options.id);
#else
            throw std::invalid_argument("Windows takeover cannot be used inside a Unix service-manager cgroup.");
#endif
        }
        std::cout << result.dump() << '\n'; return 0;
    } catch (const std::exception& error) {
        if (!options.id.empty()) { try { fail_staged_update(options.update, options.id, error.what()); } catch (...) {} }
        throw;
    }
}
}
#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    try {
        std::vector<std::string> arguments;
        for (int i = 0; i < argc; ++i) {
            const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, nullptr, 0, nullptr, nullptr);
            if (!size) throw std::invalid_argument("Invalid Unicode updater argument.");
            std::string value(static_cast<std::size_t>(size), '\0');
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, value.data(), size, nullptr, nullptr); value.pop_back();
            arguments.push_back(std::move(value));
        }
        return run(arguments);
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
#else
int main(int argc, char** argv) {
    try { return run(std::vector<std::string>(argv, argv + argc)); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
#endif
