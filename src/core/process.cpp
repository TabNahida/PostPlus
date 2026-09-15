#include <postplus/process.hpp>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <system_error>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif

namespace postplus {
namespace {
#ifdef _WIN32
std::wstring widen(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                       static_cast<int>(value.size()), nullptr, 0);
    if (!size) throw std::invalid_argument("process argument is not valid UTF-8");
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), size);
    return result;
}

// Match the MSVC command-line parser, including embedded quotes and trailing
// backslashes. Always quoting also preserves empty arguments.
std::wstring quote(const std::wstring& value) {
    std::wstring result = L"\"";
    std::size_t backslashes = 0;
    for (const auto ch : value) {
        if (ch == L'\\') { ++backslashes; continue; }
        result.append(backslashes * (ch == L'\"' ? 2 : 1), L'\\');
        backslashes = 0;
        if (ch == L'\"') result += L'\\';
        result += ch;
    }
    result.append(backslashes * 2, L'\\');
    result += L'\"';
    return result;
}

std::wstring stop_event_name(DWORD pid) {
    return L"Local\\PostPlus.Stop." + std::to_wstring(pid);
}

std::runtime_error windows_failure(const char* operation) {
    return std::runtime_error(std::string(operation) + " failed (Windows error " +
                              std::to_string(GetLastError()) + ")");
}
#endif

struct Child {
    std::string name;
    std::optional<int> code;
#ifdef _WIN32
    HANDLE process = nullptr;
    HANDLE stop_event = nullptr;
    ~Child() {
        if (stop_event) CloseHandle(stop_event);
        if (process) CloseHandle(process);
    }
#else
    pid_t pid = -1;
#endif
};

bool poll(Child& child) noexcept {
    if (child.code) return true;
#ifdef _WIN32
    const auto state = WaitForSingleObject(child.process, 0);
    if (state == WAIT_TIMEOUT) return false;
    DWORD code = 1;
    if (state == WAIT_OBJECT_0) GetExitCodeProcess(child.process, &code);
    child.code = static_cast<int>(code);
    return true;
#else
    int status = 0;
    pid_t result;
    do { result = waitpid(child.pid, &status, WNOHANG); } while (result < 0 && errno == EINTR);
    if (result == 0) return false;
    if (result < 0) { child.code = 1; return true; }
    child.code = WIFEXITED(status) ? WEXITSTATUS(status) :
                 WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
    return true;
#endif
}
}

struct ProcessGroup::Impl {
    std::vector<std::unique_ptr<Child>> children;
#ifdef _WIN32
    HANDLE job = nullptr;
    Impl() {
        job = CreateJobObjectW(nullptr, nullptr);
        if (!job) throw windows_failure("CreateJobObject");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
            auto error = windows_failure("SetInformationJobObject");
            CloseHandle(job); job = nullptr;
            throw error;
        }
    }
    ~Impl() { if (job) CloseHandle(job); }
#endif
};

ProcessGroup::ProcessGroup() : impl_(std::make_unique<Impl>()) {}
ProcessGroup::~ProcessGroup() { stop(); }

void ProcessGroup::start(const std::string& name, const std::filesystem::path& executable,
                         const std::vector<std::string>& arguments) {
    const auto absolute = std::filesystem::absolute(executable);
    if (!std::filesystem::is_regular_file(absolute))
        throw std::runtime_error("missing service executable: " + absolute.string());
    for (const auto& argument : arguments)
        if (argument.find('\0') != std::string::npos) throw std::invalid_argument("invalid process argument");
    auto child = std::make_unique<Child>();
    child->name = name;
    // Allocate storage before spawning so allocation failures cannot orphan a child.
    impl_->children.reserve(impl_->children.size() + 1);
#ifdef _WIN32
    std::wstring command = quote(absolute.native());
    for (const auto& argument : arguments) command += L" " + quote(widen(argument));
    if (command.size() >= 32767) throw std::invalid_argument("process command line is too long");
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION info{};
    if (!CreateProcessW(absolute.c_str(), command.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &info))
        throw windows_failure("CreateProcess");
    child->process = info.hProcess;
    struct StartingChild {
        PROCESS_INFORMATION& info;
        bool active = true;
        ~StartingChild() {
            if (active) {
                TerminateProcess(info.hProcess, 1);
                WaitForSingleObject(info.hProcess, INFINITE);
            }
            CloseHandle(info.hThread);
        }
    } starting{info};
    if (!AssignProcessToJobObject(impl_->job, info.hProcess)) throw windows_failure("AssignProcessToJobObject");
    child->stop_event = CreateEventW(nullptr, TRUE, FALSE, stop_event_name(info.dwProcessId).c_str());
    if (!child->stop_event) throw windows_failure("CreateEvent");
    if (ResumeThread(info.hThread) == static_cast<DWORD>(-1)) throw windows_failure("ResumeThread");
    starting.active = false;
#else
    const auto program = absolute.string();
    std::vector<char*> argv;
    argv.reserve(arguments.size() + 2);
    argv.push_back(const_cast<char*>(program.c_str()));
    for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    // The close-on-exec pipe communicates exec failure without any child-side
    // allocations. All work between fork and exec is async-signal-safe.
    int error_pipe[2];
    if (pipe(error_pipe) != 0) throw std::system_error(errno, std::generic_category(), "pipe");
    if (fcntl(error_pipe[0], F_SETFD, FD_CLOEXEC) == -1 ||
        fcntl(error_pipe[1], F_SETFD, FD_CLOEXEC) == -1) {
        const int error = errno; close(error_pipe[0]); close(error_pipe[1]);
        throw std::system_error(error, std::generic_category(), "fcntl");
    }
    const pid_t parent = getpid();
    const pid_t pid = fork();
    const int fork_error = errno;
    if (pid == 0) {
        close(error_pipe[0]);
        int error = 0;
        struct sigaction defaults{};
        defaults.sa_handler = SIG_DFL;
        sigemptyset(&defaults.sa_mask);
        if (sigaction(SIGTERM, &defaults, nullptr) != 0 || sigaction(SIGINT, &defaults, nullptr) != 0) error = errno;
        if (setpgid(0, 0) != 0) error = errno;
#ifdef __linux__
        // Also terminate a service if its launcher is killed before its RAII
        // cleanup can execute. The parent check closes the fork/prctl race.
        if (!error && prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) error = errno;
        if (!error && getppid() != parent) _exit(1);
#else
        (void)parent;
#endif
        if (!error) { execv(program.c_str(), argv.data()); error = errno; }
        ssize_t ignored;
        do { ignored = write(error_pipe[1], &error, sizeof(error)); } while (ignored < 0 && errno == EINTR);
        _exit(127);
    }
    close(error_pipe[1]);
    if (pid < 0) {
        close(error_pipe[0]);
        throw std::system_error(fork_error, std::generic_category(), "fork");
    }
    child->pid = pid;
    int error = 0;
    ssize_t count;
    do { count = read(error_pipe[0], &error, sizeof(error)); } while (count < 0 && errno == EINTR);
    const int read_error = errno;
    close(error_pipe[0]);
    if (count != 0) {
        kill(pid, SIGKILL);
        while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
        throw std::system_error(count < 0 ? read_error : error, std::generic_category(), "start " + name);
    }
#endif
    impl_->children.push_back(std::move(child));
}

std::optional<std::pair<std::string, int>> ProcessGroup::exited() {
    for (auto& child : impl_->children)
        if (poll(*child)) return std::pair{child->name, *child->code};
    return {};
}

void ProcessGroup::stop(std::chrono::milliseconds grace) noexcept {
    if (!impl_ || impl_->children.empty()) return;
    for (auto it = impl_->children.rbegin(); it != impl_->children.rend(); ++it) {
        auto& child = **it;
        if (poll(child)) continue;
#ifdef _WIN32
        SetEvent(child.stop_event);
#else
        kill(-child.pid, SIGTERM);
#endif
    }
    const auto deadline = std::chrono::steady_clock::now() + grace;
    for (;;) {
        bool all_done = true;
        for (auto& child : impl_->children) if (!poll(*child)) all_done = false;
        if (all_done || std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    for (auto& pointer : impl_->children) {
        auto& child = *pointer;
        if (poll(child)) continue;
#ifdef _WIN32
        TerminateProcess(child.process, 1);
        WaitForSingleObject(child.process, INFINITE);
#else
        kill(-child.pid, SIGKILL);
        while (waitpid(child.pid, nullptr, 0) < 0 && errno == EINTR) {}
#endif
        child.code = 1;
    }
    impl_->children.clear();
}

bool process_stop_requested() noexcept {
#ifdef _WIN32
    struct StopEvent {
        HANDLE value = CreateEventW(nullptr, TRUE, FALSE, stop_event_name(GetCurrentProcessId()).c_str());
        ~StopEvent() { if (value) CloseHandle(value); }
    };
    static StopEvent event;
    return event.value && WaitForSingleObject(event.value, 0) == WAIT_OBJECT_0;
#else
    return false;
#endif
}

std::filesystem::path executable_path(const char* argv0) {
#ifdef _WIN32
    (void)argv0;
    std::wstring buffer(32768, L'\0');
    const auto count = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!count || count >= buffer.size()) throw windows_failure("GetModuleFileName");
    buffer.resize(count);
    return std::filesystem::path(buffer);
#elif defined(__linux__)
    std::string buffer(65536, '\0');
    const auto count = readlink("/proc/self/exe", buffer.data(), buffer.size());
    if (count > 0 && static_cast<std::size_t>(count) < buffer.size()) {
        buffer.resize(static_cast<std::size_t>(count));
        return std::filesystem::path(buffer);
    }
#elif defined(__APPLE__)
    std::uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string buffer(size, '\0');
    if (_NSGetExecutablePath(buffer.data(), &size) == 0)
        return std::filesystem::weakly_canonical(buffer.c_str());
#endif
#ifndef _WIN32
    auto candidate = std::filesystem::path(argv0);
    if (candidate.has_parent_path()) return std::filesystem::absolute(candidate);
    if (const char* paths = std::getenv("PATH")) {
        const std::string value(paths);
        std::size_t start = 0;
        while (start <= value.size()) {
            const auto end = value.find(':', start);
            candidate = std::filesystem::path(value.substr(start, end - start)) / argv0;
            if (std::filesystem::is_regular_file(candidate)) return std::filesystem::absolute(candidate);
            if (end == std::string::npos) break;
            start = end + 1;
        }
    }
    throw std::runtime_error("cannot locate the PostPlus executable");
#endif
}
}
