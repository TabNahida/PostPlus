#pragma once
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace postplus {
// Child processes are started directly, with no command interpreter. The group
// owns every child and always waits for them during destruction.
class ProcessGroup {
public:
    ProcessGroup();
    ~ProcessGroup();
    ProcessGroup(const ProcessGroup&) = delete;
    ProcessGroup& operator=(const ProcessGroup&) = delete;
    void start(const std::string& name, const std::filesystem::path& executable,
               const std::vector<std::string>& arguments);
    std::optional<std::pair<std::string, int>> exited();
    void stop(std::chrono::milliseconds grace = std::chrono::seconds(35)) noexcept;
    bool stop_services(const std::vector<std::string>& names, std::chrono::milliseconds grace,
                       const std::function<void(const std::string&)>& progress) noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::filesystem::path executable_path(const char* argv0);
// Windows services poll this event for graceful shutdown even without a console.
// Unix services receive SIGTERM through their existing signal handlers.
bool process_stop_requested() noexcept;
}
