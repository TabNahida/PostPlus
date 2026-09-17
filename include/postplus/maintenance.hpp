#pragma once
#include <postplus/core.hpp>
#include <memory>

namespace postplus {
class MaintenanceError : public std::runtime_error {
public:
    int status;
    MaintenanceError(std::string message, int code = 503) : std::runtime_error(std::move(message)), status(code) {}
};

class BackupManager {
public:
    explicit BackupManager(const Config& config);
    ~BackupManager();
    Json start();
    Json status(const std::string& id);
    HttpResponse download(const std::string& id);
    bool busy() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// A private, per-launch request mailbox. Only children of the native supervisor
// inherit its unpredictable capability. No listener or configurable port is used.
class SupervisorControl {
public:
    explicit SupervisorControl(const Config& config);
    ~SupervisorControl();
    bool shutdown_requested();
private:
    std::filesystem::path directory_;
    std::string token_;
};
void request_supervisor_shutdown(const Config& config);
}
