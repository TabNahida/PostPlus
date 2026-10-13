#pragma once
#include <postplus/core.hpp>
#include <postplus/restart.hpp>
#include <postplus/update.hpp>
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

struct SupervisorUpdateRequest {
    std::string action, job_id, version;
};
UpdateOptions supervisor_update_options(const Config& config);
Json supervisor_update_status(const Config& config, const std::string& job_id = "");
Json request_supervisor_update(const Config& config, const std::string& action,
                               const std::string& value);

// A private, per-launch request mailbox. Only children of the native supervisor
// inherit its unpredictable capability. No listener or configurable port is used.
class SupervisorControl {
public:
    explicit SupervisorControl(const Config& config);
    ~SupervisorControl();
    bool shutdown_requested();
    std::optional<RestartRequest> restart_requested();
    std::optional<SupervisorUpdateRequest> update_requested();
    void update_progress(const SupervisorUpdateRequest& request, Json state);
    void update_finished(const SupervisorUpdateRequest& request, Json state);
    std::filesystem::path snapshot_config(const Config& config);
    void ready(const Config& config);
    void restart_running(const RestartRequest& request, bool service_manager = false);
    void restart_complete(const RestartRequest& request, const Config& config);
    void restart_failed(const RestartRequest& request, const std::string& error,
                        bool rolled_back = false);
private:
    std::filesystem::path directory_;
    std::filesystem::path state_directory_;
    Config config_;
    std::vector<std::filesystem::path> snapshots_;
    std::string token_;
    bool ready_ = false;
};
void request_supervisor_shutdown(const Config& config);
}
