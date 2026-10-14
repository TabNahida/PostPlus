#pragma once
#include <postplus/core.hpp>
#include <atomic>

namespace postplus {
class UpdateError : public std::runtime_error {
public:
    std::string code;
    int status;
    UpdateError(std::string name, std::string message, int http = 503)
        : std::runtime_error(std::move(message)), code(std::move(name)), status(http) {}
};
struct UpdateHttpResponse {
    int status = 0;
    std::map<std::string, std::string> headers;
    std::string body;
};
using UpdateTransport = std::function<UpdateHttpResponse(const std::string& url,
    std::size_t maximum_bytes, std::chrono::steady_clock::time_point deadline)>;
using UpdateProgress = std::function<void(const Json&)>;
struct UpdateOptions {
    std::filesystem::path install_directory;
    std::filesystem::path web_directory;
    // data_dir/.updates; job status is <storage>/<32-hex job_id>/job.json.
    // staged -> applying -> installed -> complete, or rolled_back/failed.
    // stage failures terminate as failed/cancelled. installed needs readiness.
    std::filesystem::path storage_directory;
    std::string current_version;
    // Offline tests only; never populate from HTTP request or saved settings.
    UpdateTransport transport;
};
std::string update_build_version();
std::string update_platform();
std::string update_architecture();
std::string installed_update_version(const UpdateOptions& options);
// Fixed source: highest stable semantic version among the latest 20 official
// GitHub Releases in TabNahida/PostPlus; independent of the legacy Latest badge.
// Results contain changed files/services and whether the launcher must relaunch.
Json check_update(const UpdateOptions& options);
// Caller owns async job scheduling and global restart/settings/backup exclusion.
// Version pins the previously reviewed release; a changed latest release fails.
Json stage_update(const UpdateOptions& options, const std::string& version,
    const std::string& job_id, const std::atomic<bool>& cancel,
    const UpdateProgress& progress = {});
Json update_job_status(const UpdateOptions& options, const std::string& job_id);
// Offline transaction. Caller stops only plan.services, then checks readiness.
// Windows executes these in a private copy of postplus-update, after the
// supervisor releases affected executable handles (including itself if needed).
Json apply_staged_update(const UpdateOptions& options, const std::string& job_id);
Json rollback_staged_update(const UpdateOptions& options, const std::string& job_id);
Json commit_staged_update(const UpdateOptions& options, const std::string& job_id);
// Before starting any service, restore ordinary module transactions that were
// interrupted before readiness commit. Launcher handoffs retain their separate
// startup/helper acknowledgement. Returns restored terminal job reports.
std::vector<Json> recover_interrupted_updates(const UpdateOptions& options);
// systemd ExecStartPre: allow one boot of installed launcher modules; if the
// previous generation never acknowledged readiness, restore before another
// exec. The restored launcher clears the handoff after service readiness.
Json recover_launcher_update(const UpdateOptions& options, const std::filesystem::path& config);
std::filesystem::path copy_update_helper(const UpdateOptions& options, const std::string& job_id);
// Relaunch handshake: prepare persists <storage>/relaunch.json. New launcher
// reads pending_update_relaunch before startup and commits only after all
// services are ready. Unix installs while the old inode is running, then exits
// 75 for systemd (or execs the new launcher). It must not fork a cgroup helper.
Json prepare_update_relaunch(const UpdateOptions& options, const std::string& job_id,
    const std::filesystem::path& config);
std::optional<Json> pending_update_relaunch(const UpdateOptions& options);
void finish_update_relaunch(const UpdateOptions& options, const std::string& job_id);
// Windows: spawn detached private helper outside ProcessGroup; wait for its
// ready file, then caller stops all services and exits. Helper waits for parent,
// applies, launches postplus --config, waits for startup commit, and rolls back
// after process exit/timeout. CLI: --takeover --parent PID --config PATH plus
// --job ID --install DIR --web DIR --state DIR. Returns helper PID.
std::uint64_t launch_update_takeover(const UpdateOptions& options, const std::string& job_id,
    const std::filesystem::path& config, std::uint64_t parent_pid);
void mark_update_takeover_ready(const UpdateOptions& options, const std::string& job_id);
void fail_staged_update(const UpdateOptions& options, const std::string& job_id, const std::string& error);
}
