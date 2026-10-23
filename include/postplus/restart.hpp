#pragma once
#include <postplus/core.hpp>

namespace postplus {
// Ordered from dependencies to listeners. Endpoint changes include every RPC
// consumer; ordinary policy changes affect only the service reading that field.
const std::vector<std::string>& supervisor_services();
std::vector<std::string> restart_plan(const Config& running, const Config& saved,
                                      const std::string& mode = "changed",
                                      const std::string& service = "");

bool supervisor_restart_available(const Config& config) noexcept;
bool supervisor_restart_busy(const Config& config);
std::optional<Config> supervisor_running_config(const Config& config);
Json supervisor_restart_status(const Config& config, const std::string& job_id = "");
Json request_supervisor_restart(const Config& config, const Config& saved,
                               const std::string& mode = "changed",
                               const std::string& service = "");

struct RestartRequest {
    std::string job_id;
    std::string mode;
    Config config;
    std::vector<std::string> services;
    std::string service;
};
}
