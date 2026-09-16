#pragma once
#include <postplus/core.hpp>
#include <stdexcept>

namespace postplus {
class SettingsError : public std::runtime_error {
public:
    std::string field;
    int status;
    SettingsError(std::string key, std::string message, int http = 400)
        : std::runtime_error(std::move(message)), field(std::move(key)), status(http) {}
};
Json settings_schema(const Config& config);
Json settings_view(const Config& config);
Config validate_settings(const Config& existing, const Json& patch);
Json save_settings(const Config& config, const Json& request);
std::string settings_url(const Config& config, const std::string& service);
// Used by bootstrap completion as well as authenticated settings updates.
// The caller supplies the original bytes, preventing accidental stale writes.
void replace_config_file(const std::filesystem::path& destination,
                         const std::string& expected, const std::string& replacement);
}
