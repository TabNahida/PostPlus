#pragma once
#include <postplus/core.hpp>

namespace postplus {
struct SetupOptions {
    std::filesystem::path config_path;
    std::filesystem::path web_root;
    int port = 8080;
};
// The callback provisions an administrator through an isolated auth process.
// Its Config points to a fully written staging file. Commit follows successful provisioning.
using SetupProvision = std::function<void(const Config&, const std::string&, const std::string&)>;
bool run_setup(const SetupOptions& options, SetupProvision provision);
}
