#pragma once
#include <postplus/update.hpp>

namespace postplus {
// Decode a verified distribution in memory. Archive names are never filesystem
// destinations: only reviewed, allowlisted modules reach the staging callback.
void extract_update_modules(std::string_view bytes, const std::string& asset,
    const std::string& version, const Json& files, const std::atomic<bool>& cancel,
    const std::function<void(const Json&, std::string_view)>& accept);
}
