#pragma once
#include <postplus/core.hpp>

namespace postplus {
Json mail_client_settings(const Config& config);
// Public configuration only. No password is accepted or returned.
std::optional<HttpResponse> mail_client_discovery(const Config& config, const HttpRequest& request);
}
