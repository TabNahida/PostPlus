#pragma once
#include <postplus/core.hpp>
#include <postplus/dns.hpp>

namespace postplus {
// Saved configuration is read for each operation. A pending domain cannot
// receive mail or authenticate until its DNS evidence is checked and activated.
Json domains_list(const Config& running,const Json& query=Json::object());
Json domains_add(const Config& running,const Json& request);
Json domains_preview(const Config& running,const Json& request);
Json domains_check(const Config& running,const Json& request,DnsOptions options={});
Json domains_activate(const Config& running,const Json& request);
Json domains_remove(const Config& running,const Json& request);
}
