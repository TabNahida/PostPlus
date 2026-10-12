#pragma once
#include <postplus/dns.hpp>

namespace postplus {
class OutboundError : public std::runtime_error {
public:
    std::string code;
    bool permanent;
    OutboundError(std::string name,std::string message,bool terminal=false)
        :std::runtime_error(std::move(message)),code(std::move(name)),permanent(terminal){}
};
using OutboundConnector=std::function<void(Connection&,const tcp::endpoint&,const std::string&)>;
struct OutboundOptions {
    DnsOptions dns;
    // Test code can route a validated public destination to a local fixture.
    // Configuration and RPC callers cannot select or disable this validation.
    OutboundConnector connect;
};
void deliver_direct(const Config& config,const std::string& sender,const std::string& recipient,
                    std::string_view raw,OutboundOptions options={});
}
