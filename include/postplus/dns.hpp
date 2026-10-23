#pragma once
#include <postplus/core.hpp>
#include <postplus/ip.hpp>
#include <stdexcept>

namespace postplus {
class DnsError : public std::runtime_error {
public:
    std::string code;
    explicit DnsError(std::string name,std::string message)
        : std::runtime_error(std::move(message)),code(std::move(name)) {}
};

// Only native code can inject this offline wire transport. Browser input
// cannot select a resolver, URL, port, deadline or transport.
using DnsTransport=std::function<std::vector<unsigned char>(
    const std::vector<unsigned char>&,std::chrono::steady_clock::time_point)>;
using DnsConnect=std::function<bool(const ip::address&,int,
    std::chrono::steady_clock::time_point)>;
struct DnsOptions {
    std::chrono::seconds timeout{10};
    DnsTransport transport;
    DnsTransport tcp_transport;
    // Native-only hook. Browser requests cannot choose hosts or TCP ports.
    DnsConnect connect;
};
enum class DnsType : std::uint16_t { a=1,cname=5,ptr=12,mx=15,txt=16,aaaa=28,srv=33 };
struct DnsLookup {
    std::vector<std::string> values;
    bool alias=false;
    bool nxdomain=false;
    std::string canonical_name;
    unsigned alias_hops=0;
};
// Outbound mail uses a bounded public resolver and connects only the returned
// numeric public addresses. Hooks are native-only and permit offline tests.
class DnsResolver {
public:
    explicit DnsResolver(DnsOptions options={});
    DnsLookup lookup(std::string name,DnsType type,std::chrono::steady_clock::time_point deadline) const;
private:
    DnsOptions options_;
};
bool is_public_mail_address(const ip::address& address);
bool valid_public_dns_name(std::string_view name);
// Recommendations use saved server settings. Optional expected public DNS
// values are diagnostic drafts only and never change the configuration.
Json dns_recommendations(const Config& config,const Json& input=Json::object());
class DnsChecker {
public:
    explicit DnsChecker(DnsOptions options={});
    // All fields are text. Required: domain, hostname. Optional: ipv4, ipv6,
    // spf, dkim_name, dkim_type (TXT/CNAME), dkim_value, dmarc.
    Json check(const Json& request) const;
    Json check_server(const Config& config,const Json& input) const;
private:
    DnsOptions options_;
};
}
