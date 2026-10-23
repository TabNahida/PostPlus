#include <postplus/ip.hpp>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <net/if.h>
#endif

#include <algorithm>
#include <charconv>

namespace postplus::ip {
namespace {
std::error_code invalid_address() { return std::make_error_code(std::errc::invalid_argument); }

template<class Address> Address checked(Address value, const std::error_code& error) {
    if (error) throw std::system_error(error, "invalid numeric IP address");
    return value;
}

bool scope_index(std::string_view text, std::uint32_t& scope) {
    if (text.empty() || text.find('\0') != text.npos || text.find('%') != text.npos) return false;
    if (text.find_first_not_of("0123456789") == text.npos) {
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), scope);
        return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
    }
    // Interface names are local metadata, never hostname/DNS resolution.
    scope = ::if_nametoindex(std::string(text).c_str());
    return scope != 0;
}
}

std::string address_v4::to_string() const {
    return std::to_string(bytes_[0]) + '.' + std::to_string(bytes_[1]) + '.' +
           std::to_string(bytes_[2]) + '.' + std::to_string(bytes_[3]);
}

std::string address_v6::to_string() const {
    char text[INET6_ADDRSTRLEN]{};
    if (!::inet_ntop(AF_INET6, bytes_.data(), text, sizeof(text)))
        throw std::system_error(invalid_address(), "cannot format IPv6 address");
    std::string result(text);
    std::transform(result.begin(), result.end(), result.begin(), [](char ch) {
        return ch >= 'A' && ch <= 'F' ? static_cast<char>(ch + ('a' - 'A')) : ch;
    });
    if (scope_) result += '%' + std::to_string(scope_);
    return result;
}

address_v4 make_address_v4(std::string_view value, std::error_code& error) {
    error = invalid_address();
    if (value.empty() || value.size() > 15 || value.find_first_not_of("0123456789.") != value.npos)
        return {};
    address_v4::bytes_type bytes{};
    const std::string text(value);
    if (::inet_pton(AF_INET, text.c_str(), bytes.data()) != 1) return {};
    // Keep validation consistent on platforms with permissive IPv4 parsers.
    const address_v4 result(bytes);
    if (result.to_string() != value) return {};
    error.clear();
    return result;
}

address_v4 make_address_v4(std::string_view value) {
    std::error_code error;
    const auto result = make_address_v4(value, error);
    return checked(result, error);
}

address_v6 make_address_v6(std::string_view value, std::error_code& error) {
    error = invalid_address();
    const auto percent = value.find('%');
    const auto numeric = value.substr(0, percent);
    if (numeric.empty() || numeric.size() >= INET6_ADDRSTRLEN ||
        numeric.find_first_not_of("0123456789abcdefABCDEF:.") != numeric.npos ||
        std::count(numeric.begin(), numeric.end(), ':') < 2) return {};
    address_v6::bytes_type bytes{};
    const std::string text(numeric);
    if (::inet_pton(AF_INET6, text.c_str(), bytes.data()) != 1) return {};
    std::uint32_t scope = 0;
    if (percent != value.npos && !scope_index(value.substr(percent + 1), scope)) return {};
    error.clear();
    return address_v6(bytes, scope);
}

address_v6 make_address_v6(std::string_view value) {
    std::error_code error;
    const auto result = make_address_v6(value, error);
    return checked(result, error);
}

address make_address(std::string_view value, std::error_code& error) {
    if (value.find(':') != value.npos) return make_address_v6(value, error);
    return make_address_v4(value, error);
}

address make_address(std::string_view value) {
    std::error_code error;
    const auto result = make_address(value, error);
    return checked(result, error);
}
} // namespace postplus::ip
