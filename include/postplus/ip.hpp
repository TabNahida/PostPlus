#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>

namespace postplus::ip {

// Numeric address values only. Parsing never resolves a host or opens a socket.
class address_v4 {
public:
    using bytes_type = std::array<unsigned char, 4>;
    constexpr address_v4() = default;
    explicit constexpr address_v4(bytes_type bytes) : bytes_(bytes) {}
    constexpr bytes_type to_bytes() const { return bytes_; }
    constexpr std::uint32_t to_uint() const {
        return (std::uint32_t(bytes_[0]) << 24) | (std::uint32_t(bytes_[1]) << 16) |
               (std::uint32_t(bytes_[2]) << 8) | bytes_[3];
    }
    std::string to_string() const;
    constexpr bool is_loopback() const { return bytes_[0] == 127; }
    constexpr bool is_unspecified() const { return to_uint() == 0; }
    static constexpr address_v4 loopback() { return address_v4({127, 0, 0, 1}); }
    static constexpr address_v4 any() { return {}; }
    auto operator<=>(const address_v4&) const = default;
private:
    bytes_type bytes_{};
};

class address_v6 {
public:
    using bytes_type = std::array<unsigned char, 16>;
    constexpr address_v6() = default;
    explicit constexpr address_v6(bytes_type bytes, std::uint32_t scope = 0) : bytes_(bytes), scope_(scope) {}
    constexpr bytes_type to_bytes() const { return bytes_; }
    constexpr std::uint32_t scope_id() const { return scope_; }
    constexpr void scope_id(std::uint32_t value) { scope_ = value; }
    std::string to_string() const;
    constexpr bool is_loopback() const {
        for (std::size_t index = 0; index < 15; ++index) if (bytes_[index] != 0) return false;
        return bytes_[15] == 1;
    }
    constexpr bool is_unspecified() const {
        for (const auto byte : bytes_) if (byte != 0) return false;
        return true;
    }
    constexpr bool is_v4_mapped() const {
        for (std::size_t index = 0; index < 10; ++index) if (bytes_[index] != 0) return false;
        return bytes_[10] == 255 && bytes_[11] == 255;
    }
    static constexpr address_v6 loopback() { bytes_type bytes{}; bytes[15] = 1; return address_v6(bytes); }
    static constexpr address_v6 any() { return {}; }
    auto operator<=>(const address_v6&) const = default;
private:
    bytes_type bytes_{};
    std::uint32_t scope_ = 0;
};

class address {
public:
    address() = default;
    address(address_v4 value) : value_(value) {}
    address(address_v6 value) : value_(value) {}
    bool is_v4() const { return std::holds_alternative<address_v4>(value_); }
    bool is_v6() const { return std::holds_alternative<address_v6>(value_); }
    address_v4 to_v4() const { return std::get<address_v4>(value_); }
    address_v6 to_v6() const { return std::get<address_v6>(value_); }
    bool is_loopback() const { return std::visit([](const auto& value) { return value.is_loopback(); }, value_); }
    bool is_unspecified() const { return std::visit([](const auto& value) { return value.is_unspecified(); }, value_); }
    std::string to_string() const { return std::visit([](const auto& value) { return value.to_string(); }, value_); }
    auto operator<=>(const address&) const = default;
private:
    std::variant<address_v4, address_v6> value_;
};

address_v4 make_address_v4(std::string_view value, std::error_code& error);
address_v4 make_address_v4(std::string_view value);
address_v6 make_address_v6(std::string_view value, std::error_code& error);
address_v6 make_address_v6(std::string_view value);
address make_address(std::string_view value, std::error_code& error);
address make_address(std::string_view value);

} // namespace postplus::ip
