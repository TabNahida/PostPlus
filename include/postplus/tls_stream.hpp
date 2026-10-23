#pragma once
#include <pace/tcp.hpp>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace postplus {
struct Config;

// Borrowed PACE transport; callers keep it alive and serialize operations.
// Cancellation ends the current wait without closing the connection, allowing
// IMAP IDLE polling to be followed by a notification write on the same socket.
class TlsStream {
public:
    explicit TlsStream(pace::tcp::stream& transport);
    ~TlsStream();
    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;
    TlsStream(TlsStream&&) = delete;
    TlsStream& operator=(TlsStream&&) = delete;
    // Preparation does filesystem/crypto work; call while idle from a worker.
    // Only handshake/read/write/wait execute on the owning PACE reactor.
    void configure_server(const Config& config);
    void configure_client(const std::string& hostname);
    // Supervisor loopback readiness only: preserve the exact configured leaf.
    void configure_pinned(const std::string& certificate_file);
    pace::task<void> handshake();
    pace::task<std::size_t> read_some(std::span<char> bytes);
    pace::task<void> write_all(std::string_view bytes);
    pace::task<void> wait_readable();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}

