#pragma once
#include <postplus/ip.hpp>
#include <pace/io_context.hpp>
#include <pace/tcp.hpp>
#include <condition_variable>
#include <deque>
#include <future>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

namespace postplus {
struct tcp {
    class endpoint {
    public:
        endpoint() = default;
        endpoint(ip::address value, unsigned short port) : address_(std::move(value)), port_(port) {}
        const ip::address& address() const { return address_; }
        unsigned short port() const { return port_; }
        pace::tcp::endpoint native() const {
            auto address = address_.to_string();
            if (const auto zone = address.find('%'); zone != std::string::npos) address.resize(zone);
            return {address, port_, address_.is_v6() ? pace::address_family::ipv6 : pace::address_family::ipv4,
                    address_.is_v6() ? static_cast<std::uint32_t>(address_.to_v6().scope_id()) : 0};
        }
    private:
        ip::address address_;
        unsigned short port_ = 0;
    };
};

// Application handlers are synchronous; only this bounded bridge executes their
// network operations on PACE's context-affine reactor. No nested event loops.
class NetworkExecutor {
public:
    NetworkExecutor();
    ~NetworkExecutor();
    NetworkExecutor(const NetworkExecutor&) = delete;
    NetworkExecutor& operator=(const NetworkExecutor&) = delete;
    pace::io_context& context() { return io_; }
    template<class T> T run(pace::task<T> operation) {
        if (pace::io_context::current() == &io_) throw std::logic_error("blocking call on network reactor");
        std::promise<T> promise;
        auto result = promise.get_future();
        io_.spawn(complete(std::move(operation), std::move(promise)));
        return result.get();
    }
    template<class F> auto invoke(F function) -> std::invoke_result_t<F> {
        using T = std::invoke_result_t<F>;
        if (pace::io_context::current() == &io_) return function();
        auto promise = std::make_shared<std::promise<T>>();
        auto result = promise->get_future();
        io_.post([promise, function = std::move(function)]() mutable {
            try {
                if constexpr (std::is_void_v<T>) { function(); promise->set_value(); }
                else promise->set_value(function());
            } catch (...) { promise->set_exception(std::current_exception()); }
        });
        return result.get();
    }
private:
    template<class T> static pace::task<void> complete(pace::task<T> task, std::promise<T> promise) {
        try {
            if constexpr (std::is_void_v<T>) { co_await std::move(task); promise.set_value(); }
            else promise.set_value(co_await std::move(task));
        } catch (...) { promise.set_exception(std::current_exception()); }
    }
    pace::io_context io_;
    std::thread thread_;
};
NetworkExecutor& network_executor();

class NetworkTimeout : public std::system_error {
public:
    NetworkTimeout() : std::system_error(std::make_error_code(std::errc::timed_out), "connection timed out") {}
};
class NetworkEof : public std::runtime_error {
public:
    NetworkEof() : std::runtime_error("connection closed") {}
};
class NetworkDnsError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class NetworkDeadline {
public:
    NetworkDeadline(pace::io_context& io, std::chrono::steady_clock::time_point deadline,
                    std::function<void()> cancel)
        : deadline_(deadline), timer_(io.call_at(deadline, [this, cancel = std::move(cancel)] { expired_ = true; cancel(); })) {
        if (deadline <= std::chrono::steady_clock::now()) throw NetworkTimeout();
    }
    void check() const { if (expired()) throw NetworkTimeout(); }
    bool expired() const { return expired_ || std::chrono::steady_clock::now() >= deadline_; }
private:
    std::chrono::steady_clock::time_point deadline_;
    bool expired_ = false;
    pace::io_context::timer_handle timer_;
};

// Bounded thread count for disk/database and existing synchronous mail handlers.
class WorkerPool {
public:
    explicit WorkerPool(std::size_t count);
    ~WorkerPool();
    void post(std::function<void()> work);
    void join();
private:
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<std::function<void()>> work_;
    std::vector<std::thread> threads_;
    bool stopping_ = false;
};
}
