#include <postplus/core.hpp>
#include <postplus/process.hpp>
#include <postplus/tls_stream.hpp>
#include <pace/dns.hpp>
#include <atomic>
#include <algorithm>
#include <csignal>

namespace postplus {
namespace {
tcp::endpoint endpoint_value(const pace::tcp::endpoint& value) {
    auto address = ip::make_address(value.address);
    if (address.is_v6()) { auto v6 = address.to_v6(); v6.scope_id(value.scope_id); address = v6; }
    return {address, value.port};
}
}
struct Connection::Impl {
    NetworkExecutor& executor = network_executor();
    std::unique_ptr<pace::tcp::stream> socket;
    std::unique_ptr<TlsStream> tls;
    pace::dns::resolver* resolver = nullptr; // Only accessed on the reactor.
    std::chrono::seconds timeout;
    std::optional<std::chrono::steady_clock::time_point> operation_deadline, deadline;
    std::atomic<bool> stopping{false};
    std::string buffer;
    explicit Impl(std::chrono::seconds value) : timeout(value) {
        executor.invoke([&] { socket = std::make_unique<pace::tcp::stream>(executor.context()); });
    }
    ~Impl() { executor.invoke([&] { tls.reset(); socket.reset(); }); }
    auto expires() const {
        auto result = std::chrono::steady_clock::now() + timeout;
        if (operation_deadline) result = std::min(result, *operation_deadline);
        if (deadline) result = std::min(result, *deadline);
        return result;
    }
    void cancel() {
        if (resolver) resolver->cancel();
        executor.context().cancel(socket->native_handle());
    }
    template<class T> pace::task<T> bounded(pace::task<T> operation) {
        if (stopping.load()) throw std::runtime_error("service stopping");
        NetworkDeadline timer(executor.context(), expires(), [this] { cancel(); });
        try {
            if constexpr (std::is_void_v<T>) {
                co_await std::move(operation); timer.check();
                if (stopping.load()) throw std::runtime_error("service stopping");
                co_return;
            } else {
                auto result = co_await std::move(operation); timer.check();
                if (stopping.load()) throw std::runtime_error("service stopping");
                co_return result;
            }
        } catch (...) { timer.check(); throw; }
    }
    pace::task<void> connect_endpoint(tcp::endpoint endpoint) {
        co_await socket->connect(endpoint.native());
        socket->set_no_delay();
    }
    pace::task<void> connect_host(std::string host, int port) {
        if (port < 1 || port > 65535) throw std::invalid_argument("invalid port");
        std::error_code error;
        auto numeric = ip::make_address(host, error);
        if (!error) { co_await connect_endpoint({numeric, static_cast<unsigned short>(port)}); co_return; }
        pace::dns::resolver lookup(executor.context(), {
            .timeout = std::max(std::chrono::milliseconds(1), std::chrono::duration_cast<std::chrono::milliseconds>(expires() - std::chrono::steady_clock::now()))});
        resolver = &lookup;
        struct Reset { Impl& value; ~Reset() { value.resolver = nullptr; } } reset{*this};
        pace::dns::result addresses;
        try { addresses = co_await lookup.resolve(host); }
        catch (const std::system_error& failure) {
            if (failure.code() == std::errc::timed_out || failure.code() == std::errc::operation_canceled) throw;
            throw NetworkDnsError("hostname resolution failed");
        }
        if (addresses.addresses.empty()) throw NetworkDnsError("hostname has no addresses");
        std::exception_ptr failure;
        for (const auto& address : addresses.addresses) {
            if (stopping.load()) throw std::runtime_error("service stopping");
            if (expires() <= std::chrono::steady_clock::now()) throw NetworkTimeout();
            socket = std::make_unique<pace::tcp::stream>(executor.context());
            try {
                co_await connect_endpoint({ip::make_address(address.text), static_cast<unsigned short>(port)});
                co_return;
            } catch (...) { failure = std::current_exception(); }
        }
        std::rethrow_exception(failure);
    }
    pace::task<std::string> receive_task(std::size_t size) {
        std::string bytes(size, '\0');
        const auto count = tls ? co_await tls->read_some(bytes) : co_await socket->read_some(bytes);
        if (count == 0) throw NetworkEof();
        bytes.resize(count);
        co_return bytes;
    }
    std::string receive(std::size_t size) { return executor.run(bounded(receive_task(size))); }
    pace::task<void> write_task(std::string_view bytes) {
        if (tls) co_await tls->write_all(bytes);
        else co_await socket->write_all(bytes);
    }
    void check_read_state() const {
        if (stopping.load()) throw std::runtime_error("service stopping");
        if (expires() <= std::chrono::steady_clock::now()) throw NetworkTimeout();
    }
    pace::task<bool> poll(std::chrono::steady_clock::time_point until) {
        // Stop may be posted before this queued task has armed its socket wait.
        if (stopping.load()) throw std::runtime_error("service stopping");
        try {
            NetworkDeadline timer(executor.context(), until, [this] { cancel(); });
            try {
                if (tls) co_await tls->wait_readable();
                else co_await executor.context().wait_readable(socket->native_handle());
            } catch (...) { if (!timer.expired()) throw; }
            if (stopping.load()) throw std::runtime_error("service stopping");
            co_return !timer.expired();
        } catch (const NetworkTimeout&) {
            // Queue delay, including the constructor's boundary race, is an
            // ordinary polling timeout and must leave the transport usable.
            if (stopping.load()) throw std::runtime_error("service stopping");
            co_return false;
        }
    }
};
Connection::Connection(std::chrono::seconds timeout) : impl_(std::make_unique<Impl>(timeout)) {}
Connection::~Connection() = default;
tcp::endpoint Connection::peer_endpoint() const {
    return impl_->executor.invoke([&] { return endpoint_value(impl_->socket->remote_endpoint()); });
}
bool Connection::encrypted() const { return static_cast<bool>(impl_->tls); }
void Connection::set_deadline(std::optional<std::chrono::steady_clock::time_point> value) { impl_->deadline = value; }
void Connection::request_stop() {
    impl_->stopping.store(true);
    impl_->executor.invoke([&] { impl_->cancel(); });
}
void Connection::connect(const std::string& host, int port) {
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& value; ~Reset() { value.operation_deadline.reset(); } } reset{*impl_};
    impl_->executor.run(impl_->bounded(impl_->connect_host(host, port)));
}
void Connection::connect(const tcp::endpoint& endpoint) { impl_->executor.run(impl_->bounded(impl_->connect_endpoint(endpoint))); }
std::string Connection::line(std::size_t limit) {
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& value; ~Reset() { value.operation_deadline.reset(); } } reset{*impl_};
    for (;;) {
        impl_->check_read_state();
        const auto end = impl_->buffer.find("\r\n");
        if (end != std::string::npos) {
            if (end > limit || impl_->buffer.find('\n') < end) throw std::length_error("invalid or oversized line");
            auto result = impl_->buffer.substr(0, end); impl_->buffer.erase(0, end + 2); return result;
        }
        if (impl_->buffer.size() >= limit + 2) throw std::length_error("line too long");
        impl_->buffer += impl_->receive(std::min<std::size_t>(4096, limit + 2 - impl_->buffer.size()));
    }
}
std::string Connection::read(std::size_t count) {
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& value; ~Reset() { value.operation_deadline.reset(); } } reset{*impl_};
    impl_->check_read_state();
    std::string result = impl_->buffer.substr(0, count); impl_->buffer.erase(0, result.size());
    while (result.size() < count) result += impl_->receive(std::min<std::size_t>(65536, count - result.size()));
    impl_->check_read_state();
    return result;
}
bool Connection::wait_readable(std::chrono::milliseconds timeout) {
    if (impl_->stopping.load()) throw std::runtime_error("service stopping");
    if (impl_->deadline && *impl_->deadline <= std::chrono::steady_clock::now()) return false;
    if (!impl_->buffer.empty()) return true;
    auto until = std::chrono::steady_clock::now() + timeout;
    if (impl_->deadline) until = std::min(until, *impl_->deadline);
    if (until <= std::chrono::steady_clock::now()) return false;
    return impl_->executor.run(impl_->poll(until));
}
void Connection::write(std::string_view bytes) { impl_->executor.run(impl_->bounded(impl_->write_task(bytes))); }
void Connection::start_tls_server(const Config& config) {
    if (encrypted() || !impl_->buffer.empty()) throw std::runtime_error("invalid TLS transition");
    if (impl_->stopping.load()) throw std::runtime_error("service stopping");
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& value; ~Reset() { value.operation_deadline.reset(); } } reset{*impl_};
    // Certificate I/O and SSL configuration run on this caller, never the shared
    // network reactor. The preparation time consumes the handshake budget.
    if (impl_->expires() <= std::chrono::steady_clock::now()) throw NetworkTimeout();
    auto prepared = std::make_unique<TlsStream>(*impl_->socket);
    prepared->configure_server(config);
    impl_->executor.invoke([&] { impl_->tls = std::move(prepared); });
    impl_->executor.run(impl_->bounded(impl_->tls->handshake()));
}
void Connection::start_tls_client(const std::string& hostname) {
    if (encrypted() || !impl_->buffer.empty()) throw std::runtime_error("invalid TLS transition");
    if (impl_->stopping.load()) throw std::runtime_error("service stopping");
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& value; ~Reset() { value.operation_deadline.reset(); } } reset{*impl_};
    if (impl_->expires() <= std::chrono::steady_clock::now()) throw NetworkTimeout();
    auto prepared = std::make_unique<TlsStream>(*impl_->socket);
    prepared->configure_client(hostname);
    impl_->executor.invoke([&] { impl_->tls = std::move(prepared); });
    impl_->executor.run(impl_->bounded(impl_->tls->handshake()));
}
void Connection::start_tls_pinned(const std::string& certificate) {
    if (encrypted() || !impl_->buffer.empty()) throw std::runtime_error("invalid TLS transition");
    if (impl_->stopping.load()) throw std::runtime_error("service stopping");
    impl_->operation_deadline = std::chrono::steady_clock::now() + impl_->timeout;
    struct Reset { Impl& value; ~Reset() { value.operation_deadline.reset(); } } reset{*impl_};
    if (impl_->expires() <= std::chrono::steady_clock::now()) throw NetworkTimeout();
    auto prepared = std::make_unique<TlsStream>(*impl_->socket);
    prepared->configure_pinned(certificate);
    impl_->executor.invoke([&] { impl_->tls = std::move(prepared); });
    impl_->executor.run(impl_->bounded(impl_->tls->handshake()));
}

struct SocketListener::Impl {
    NetworkExecutor& executor = network_executor();
    std::unique_ptr<pace::tcp::listener> listener;
    pace::task<void> accept(Connection& connection, std::chrono::milliseconds timeout) {
        NetworkDeadline timer(executor.context(), std::chrono::steady_clock::now() + timeout,
                              [&] { executor.context().cancel(listener->native_handle()); });
        try {
            // A completed accept wins a race with its polling timeout. Dropping
            // an already accepted socket here resets a legitimate new client.
            auto socket = co_await listener->accept();
            connection.impl_->tls.reset();
            connection.impl_->socket = std::make_unique<pace::tcp::stream>(std::move(socket));
            connection.impl_->socket->set_no_delay();
        } catch (...) { timer.check(); throw; }
    }
};
SocketListener::SocketListener(const tcp::endpoint& endpoint) : impl_(std::make_unique<Impl>()) {
    impl_->executor.invoke([&] { impl_->listener = std::make_unique<pace::tcp::listener>(
        impl_->executor.context(), endpoint.native(), pace::tcp::listen_options{.ipv6_only = !endpoint.address().is_v6()}); });
}
SocketListener::~SocketListener() { impl_->executor.invoke([&] { impl_->listener.reset(); }); }
tcp::endpoint SocketListener::local_endpoint() const {
    return impl_->executor.invoke([&] { return endpoint_value(impl_->listener->local_endpoint()); });
}
void SocketListener::accept(Connection& connection, std::chrono::milliseconds timeout) { impl_->executor.run(impl_->accept(connection, timeout)); }
void SocketListener::close() { impl_->executor.invoke([&] { impl_->listener->close(); }); }

namespace {
std::atomic<std::sig_atomic_t> interrupted{0};
static_assert(decltype(interrupted)::is_always_lock_free);
void stop_signal(int) { interrupted.store(1, std::memory_order_relaxed); }
void serve_listeners(const Config& config, const std::string& service, const std::vector<TcpListener>& listeners,
                     ListenerSession handler, bool internal, std::function<bool()> stop_requested, bool check_ip_bans) {
    const auto address = ip::make_address(internal ? "127.0.0.1" : config.text(service == "admin" ? "admin_bind" : "bind", "127.0.0.1"));
    std::vector<std::unique_ptr<SocketListener>> acceptors;
    for (const auto& listener : listeners) acceptors.push_back(std::make_unique<SocketListener>(tcp::endpoint{address, static_cast<unsigned short>(listener.port)}));
    const auto maximum = static_cast<std::size_t>(std::max(1, config.number("max_connections", 32)));
    WorkerPool workers(maximum);
    std::mutex mutex;
    std::vector<std::weak_ptr<Connection>> connections;
    interrupted.store(0, std::memory_order_relaxed);
    const auto old_int = std::signal(SIGINT, stop_signal), old_term = std::signal(SIGTERM, stop_signal);
    struct Restore { decltype(old_int) a, b; ~Restore() { std::signal(SIGINT, a); std::signal(SIGTERM, b); } } restore{old_int, old_term};
    std::atomic<bool> stopping{false};
    std::atomic<bool> listener_failed{false};
    std::vector<std::thread> accept_threads;
    // Also stop and join already-created listeners if another thread cannot start.
    struct JoinAcceptors {
        std::atomic<bool>& stopping;
        std::vector<std::unique_ptr<SocketListener>>& acceptors;
        std::vector<std::thread>& threads;
        ~JoinAcceptors() {
            stopping.store(true);
            for (auto& acceptor : acceptors) { try { acceptor->close(); } catch (...) {} }
            for (auto& thread : threads) if (thread.joinable()) thread.join();
        }
    } join_acceptors{stopping, acceptors, accept_threads};
    for (std::size_t index = 0; index < listeners.size(); ++index) {
        accept_threads.emplace_back([&, index] {
            try { while (!stopping.load()) {
                auto connection = std::make_shared<Connection>(std::chrono::seconds(config.number("timeout_seconds", 30)));
                try { acceptors[index]->accept(*connection, std::chrono::milliseconds(100)); }
                catch (const NetworkTimeout&) { continue; }
                catch (const std::exception&) {
                    if (!stopping.load()) { listener_failed.store(true); log(service, "listener stopped after I/O error", "error"); }
                    break;
                }
                {
                    std::lock_guard lock(mutex);
                    std::erase_if(connections, [](const auto& weak) { return weak.expired(); });
                    if (connections.size() >= maximum) continue;
                    connections.push_back(connection);
                }
                workers.post([&, connection, index] {
                    try {
                        bool allowed = true;
                        if (!internal && check_ip_bans) {
                            const auto peer = connection->peer_endpoint().address().to_string(); allowed = false;
                            try {
                                const auto result = rpc(config, "auth", {{"op", "security_check"}, {"peer_ip", peer},
                                    {"protocol", service == "web" ? "webmail" : service}}, std::chrono::steady_clock::now() + std::chrono::seconds(2));
                                allowed = result.at("ok").get<bool>();
                                if (!allowed) log(service, "connection rejected ip=" + peer + " reason=" +
                                    (result.value("code", "") == "ip_banned" ? "ip_banned" : "security_check_unavailable"), "warn");
                            } catch (const std::exception&) { log(service, "connection rejected ip=" + peer + " reason=security_check_unavailable", "warn"); }
                        }
                        if (allowed) {
                            if (listeners[index].implicit_tls) connection->start_tls_server(config);
                            handler(*connection, listeners[index]);
                        }
                    } catch (const std::exception&) { log(service, "session closed after I/O or protocol error", "debug"); }
                });
            } } catch (const std::exception&) {
                listener_failed.store(true);
                log(service, "listener stopped after resource error", "error");
            }
        });
        log(service, (listeners[index].name == service ? "" : listeners[index].name + " ") + "listening on " + address.to_string() + ":" + std::to_string(listeners[index].port));
    }
    bool cancel_sessions = false;
    for (;;) {
        if (interrupted.load(std::memory_order_relaxed) || process_stop_requested() || listener_failed.load()) { cancel_sessions = true; break; }
        if (stop_requested && stop_requested()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    stopping.store(true);
    for (auto& acceptor : acceptors) acceptor->close();
    for (auto& thread : accept_threads) thread.join();
    if (cancel_sessions) {
        std::lock_guard lock(mutex);
        for (auto& weak : connections) if (auto connection = weak.lock()) connection->request_stop();
    }
    workers.join();
    if (listener_failed.load()) throw std::runtime_error("listener stopped after I/O error");
}
}
void serve_tcp(const Config& config, const std::string& service, Session handler, bool internal, std::function<bool()> stop_requested, bool check_ip_bans) {
    serve_listeners(config, service, {{service, config.port(service), false}},
        [handler=std::move(handler)](Connection& connection, const TcpListener&) { handler(connection); }, internal, std::move(stop_requested), check_ip_bans);
}
void serve_tcp_listeners(const Config& config, const std::string& service, ListenerSession handler, std::function<bool()> stop_requested) {
    serve_listeners(config, service, config.listeners(service), std::move(handler), false, std::move(stop_requested), true);
}
}
