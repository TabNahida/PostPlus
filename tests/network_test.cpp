#include <postplus/core.hpp>
#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>

using namespace postplus;
using namespace std::chrono_literals;
namespace {
using Clock = std::chrono::steady_clock;
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Cancellation regressions must fail the test rather than strand the test runner.
class Watchdog {
public:
    Watchdog() : thread_([this] {
        std::unique_lock lock(mutex_);
        if (!ready_.wait_for(lock, 30s, [this] { return done_; })) {
            std::cerr << "FAIL network regression test did not finish within 30 seconds\n" << std::flush;
            std::_Exit(1);
        }
    }) {}
    ~Watchdog() {
        { std::lock_guard lock(mutex_); done_ = true; }
        ready_.notify_one();
        thread_.join();
    }
private:
    std::mutex mutex_;
    std::condition_variable ready_;
    bool done_ = false;
    std::thread thread_;
};

struct Pair {
    SocketListener listener;
    Connection client{10s}, peer{10s};
    explicit Pair(ip::address address = ip::address_v4::loopback()) : listener({address, 0}) {
        client.connect(listener.local_endpoint());
        listener.accept(peer, 2s);
    }
};

// The cleanup runs before future destruction, which otherwise waits indefinitely
// if an assertion fails while the worker still owns a pending network operation.
struct Pending {
    std::function<void()> cancel;
    std::future<void> result;
    template<class F, class C> Pending(F operation, C cleanup)
        : cancel(std::move(cleanup)), result(std::async(std::launch::async, std::move(operation))) {}
    ~Pending() {
        if (result.valid()) {
            try { cancel(); } catch (...) {}
            result.wait();
        }
    }
    void require_pending() {
        check(result.wait_for(50ms) == std::future_status::timeout,
              "operation unexpectedly completed before cancellation/input");
    }
    void require_ready() {
        check(result.wait_for(2s) == std::future_status::ready,
              "operation remained blocked after cancellation/input");
    }
};

// Hold the owning reactor before a poll is dispatched. Releasing the gate can
// stop the connection on that reactor before the queued poll arms its wait.
class ReactorGate {
public:
    explicit ReactorGate(Connection* stop_before_resume = nullptr) {
        auto entered = entered_.get_future();
        auto released = released_.get_future().share();
        network_executor().context().post([this, released, stop_before_resume] {
            entered_.set_value();
            released.wait();
            if (stop_before_resume) stop_before_resume->request_stop();
        });
        entered.get();
    }
    ~ReactorGate() {
        open();
        // The posted closure must leave before the promises are destroyed.
        network_executor().invoke([] {});
    }
    void open() {
        if (!opened_) { opened_ = true; released_.set_value(); }
    }
private:
    std::promise<void> entered_, released_;
    bool opened_ = false;
};

void require_cancelled(Pending& operation) {
    operation.require_ready();
    try { operation.result.get(); }
    catch (const NetworkTimeout&) {
        throw std::runtime_error("cancellation only completed through the ordinary operation timeout");
    }
    catch (const std::system_error& error) {
        check(error.code() == std::errc::operation_canceled, "wrong cancellation error");
        return;
    }
    catch (const std::runtime_error& error) {
        check(std::string_view(error.what()) == "service stopping", "wrong stopped connection error");
        return;
    }
    throw std::runtime_error("cancelled operation reported success");
}

void ipv6_loopback() {
    Pair pair(ip::address_v6::loopback());
    const auto local = pair.listener.local_endpoint();
    const auto remote = pair.client.peer_endpoint();
    const auto accepted = pair.peer.peer_endpoint();
    check(local.address().is_v6() && local.address().is_loopback() && local.port() != 0,
          "IPv6 listener did not retain its loopback address/ephemeral port");
    check(remote.address().is_v6() && remote.address().is_loopback() && remote.port() == local.port(),
          "IPv6 client peer endpoint lost address family/port");
    check(accepted.address().is_v6() && accepted.address().is_loopback() && accepted.port() != 0,
          "accepted IPv6 peer endpoint lost address family/port");
    const std::string binary("\0x\xff", 3);
    pair.client.write(binary);
    check(pair.peer.read(binary.size()) == binary, "IPv6 exact binary read failed");
    pair.peer.write("IPv6 ready\r\n");
    check(pair.client.line() == "IPv6 ready", "IPv6 response failed");
    std::cout << "PASS native IPv6 loopback listener, peer endpoints and bidirectional bytes\n";
}

void empty_connection_and_accept_retry() {
    Connection empty;
    auto disconnected = [](auto operation) {
        bool rejected = false;
        try { operation(); } catch (const std::runtime_error&) { rejected = true; }
        check(rejected, "unconnected operation was not rejected");
    };
    disconnected([&] { (void)empty.peer_endpoint(); });
    disconnected([&] { empty.write("x"); });
    disconnected([&] { (void)empty.read(1); });
    disconnected([&] { (void)empty.wait_readable(1s); });
    empty.request_stop();
    empty.request_stop();

    SocketListener listener({ip::address_v4::loopback(), 0});
    Connection accepted;
    for (int attempt = 0; attempt < 2; ++attempt) {
        bool expired = false;
        try { listener.accept(accepted, 20ms); } catch (const NetworkTimeout&) { expired = true; }
        check(expired, "idle accept did not expire");
    }
    Connection first, second;
    first.connect("localhost", listener.local_endpoint().port());
    listener.accept(accepted, 2s);
    const auto previous = accepted.peer_endpoint();
    check(first.peer_endpoint().port() == listener.local_endpoint().port(), "resolved peer has wrong port");
    first.write("first\r\n");
    check(accepted.line() == "first", "accept failed after idle polling timeout");
    second.connect(listener.local_endpoint());
    listener.accept(accepted, 2s);
    check(accepted.peer_endpoint().address().is_loopback() && accepted.peer_endpoint().port() != previous.port(),
          "reusing an accepted connection retained the old peer identity");
    second.write("second\r\n");
    check(accepted.line() == "second", "replacement accepted socket did not receive bytes");
    std::cout << "PASS empty connections are safe, timed-out accepts retry, and replacement sockets update peer identity\n";
}

void polling_preserves_transport() {
    Pair pair;
    for (int attempt = 0; attempt < 3; ++attempt)
        check(!pair.peer.wait_readable(20ms), "empty TCP connection was readable");
    pair.client.write("first\r\nsecond\r\n");
    check(pair.peer.wait_readable(2s), "TCP poll did not see input after repeated timeouts");
    check(pair.peer.line() == "first", "poll consumed application input");
    // TCP may split one write across reads, so accept either buffered or newly
    // readable bytes instead of assuming packet boundaries in the fixture.
    check(pair.peer.wait_readable(2s), "second line did not remain readable");
    check(pair.peer.line() == "second", "second line changed");
    pair.peer.write("still open\r\n");
    check(pair.client.line() == "still open", "poll timeout closed or poisoned the transport");
    std::cout << "PASS repeated TCP poll timeouts preserve subsequent reads, buffered input and writes\n";
}

void final_response_closes_without_worker_destruction() {
    Pair pair;
    pair.client.write("trailing input");
    Pending finishing([&] { pair.peer.write_and_close("complete response"); }, [&] { pair.peer.request_stop(); });
    check(pair.client.read(17) == "complete response", "final response was truncated by close");
    bool closed = false;
    try { (void)pair.client.read(1); } catch (const NetworkEof&) { closed = true; }
    check(closed, "final response did not signal EOF while its connection object remained alive");
    finishing.require_ready();
    finishing.result.get();
    std::cout << "PASS final plaintext response signals EOF before destruction with bounded trailing-input drain\n";
}

void queued_poll_timeout_and_stop() {
    for (const bool stopping : {false, true}) {
        Pair pair;
        ReactorGate gate(stopping ? &pair.peer : nullptr);
        std::promise<void> starting;
        auto started = starting.get_future();
        Pending polling([&] {
            starting.set_value();
            check(!pair.peer.wait_readable(stopping ? 10s : 20ms), "empty queued poll reported readable");
        }, [&] { gate.open(); pair.peer.request_stop(); });
        started.get();
        // The reactor is explicitly held, not merely assumed to be busy. The
        // expired case queues a short poll; the stop case keeps a long budget.
        check(polling.result.wait_for(100ms) == std::future_status::timeout,
              "poll completed while its owning reactor was held");
        gate.open();
        if (stopping) require_cancelled(polling);
        else {
            polling.require_ready();
            polling.result.get();
            pair.client.write("after queue timeout\r\n");
            check(pair.peer.line() == "after queue timeout", "queue expiry poisoned subsequent read");
            pair.peer.write("OK\r\n");
            check(pair.client.line() == "OK", "queue expiry poisoned subsequent write");
        }
    }
    std::cout << "PASS queued poll expiry returns false and stop before wait registration cancels promptly\n";
}

void buffer_complete_line(Pair& pair) {
    // A rejected bare LF leaves the complete CRLF-terminated bytes in the
    // buffer. Discarding that LF gives a known buffered line without assuming
    // that TCP delivers an entire write in one receive.
    pair.client.write("\nbuffered\r\n");
    bool rejected = false;
    try { (void)pair.peer.line(); } catch (const std::length_error&) { rejected = true; }
    check(rejected && pair.peer.read(1) == "\n", "could not prepare a complete buffered line");
}

void buffered_reads_obey_state() {
    for (const bool line : {false, true}) {
        Pair pair;
        buffer_complete_line(pair);
        check(pair.peer.wait_readable(0ms), "buffer fixture was not immediately readable");
        pair.peer.set_deadline(Clock::now() - 1ms);
        check(!pair.peer.wait_readable(0ms), "buffered readiness ignored an expired absolute deadline");
        bool expired = false;
        try { if (line) (void)pair.peer.line(); else (void)pair.peer.read(8); }
        catch (const NetworkTimeout&) { expired = true; }
        check(expired, "buffered read ignored an expired absolute deadline");
        pair.peer.set_deadline(std::nullopt);
        check(pair.peer.line() == "buffered", "expired buffered read consumed application data");

        buffer_complete_line(pair);
        pair.peer.request_stop();
        auto require_stopped = [](auto operation) {
            bool stopped = false;
            try { operation(); }
            catch (const std::runtime_error& error) { stopped = std::string_view(error.what()) == "service stopping"; }
            check(stopped, "buffered operation ignored request_stop");
        };
        require_stopped([&] { if (line) (void)pair.peer.line(); else (void)pair.peer.read(8); });
        require_stopped([&] { (void)pair.peer.wait_readable(0ms); });
    }
    std::cout << "PASS buffered line/read/readiness honor deadlines and stop without consuming expired data\n";
}

void absolute_deadline_with_fragments() {
    Pair pair;
    pair.client.write("x");
    pair.peer.set_deadline(Clock::now() + 500ms);
    Pending reader([&] { (void)pair.peer.read(1024 * 1024); }, [&] { pair.peer.request_stop(); });
    std::atomic<unsigned> fragments{0};
    std::atomic<bool> writer_stopping{false};
    std::exception_ptr writer_failure;
    Pending writer([&] {
        try {
            while (!writer_stopping.load()) {
                pair.client.write("x");
                ++fragments;
                std::this_thread::sleep_for(20ms);
            }
        } catch (...) { writer_failure = std::current_exception(); }
    }, [&] { writer_stopping.store(true); pair.client.request_stop(); });
    // The peer remains open and keeps sending. The read must expire because of
    // the absolute budget, not EOF or its much longer 10-second idle timeout.
    const bool completed = reader.result.wait_for(2s) == std::future_status::ready;
    writer.cancel();
    writer.require_ready();
    writer.result.get();
    check(completed, "small incoming fragments reset the absolute read deadline");
    bool expired = false;
    try { reader.result.get(); } catch (const NetworkTimeout&) { expired = true; }
    check(expired, "fragmented read did not report NetworkTimeout");
    check(fragments.load() >= 2, "fragment fixture did not send multiple small writes");
    // request_stop can cancel the final write during fixture teardown.
    if (writer_failure) {
        try { std::rethrow_exception(writer_failure); }
        catch (const std::system_error& error) {
            check(error.code() == std::errc::operation_canceled, "fragment writer failed before cancellation");
        }
        catch (const std::runtime_error& error) {
            check(std::string_view(error.what()) == "service stopping", "fragment writer failed before cancellation");
        }
    }
    std::cout << "PASS absolute read deadline survives continuous small incoming fragments\n";
}

void stop_pending_operations() {
    for (const bool poll : {false, true}) {
        Pair pair;
        Pending reader([&] {
            if (poll) (void)pair.peer.wait_readable(10s);
            else (void)pair.peer.read(1);
        }, [&] { pair.peer.request_stop(); });
        reader.require_pending();
        pair.peer.request_stop();
        require_cancelled(reader);
        pair.peer.request_stop(); // stopping an already stopped session is safe
    }
    SocketListener listener({ip::address_v4::loopback(), 0});
    Connection peer;
    Pending accepting([&] { listener.accept(peer, 10s); }, [&] { listener.close(); });
    accepting.require_pending();
    listener.close();
    require_cancelled(accepting);
    listener.close();
    std::cout << "PASS request_stop cancels pending read/poll and listener close cancels pending accept\n";
}

void independent_connections() {
    Pair slow, fast;
    Pending stalled([&] { (void)slow.peer.read(1); }, [&] { slow.peer.request_stop(); });
    stalled.require_pending();
    Pending responding([&] {
        check(fast.peer.line() == "ping", "independent request changed");
        fast.peer.write("pong\r\n");
    }, [&] { fast.peer.request_stop(); });
    fast.client.write("ping\r\n");
    check(fast.client.line() == "pong", "slow connection blocked an independent roundtrip");
    responding.require_ready();
    responding.result.get();
    check(stalled.result.wait_for(0ms) == std::future_status::timeout,
          "slow fixture stopped before independent connection completed");
    slow.peer.request_stop();
    require_cancelled(stalled);
    std::cout << "PASS an independent connection completes while another read stays pending\n";
}

void synchronous_deadline_check() {
    const auto callback_ran = std::make_shared<bool>(false);
    network_executor().invoke([callback_ran] {
        const auto limit = Clock::now() + 30ms;
        NetworkDeadline timer(network_executor().context(), limit, [callback_ran] { *callback_ran = true; });
        // Deliberately hold the reactor so its callback cannot run. Cached or
        // immediately-ready operations must still check the actual clock.
        std::this_thread::sleep_until(limit + 5ms);
        check(!*callback_ran, "deadline callback ran concurrently with its owning reactor");
        check(timer.expired(), "deadline depended solely on dispatching its callback");
        bool expired = false;
        try { timer.check(); } catch (const NetworkTimeout&) { expired = true; }
        check(expired, "synchronous reactor work escaped its absolute deadline");
    });
    // A new reactor operation also verifies destruction cancelled the old timer.
    network_executor().invoke([callback_ran] {
        check(!*callback_ran, "destroyed NetworkDeadline still dispatched its callback");
    });
    std::cout << "PASS NetworkDeadline checks wall clock before its callback can execute\n";
}
}

int main() {
    Watchdog watchdog;
    try {
        ipv6_loopback();
        empty_connection_and_accept_retry();
        polling_preserves_transport();
        final_response_closes_without_worker_destruction();
        queued_poll_timeout_and_stop();
        buffered_reads_obey_state();
        absolute_deadline_with_fragments();
        stop_pending_operations();
        independent_connections();
        synchronous_deadline_check();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
