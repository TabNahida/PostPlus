#include <postplus/network.hpp>
namespace postplus {
NetworkExecutor::NetworkExecutor() : thread_([this] { io_.run(); }) {}
NetworkExecutor::~NetworkExecutor() { io_.stop(); thread_.join(); }
NetworkExecutor& network_executor() { static NetworkExecutor executor; return executor; }
WorkerPool::WorkerPool(std::size_t count) {
    try {
        for (std::size_t i = 0; i < count; ++i) threads_.emplace_back([this] {
            for (;;) {
                std::function<void()> work;
                {
                    std::unique_lock lock(mutex_);
                    ready_.wait(lock, [&] { return stopping_ || !work_.empty(); });
                    if (work_.empty()) return;
                    work = std::move(work_.front()); work_.pop_front();
                }
                work();
            }
        });
    } catch (...) { join(); throw; }
}
WorkerPool::~WorkerPool() { join(); }
void WorkerPool::post(std::function<void()> work) {
    { std::lock_guard lock(mutex_); if (stopping_) throw std::runtime_error("worker pool stopping"); work_.push_back(std::move(work)); }
    ready_.notify_one();
}
void WorkerPool::join() {
    { std::lock_guard lock(mutex_); stopping_ = true; }
    ready_.notify_all();
    for (auto& thread : threads_) if (thread.joinable()) thread.join();
}
}
