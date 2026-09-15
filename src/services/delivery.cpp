#include <postplus/core.hpp>
#include <algorithm>
#include <csignal>
#include <fstream>
#include <thread>

using namespace postplus;
namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
Json require_ok(Json reply) {
    if (!reply.value("ok",false)) throw std::runtime_error(reply.value("error","operation failed"));
    return reply;
}
void process(const Config& config, const Json& job) {
    const auto id = job.at("id").get<std::string>();
    const auto recipient = job.at("recipient").get<std::string>();
    const auto raw = job.at("raw").get<std::string>();
    const auto scan = require_ok(rpc(config,"filter",{{"op","scan"},{"raw",raw}}));
    if (scan.value("action", "reject") != "accept") {
        // Keep rejected mail durable and visible to administrators; never auto-release it.
        require_ok(rpc(config,"storage",{{"op","queue_reject"},{"id",id},{"error",scan.value("reason","policy rejection")}}));
        log("delivery", "quarantined queue item " + id);
        return;
    }
    const auto local_domain = lower(config.text("domain","localhost"));
    if (recipient.substr(recipient.find('@') + 1) == local_domain) {
        const auto exists = require_ok(rpc(config,"auth",{{"op","exists"},{"username",recipient}}));
        if (!exists.value("exists",false)) throw std::runtime_error("local recipient no longer exists");
        require_ok(rpc(config,"storage",{{"op","deliver"},{"username",recipient},{"raw",raw},{"delivery_id",id}}));
    } else {
        require_ok(rpc(config,"transfer",{{"op","send"},{"sender",job.at("sender")},{"recipient",recipient},{"raw",raw}}));
    }
    require_ok(rpc(config,"storage",{{"op","queue_finish"},{"id",id}}));
    log("delivery", "delivered queue item " + id);
}
}
int main(int argc, char** argv) {
    return service_main("delivery",argc,argv,[](const Config& config) {
        std::signal(SIGINT,stop); std::signal(SIGTERM,stop);
        // Exclusive OS lock released automatically on crash; prevents two consumers.
        std::filesystem::create_directories(config.text("data_dir"));
        asio::io_context lock_io;
        tcp::acceptor worker_lock(lock_io);
        worker_lock.open(tcp::v4());
        const int lock_port = config.number("delivery_lock_port",18085);
        if (lock_port < 1 || lock_port > 65535) throw std::invalid_argument("invalid delivery_lock_port");
        worker_lock.bind({asio::ip::address_v4::loopback(),static_cast<unsigned short>(lock_port)});
        worker_lock.listen(1);
        log("delivery","queue worker started");
        while (!stopping) {
            try {
                const auto batch = require_ok(rpc(config,"storage",{{"op","queue_list"},{"limit",1}}));
                for (const auto& job : batch.at("jobs")) {
                    if (stopping) break;
                    try { process(config,job); }
                    catch (const std::exception&) {
                        const auto id = job.at("id").get<std::string>();
                        const int attempts = std::clamp(job.value("attempts",0),0,10);
                        require_ok(rpc(config,"storage",{{"op","queue_retry"},{"id",id},{"delay",std::min(3600, 5 * (1 << attempts))},{"error","temporary delivery failure; check service health and configuration"}}));
                        log("delivery","deferred queue item " + id);
                    }
                }
                if (!batch.at("jobs").empty()) continue;
            } catch (const std::exception&) { log("delivery","queue unavailable; retrying"); }
            for (int i=0; i<10 && !stopping; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}
