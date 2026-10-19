#include <postplus/core.hpp>
#include <postplus/forwarding.hpp>
#include <postplus/process.hpp>
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
    const auto now=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if(job.contains("created_at") && now-job.at("created_at").get<std::int64_t>()>=config.number("delivery_max_age_seconds",432000)) {
        require_ok(rpc(config,"storage",{{"op","queue_reject"},{"id",id},{"status","failed"},{"error","delivery retry age exceeded"}}));
        log("delivery","delivery expired for queue item "+id,"warn");
        return;
    }
    const auto scan = require_ok(rpc(config,"filter",{{"op","scan"},{"raw",raw},{"inbound",job.value("inbound",job.value("sent_username",std::string{}).empty())},
        {"sender",job.at("sender")},{"recipient",recipient},{"peer_ip",job.value("peer_ip",std::string{})},{"helo",job.value("helo",std::string{})}}));
    const auto action=scan.value("action",std::string("reject"));
    if (action != "accept" && action != "spam") {
        // Keep rejected mail durable and visible to administrators; never auto-release it.
        require_ok(rpc(config,"storage",{{"op","queue_reject"},{"id",id},{"error",scan.value("reason","policy rejection")}}));
        log("delivery", "quarantined queue item " + id, "warn");
        return;
    }
    std::string delivery_scope="remote_mta";
    if (job.value("local_route",false) || config.local_address(recipient)) {
        const auto route = resolve_local_recipient(config,recipient,id);
        if (!route.value("exists",false)) throw std::runtime_error("local destination mailbox no longer exists");
        Json request{{"op","deliver"},{"username",route.at("destination")},{"raw",raw},{"delivery_id",id}};
        request["folder"]=action=="spam"?"Junk":"INBOX";
        request["filter_action"]=action; request["spam_score"]=scan.value("spam_score",Json(0)); request["spam_reasons"]=scan.value("spam_reasons",Json::array());
        if (job.contains("submission_id")) request["submission_id"] = job.at("submission_id");
        require_ok(rpc(config,"storage",request));
        delivery_scope="local_mailbox";
    } else {
        const auto sent=rpc(config,"transfer",{{"op","send"},{"sender",job.at("sender")},{"recipient",recipient},{"raw",raw}});
        if(!sent.value("ok",false) && sent.value("permanent",false)) {
            require_ok(rpc(config,"storage",{{"op","queue_reject"},{"id",id},{"error",sent.value("error","permanent delivery failure")}}));
            log("delivery","permanent delivery failure for queue item "+id,"warn");
            return;
        }
        require_ok(sent);
    }
    require_ok(rpc(config,"storage",{{"op","queue_finish"},{"id",id},{"delivery_scope",delivery_scope}}));
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
        while (!stopping && !process_stop_requested()) {
            try {
                const auto batch = require_ok(rpc(config,"storage",{{"op","queue_list"},{"limit",1}}));
                for (const auto& job : batch.at("jobs")) {
                    if (stopping || process_stop_requested()) break;
                    try { process(config,job); }
                    catch (const std::exception& error) {
                        const auto id = job.at("id").get<std::string>();
                        const int attempts = std::clamp(job.value("attempts",0),0,10);
                        auto reason=std::string(error.what()).substr(0,1024);
                        for(auto& c:reason) if(static_cast<unsigned char>(c)<32)c=' ';
                        require_ok(rpc(config,"storage",{{"op","queue_retry"},{"id",id},{"delay",std::min(3600, 5 * (1 << attempts))},{"error",reason}}));
                        log("delivery","deferred queue item " + id, "warn");
                    }
                }
                if (!batch.at("jobs").empty()) continue;
            } catch (const std::exception&) { log("delivery","queue unavailable; retrying", "warn"); }
            for (int i=0; i<10 && !stopping && !process_stop_requested(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}
