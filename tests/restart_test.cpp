#include <postplus/maintenance.hpp>
#include <postplus/restart.hpp>
#include <atomic>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <mutex>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace postplus;
namespace {
namespace fs = std::filesystem;
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template<class F> void rejects(int status, F operation) {
    try { operation(); } catch (const MaintenanceError& error) { check(error.status == status, "unexpected restart error status"); return; }
    throw std::runtime_error("restart operation unexpectedly accepted");
}
void environment(const char* name, const std::string& value) {
#ifdef _WIN32
    check(_putenv_s(name, value.c_str()) == 0, "cannot set test environment");
#else
    check(value.empty() ? unsetenv(name) == 0 : setenv(name, value.c_str(), 1) == 0, "cannot set test environment");
#endif
}
void save(const fs::path& path, const Json& values) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << values.dump(2);
    check(output.good(), "cannot save test config");
}
void plan(const Config& current, const std::string& key, Json value, std::vector<std::string> expected) {
    auto next = current;
    next.values[key] = std::move(value);
    check(restart_plan(current, next) == expected, "incorrect policy restart scope");
}
#ifdef _WIN32
struct TestHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~TestHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
#endif
void concurrent_state_reads(SupervisorControl& control, const Config& initial,
                            const Config& applied, const RestartRequest& request) {
    auto quiet = applied;
    quiet.values["log_level"] = "error";
    configure_logging(quiet, "postplus");
    const auto state_directory = fs::path(applied.text("data_dir")) / ".restart-state";
#ifdef _WIN32
    // A replacement handle has DELETE access. Readers must allow it even
    // when it is opened first, rather than depending on thread timing.
    {
        TestHandle latest, running;
        const auto share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        latest.value = CreateFileW((state_directory / "latest.json").c_str(), DELETE, share,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        running.value = CreateFileW((state_directory / "applied.json").c_str(), DELETE, share,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        check(latest.value != INVALID_HANDLE_VALUE && running.value != INVALID_HANDLE_VALUE,
              "cannot establish replacement handle regression");
        check(supervisor_restart_status(initial).at("state") == "complete", "reader refused replacement handle");
        check(supervisor_running_config(initial)->values == applied.values, "running reader refused replacement handle");
    }
    // A short-lived legacy reader or file scanner can still omit delete
    // sharing. Publication should wait briefly and retain the complete file.
    {
        TestHandle blocker;
        blocker.value = CreateFileW((state_directory / "latest.json").c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        check(blocker.value != INVALID_HANDLE_VALUE, "cannot establish transient publication conflict");
        std::atomic<bool> started = false;
        std::exception_ptr failure;
        std::jthread writer([&] {
            started.store(true);
            try { control.restart_running(request); } catch (...) { failure = std::current_exception(); }
        });
        while (!started.load()) std::this_thread::yield();
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        CloseHandle(blocker.value); blocker.value = INVALID_HANDLE_VALUE;
        writer.join();
        if (failure) std::rethrow_exception(failure);
        control.restart_complete(request, applied);
    }
#endif
    auto first = applied, second = applied;
    first.values["blocked_terms"] = Json::array({std::string(32768, 'A')});
    second.values["blocked_terms"] = Json::array({std::string(32768, 'B')});
    std::atomic<bool> stop = false;
    std::atomic<unsigned> started = 0, samples = 0;
    std::mutex failure_mutex;
    std::exception_ptr failure;
    auto record_failure = [&] {
        std::lock_guard lock(failure_mutex);
        if (!failure) failure = std::current_exception();
        stop.store(true);
    };
    std::vector<std::jthread> readers;
    for (unsigned i = 0; i < 4; ++i) readers.emplace_back([&] {
        ++started;
        try {
            while (!stop.load()) {
                check(supervisor_restart_available(initial), "publication hid the ready supervisor");
                const auto state = supervisor_restart_status(initial, request.job_id);
                check(state.at("state") == "running" || state.at("state") == "complete", "reader saw a torn job state");
                const auto running = supervisor_running_config(initial);
                check(running && (running->values == applied.values || running->values == first.values ||
                    running->values == second.values), "reader saw a partial applied configuration");
                ++samples;
            }
        } catch (...) { record_failure(); }
    });
    while (started.load() != readers.size()) std::this_thread::yield();
    try {
        for (unsigned i = 0; i < 64 && !stop.load(); ++i) {
            control.restart_running(request);
            control.restart_complete(request, i % 2 ? first : second);
        }
        control.restart_complete(request, applied);
    } catch (...) { record_failure(); }
    stop.store(true);
    for (auto& reader : readers) reader.join();
    if (failure) std::rethrow_exception(failure);
    check(samples.load() > 0, "concurrent state regression did not read any publications");

    const auto latest = state_directory / "latest.json";
    Json saved_state;
    { std::ifstream input(latest, std::ios::binary); saved_state = Json::parse(input); }
    save(latest, {{"padding", std::string(1024 * 1024, 'x')}});
    rejects(503, [&] { supervisor_restart_status(initial); });
    save(latest, saved_state);
    const auto saved_path = state_directory / "latest.saved";
    fs::rename(latest, saved_path);
    std::error_code link_error;
    fs::create_symlink(saved_path, latest, link_error);
    if (!link_error) {
        bool refused = false;
        try { supervisor_restart_status(initial); } catch (const std::exception&) { refused = true; }
        check(refused, "linked supervisor state was accepted");
        fs::remove(latest);
    }
    fs::rename(saved_path, latest);
    configure_logging(applied, "postplus");
}
}
int main() {
    try {
        Config base;
        base.values = {{"domain", "example.test"}};
        check(restart_plan(base, base).empty(), "no-op config restarted services");
        plan(base, "blocked_terms", Json::array({"blocked"}), {"filter"});
        plan(base, "smarthost_port", 2525, {"transfer"});
        plan(base, "smarthost_timeout_seconds", 40, {"transfer", "delivery"});
        plan(base, "direct_timeout_seconds", 150, {"transfer", "delivery"});
        plan(base, "web_session_seconds", 120, {"web", "admin"});
        plan(base, "max_mailbox_messages", 500, {"storage"});
        plan(base, "outbound_mode", "relay", {"transfer", "delivery", "smtp", "web"});
        plan(base, "delivery_max_age_seconds", 900, {"delivery"});
        plan(base, "bind", "0.0.0.0", {"smtp", "pop3", "imap", "web"});
        plan(base, "log_level", "warn", supervisor_services());
        plan(base, "unknown_future_setting", 1, supervisor_services());
        auto legacy_relay = base;
        legacy_relay.values["smarthost_host"] = "relay.example.test";
        check(restart_plan(base, legacy_relay) == std::vector<std::string>{"transfer", "delivery", "smtp", "web"},
              "legacy derived outgoing mode omitted consumers");
        check(restart_plan(legacy_relay, base) == std::vector<std::string>{"transfer", "delivery", "smtp", "web"},
              "legacy relay removal omitted consumers");
        auto explicit_disabled = base;
        explicit_disabled.values["outbound_mode"] = "disabled";
        plan(explicit_disabled, "smarthost_host", "relay.example.test", {"transfer"});
        for (const auto& [service, expected] : std::map<std::string, std::vector<std::string>>{
            {"auth", {"auth", "delivery", "smtp", "pop3", "imap", "web", "admin"}},
            {"storage", {"storage", "delivery", "smtp", "pop3", "imap", "web", "admin"}},
            {"filter", {"filter", "delivery", "web"}}, {"transfer", {"transfer", "delivery"}}, {"smtp", {"smtp"}}}) {
            auto changed = base;
            changed.values["ports"][service] = 22000;
            check(restart_plan(base, changed) == expected, "RPC endpoint consumers were omitted");
        }
        check(restart_plan(base, base, "all") == supervisor_services(), "full restart scope is incomplete");
        rejects(400, [&] { restart_plan(base, base, "unexpected"); });

        const auto test_root = fs::absolute("build/test-runs").lexically_normal();
        fs::create_directories(test_root);
        const auto directory = test_root / ("restart-unit-" + random_hex(12));
        fs::create_directory(directory);
        const auto source = directory / "postplus.json";
        fs::create_directory(directory / "data");
        environment("POSTPLUS_RESTART_TEST_TOKEN", random_hex(32));
        save(source, {{"domain", "example.test"}, {"data_dir", (directory / "data").string()},
            {"service_token_env", "POSTPLUS_RESTART_TEST_TOKEN"}});
        auto initial = Config::from_file(source);
        environment("POSTPLUS_SUPERVISOR_CONTROL", "");
        check(!supervisor_restart_available(initial), "standalone service advertised restart availability");
        check(!supervisor_running_config(initial), "standalone service invented running config");
        rejects(503, [&] { request_supervisor_restart(initial, initial); });
        std::string manager_job;
        {
            SupervisorControl control(initial);
            check(!supervisor_restart_available(initial), "restart advertised before readiness");
            control.ready(initial);
            check(supervisor_restart_available(initial), "ready supervisor is unavailable");
            check(supervisor_running_config(initial)->values == initial.values, "running metadata is wrong");
            const auto control_directory = fs::path(std::getenv("POSTPLUS_SUPERVISOR_CONTROL"));
            save(control_directory / "restart.request", {{"token", std::string(64, '0')}});
            check(!control.restart_requested(), "forged per-launch capability accepted");
            { std::ofstream malformed(control_directory / "restart.request"); malformed << "{bad"; }
            check(!control.restart_requested(), "malformed control request accepted");
            save(control_directory / "shutdown.request", {{"token", std::string(64, '0')}});
            check(!control.shutdown_requested(), "forged shutdown capability accepted");
            auto updated = initial;
            updated.values["blocked_terms"] = Json::array({"blocked"});
            save(source, updated.values);
            const auto job = request_supervisor_restart(initial, updated);
            check(job.at("state") == "pending" && job.at("services") == Json::array({"filter"}), "incorrect pending job");
            check(!job.contains("config") && !job.contains("token"), "private restart metadata leaked");
            check(supervisor_restart_busy(initial), "pending job did not reserve restart");
            rejects(409, [&] { request_supervisor_restart(initial, updated); });
            rejects(409, [&] { request_supervisor_shutdown(initial); });
            rejects(404, [&] { supervisor_restart_status(initial, "missing"); });
            check(!control.restart_requested(), "restart started before the response delay");
            std::this_thread::sleep_for(std::chrono::milliseconds(320));
            auto request = control.restart_requested();
            check(request && request->job_id == job.at("job_id").get<std::string>(), "queued restart was lost");
            control.restart_running(*request);
            check(supervisor_restart_status(initial).at("state") == "running", "running job not visible");
            check(supervisor_running_config(initial)->values == initial.values, "unready config was marked applied");
            control.restart_complete(*request, updated);
            check(!supervisor_restart_busy(initial), "completed job kept the reservation");
            check(supervisor_running_config(initial)->values == updated.values, "applied config remains stale in unchanged admin child");
            concurrent_state_reads(control, initial, updated, *request);

            auto failed = updated;
            failed.values["blocked_terms"] = Json::array({"another"});
            save(source, failed.values);
            request_supervisor_restart(initial, failed);
            std::this_thread::sleep_for(std::chrono::milliseconds(320));
            auto failure = control.restart_requested();
            control.restart_running(*failure);
            control.restart_failed(*failure, "test readiness failure", true);
            const auto status = supervisor_restart_status(initial);
            check(status.at("state") == "failed" && status.at("rolled_back") == true, "failure status missing");
            check(supervisor_running_config(initial)->values == updated.values, "failed job applied broken configuration");
            check(!supervisor_restart_busy(initial), "failed job blocks an explicit retry");

            fs::create_directory(control_directory / "restart.tmp");
            rejects(503, [&] { request_supervisor_restart(initial, failed); });
            check(supervisor_restart_status(initial).at("state") == "failed", "mailbox failure left an orphaned pending job");
            check(!supervisor_restart_busy(initial), "mailbox failure kept the reservation");
            check(!fs::exists(control_directory / "restart.tmp"), "failed mailbox temporary was not cleaned up");

            save(source, updated.values);
            const auto full = request_supervisor_restart(initial, updated, "all");
            manager_job = full.at("job_id").get<std::string>();
            std::this_thread::sleep_for(std::chrono::milliseconds(320));
            auto manager = control.restart_requested();
            control.restart_running(*manager, true);
            initial = updated;
        }
        {
            SupervisorControl relaunched(initial);
            relaunched.ready(initial);
            const auto status = supervisor_restart_status(initial, manager_job);
            check(status.at("state") == "complete", "service-manager restart status did not survive relaunch");
            check(!supervisor_restart_busy(initial), "service-manager relaunch kept old reservation");
            request_supervisor_shutdown(initial);
            check(relaunched.shutdown_requested(), "ordinary shutdown control no longer works");
        }
        environment("POSTPLUS_SUPERVISOR_CONTROL", "");
        environment("POSTPLUS_RESTART_TEST_TOKEN", "");
        // This absolute, random child was created by this test within its fixed
        // workspace directory; never recursively remove a computed ancestor.
        check(directory.parent_path() == test_root, "unsafe test cleanup path");
        fs::remove_all(directory);
        std::cout << "PASS selective restart plans, authenticated per-launch control, response delay, concurrent bounded state publication, applied state, busy exclusion, rollback status and manager relaunch\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
