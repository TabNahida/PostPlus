#include <postplus/update.hpp>
#include <openssl/evp.h>
#include <array>
#include <fstream>
#include <iostream>
#include <map>

using namespace postplus;
namespace {
namespace fs = std::filesystem;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void write(const fs::path& path, std::string_view bytes) { std::ofstream file(path, std::ios::binary); file << bytes; check(file.good(), "fixture write failed"); }
std::string read(const fs::path& path) { std::ifstream file(path, std::ios::binary); return {std::istreambuf_iterator<char>(file), {}}; }
std::string sha(std::string_view bytes) {
    std::array<unsigned char, 32> digest{}; unsigned count = 0;
    check(EVP_Digest(bytes.data(), bytes.size(), digest.data(), &count, EVP_sha256(), nullptr) == 1 && count == 32, "fixture hash failed");
    const char* digits = "0123456789abcdef"; std::string result;
    for (auto c : digest) { result += digits[c >> 4]; result += digits[c & 15]; } return result;
}
template<class F> void rejects(const std::string& code, F operation) {
    try { operation(); } catch (const UpdateError& error) { check(error.code == code, "unexpected updater rejection code"); return; }
    throw std::runtime_error("unsafe update unexpectedly accepted");
}
struct Fixture {
    fs::path directory;
    UpdateOptions options;
    Json release, manifest;
    std::map<std::string, UpdateHttpResponse> responses;
    std::vector<std::string> requests;
    std::string version = "0.2.2", smtp, auth;
    explicit Fixture(const fs::path& root) : directory(root) {
        fs::create_directories(directory / "install/web"); fs::create_directories(directory / "data");
        options = {directory / "install", directory / "install/web", directory / "data/.updates", "0.2.1", {}};
        options.transport = [this](const std::string& url, std::size_t, auto) { requests.push_back(url); return responses.at(url); };
#ifdef _WIN32
        smtp = "postplus-smtp.exe"; auth = "postplus-auth.exe";
#else
        smtp = "postplus-smtp"; auth = "postplus-auth";
#endif
        write(options.install_directory / smtp, "old SMTP"); write(options.install_directory / auth, "old AUTH");
        write(options.web_directory / "style.css", "old CSS");
        write(options.install_directory / "README.md", "user edited documentation");
        write(directory / "data/message.eml", "user mail and secrets remain untouched");
        Json old{{"schema", 1}, {"repository", "TabNahida/PostPlus"}, {"version", "0.2.1"}, {"files", Json::array({
            {{"path", auth}, {"sha256", sha("old AUTH")}, {"fingerprint", sha("auth source")}}})}};
        write(options.install_directory / "postplus-update.json", old.dump());
        manifest = {{"schema", 1}, {"repository", "TabNahida/PostPlus"}, {"version", version}, {"minimum_updater", 1}, {"targets", Json::array({
            {{"platform", update_platform()}, {"arch", update_architecture()}, {"service_contract", 1}, {"minimum_version", "0.2.1"}, {"files", Json::array()}}})}};
        add(auth, "rebuilt AUTH with same source", sha("auth source"));
        add(smtp, "new SMTP", sha("new smtp source"));
        add("web/style.css", "new CSS", sha("new CSS")); rebuild();
    }
    std::string asset_url(const std::string& name) const { return "https://github.com/TabNahida/PostPlus/releases/download/v" + version + "/" + name; }
    void add(const std::string& path, const std::string& body, const std::string& fingerprint) {
        const auto name = sha(body) + ".module";
        manifest["targets"][0]["files"].push_back({{"path", path}, {"asset", name}, {"sha256", sha(body)},
            {"fingerprint", fingerprint}, {"size", body.size()}, {"executable", !path.starts_with("web/")}});
        responses[asset_url(name)] = {200, {}, body};
    }
    void rebuild() {
        release = {{"tag_name", "v" + version}, {"draft", false}, {"prerelease", false}, {"assets", Json::array()}};
        const auto body = manifest.dump(); std::string sums = sha(body) + "  postplus-update.json\n";
        for (const auto& file : manifest["targets"][0]["files"]) sums += file["sha256"].get<std::string>() + "  " + file["asset"].get<std::string>() + "\n";
        for (const auto& name : {std::string("postplus-update.json"), std::string("SHA256SUMS")}) release["assets"].push_back({{"name", name}, {"browser_download_url", asset_url(name)}});
        for (const auto& file : manifest["targets"][0]["files"]) release["assets"].push_back({{"name", file["asset"]}, {"browser_download_url", asset_url(file["asset"].get<std::string>())}});
        responses[asset_url("postplus-update.json")] = {200, {}, body};
        responses[asset_url("SHA256SUMS")] = {200, {}, sums};
        responses["https://api.github.com/repos/TabNahida/PostPlus/releases/latest"] = {200, {}, release.dump()};
    }
    Json stage(const std::string& id) { std::atomic<bool> cancel = false; return stage_update(options, version, id, cancel); }
    void preserved() {
        check(read(options.install_directory / "README.md") == "user edited documentation", "updater changed user documentation");
        check(read(directory / "data/message.eml") == "user mail and secrets remain untouched", "updater changed user data");
        check(read(options.install_directory / auth) == "old AUTH", "unchanged source fingerprint downloaded a rebuilt binary");
    }
};
}
int main() {
    try {
        const auto workspace = fs::absolute("build/test-runs").lexically_normal(); fs::create_directories(workspace);
        const auto root = workspace / ("update-unit-" + random_hex(12)); fs::create_directory(root);
        Fixture fixture(root);
        const auto checked = check_update(fixture.options);
        check(checked.at("available") == true && checked.at("supported") == true && checked.at("component_aware") == true, "release check lost compatibility metadata");
        check(checked.at("files").size() == 2 && checked.at("services") == Json::array({"smtp", "web", "admin"}), "unchanged modules or web resource consumers omitted");
        check(checked.at("download_bytes") == 15 && !checked.contains("installation_manifest"), "incorrect download plan or private state leak");
        const auto first = random_hex(16);
        check(fixture.stage(first).at("state") == "staged", "modules were not staged");
        check(fixture.stage(first).at("state") == "staged", "staging replay is not idempotent");
        check(read(fixture.options.install_directory / fixture.smtp) == "old SMTP", "download changed a running module");
        check(apply_staged_update(fixture.options, first).at("state") == "installed", "installation not awaiting readiness");
        check(read(fixture.options.install_directory / fixture.smtp) == "new SMTP", "changed binary not replaced");
        check(read(fixture.options.web_directory / "style.css") == "new CSS", "changed web resource not replaced");
        fixture.preserved();
        check(rollback_staged_update(fixture.options, first).at("rolled_back") == true, "readiness rollback missing");
        check(read(fixture.options.install_directory / fixture.smtp) == "old SMTP" && read(fixture.options.web_directory / "style.css") == "old CSS", "rollback did not restore originals");
        const auto interrupted = random_hex(16);
        const auto old_metadata = read(fixture.options.install_directory / "postplus-update.json");
        fixture.stage(interrupted); apply_staged_update(fixture.options, interrupted);
        const auto interrupted_path = fixture.options.storage_directory / interrupted / "job.json";
        auto journal = Json::parse(read(interrupted_path));
        const auto new_metadata = journal.at("installation_manifest").dump();
        journal["new_metadata_sha256"] = sha(new_metadata); journal["metadata_applied"] = true;
        write(interrupted_path, journal.dump());
        write(fixture.options.install_directory / "postplus-update.json", new_metadata);
        check(rollback_staged_update(fixture.options, interrupted).at("rolled_back") == true, "interrupted readiness commit did not roll back");
        check(read(fixture.options.install_directory / "postplus-update.json") == old_metadata && installed_update_version(fixture.options) == "0.2.1", "rollback retained an uncommitted installed version");
        const auto second = random_hex(16); fixture.stage(second); apply_staged_update(fixture.options, second);
        check(commit_staged_update(fixture.options, second).at("state") == "complete", "ready update not committed");
        check(commit_staged_update(fixture.options, second).at("state") == "complete", "commit replay is not idempotent");
        check(installed_update_version(fixture.options) == "0.2.2", "asset-only update retained stale launcher version");
        check(check_update(fixture.options).at("available") == false, "committed release repeatedly offered");
        fixture.preserved();
        fixture.version = "0.2.3"; fixture.manifest["version"] = fixture.version; fixture.rebuild();
        check(check_update(fixture.options).at("files").empty(), "unchanged-source release replaced retained local modules");
        const auto metadata_only = random_hex(16); fixture.stage(metadata_only);
        apply_staged_update(fixture.options, metadata_only); commit_staged_update(fixture.options, metadata_only);
        check(installed_update_version(fixture.options) == "0.2.3", "metadata-only release failed to advance installed version");
        rejects("invalid_state", [&] { rollback_staged_update(fixture.options, second); });
        rejects("invalid_job", [&] { update_job_status(fixture.options, "../escape"); });

        Fixture corrupt(root / "corrupt");
        const auto file = corrupt.manifest["targets"][0]["files"][1];
        corrupt.responses[corrupt.asset_url(file["asset"].get<std::string>())].body = "tampered";
        const auto corrupt_id = random_hex(16);
        rejects("checksum_mismatch", [&] { corrupt.stage(corrupt_id); });
        check(update_job_status(corrupt.options, corrupt_id).at("state") == "failed", "download corruption did not persist terminal state");
        check(read(corrupt.options.install_directory / corrupt.smtp) == "old SMTP", "bad download changed installation");

        Fixture hostile(root / "hostile"); hostile.manifest["targets"][0]["files"][1]["path"] = "../outside"; hostile.rebuild();
        rejects("invalid_update", [&] { check_update(hostile.options); });
        hostile.manifest["targets"][0]["files"][1]["path"] = hostile.smtp; hostile.rebuild();
        hostile.responses[hostile.asset_url("postplus-update.json")] = {302, {{"location", "https://evil.example/module"}}, ""};
        rejects("untrusted_url", [&] { check_update(hostile.options); });

        Fixture omitted_baseline(root / "omitted-baseline");
        omitted_baseline.manifest["targets"][0]["files"].erase(0); omitted_baseline.rebuild();
        rejects("incomplete_release", [&] { check_update(omitted_baseline.options); });
        Fixture omitted_native(root / "omitted-native");
        fs::remove(omitted_native.options.install_directory / "postplus-update.json");
        omitted_native.manifest["targets"][0]["files"].erase(1); omitted_native.rebuild();
        rejects("incomplete_release", [&] { check_update(omitted_native.options); });

        Fixture crashed(root / "crashed"); const auto crashed_id = random_hex(16);
        crashed.stage(crashed_id); apply_staged_update(crashed.options, crashed_id);
        auto recovered = recover_interrupted_updates(crashed.options);
        check(recovered.size() == 1 && recovered[0].at("state") == "failed" && recovered[0].at("rolled_back") == true,
              "interrupted ordinary-module install lacked durable recovery");
        check(read(crashed.options.install_directory / crashed.smtp) == "old SMTP" &&
              read(crashed.options.web_directory / "style.css") == "old CSS", "startup recovery retained a mixed module generation");
        check(recover_interrupted_updates(crashed.options).empty(), "startup recovery repeated an already restored job");

        const auto partially_applied_id = random_hex(16); crashed.stage(partially_applied_id);
        apply_staged_update(crashed.options, partially_applied_id);
        const auto partial_path = crashed.options.storage_directory / partially_applied_id / "job.json";
        auto partial = Json::parse(read(partial_path)); partial["state"] = "applying"; write(partial_path, partial.dump());
        check(recover_interrupted_updates(crashed.options).size() == 1, "interrupted applying journal was not restored");

        const auto boot_id = random_hex(16); crashed.stage(boot_id);
        const auto boot_path = crashed.options.storage_directory / boot_id / "job.json";
        auto boot = Json::parse(read(boot_path)); boot["requires_launcher_restart"] = true; write(boot_path, boot.dump());
        apply_staged_update(crashed.options, boot_id);
        const auto boot_config = fs::absolute(crashed.directory / "postplus.json").lexically_normal();
        write(boot_config, "{}");
        write(crashed.options.storage_directory / "relaunch.json", Json{{"job_id", boot_id}, {"config", boot_config.string()}}.dump());
        check(recover_interrupted_updates(crashed.options).empty(), "ordinary startup recovery consumed a launcher handoff");
        check(recover_launcher_update(crashed.options, boot_config).at("state") == "installed", "systemd prestart rejected first launcher boot");
        check(read(crashed.options.install_directory / crashed.smtp) == "new SMTP", "first prestart restored before attempting new launcher");
        check(recover_launcher_update(crashed.options, boot_config).at("state") == "rolled_back", "systemd repeated an unacknowledged launcher boot");
        check(pending_update_relaunch(crashed.options).has_value(), "prestart recovery lost restored-generation acknowledgement");
        check(read(crashed.options.install_directory / crashed.smtp) == "old SMTP", "prestart failed to restore originals");
        check(recover_launcher_update(crashed.options, boot_config).at("state") == "rolled_back", "restored prestart was not idempotent");
        finish_update_relaunch(crashed.options, boot_id);
        check(recover_launcher_update(crashed.options, boot_config).at("state") == "idle", "finished launcher recovery remained active");

        Fixture linked(root / "linked");
        fs::create_hard_link(linked.options.install_directory / linked.smtp, linked.directory / "data/hard-linked-module");
        rejects("invalid_update", [&] { check_update(linked.options); });

        Fixture local(root / "local"); const auto local_id = random_hex(16); local.stage(local_id);
        write(local.options.install_directory / local.smtp, "local change after staging");
        rejects("local_change", [&] { apply_staged_update(local.options, local_id); });
        check(read(local.options.web_directory / "style.css") == "old CSS", "preflight failure partially installed another module");
        check(update_job_status(local.options, local_id).at("state") == "failed", "preflight failure stayed staged");

        Fixture cancelled(root / "cancelled"); const auto cancelled_id = random_hex(16); std::atomic<bool> cancel = true;
        rejects("cancelled", [&] { stage_update(cancelled.options, cancelled.version, cancelled_id, cancel); });
        check(update_job_status(cancelled.options, cancelled_id).at("state") == "cancelled", "cancellation state not durable");
        check(root.parent_path() == workspace, "unsafe updater test cleanup"); fs::remove_all(root);
        std::cout << "PASS trusted stable modules, source fingerprints, SHA integrity, selective staging/install, durable idempotent jobs, readiness commit/rollback, local-change protection, traversal/redirect rejection and data/document preservation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
