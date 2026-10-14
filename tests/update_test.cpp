#include <postplus/update.hpp>
#include "../src/core/update_archive.hpp"
#include <openssl/evp.h>
#include <zlib.h>
#include <array>
#include <fstream>
#include <iostream>
#include <map>
#include <iomanip>

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
std::string compressed(std::string_view bytes, int window) {
    z_stream stream{}; check(deflateInit2(&stream, 6, Z_DEFLATED, window, 8, Z_DEFAULT_STRATEGY) == Z_OK, "fixture compression failed");
    std::string output(deflateBound(&stream, static_cast<uLong>(bytes.size())), '\0');
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(bytes.data())); stream.avail_in = static_cast<uInt>(bytes.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data()); stream.avail_out = static_cast<uInt>(output.size());
    check(deflate(&stream, Z_FINISH) == Z_STREAM_END, "fixture compression truncated");
    output.resize(stream.total_out); deflateEnd(&stream); return output;
}
using Entries = std::vector<std::pair<std::string, std::string>>;
std::string package(const Entries& entries, bool zip, char type = '0') {
    std::string result, central;
    auto little = [](std::string& out, std::uint32_t value, unsigned size) { for (unsigned i = 0; i < size; ++i) out += static_cast<char>((value >> (8 * i)) & 255); };
    for (const auto& [name, body] : entries) {
        if (zip) {
            const auto offset = result.size();
            const auto crc = static_cast<std::uint32_t>(crc32(0, reinterpret_cast<const Bytef*>(body.data()), static_cast<uInt>(body.size())));
            const auto packed = compressed(body, -MAX_WBITS);
            little(result, 0x04034b50, 4); little(result, 20, 2); little(result, 0, 2); little(result, 8, 2); little(result, 0, 4);
            little(result, crc, 4); little(result, static_cast<std::uint32_t>(packed.size()), 4); little(result, static_cast<std::uint32_t>(body.size()), 4);
            little(result, static_cast<std::uint32_t>(name.size()), 2); little(result, 0, 2); result += name; result += packed;
            little(central, 0x02014b50, 4); little(central, 0x0314, 2); little(central, 20, 2); little(central, 0, 2); little(central, 8, 2); little(central, 0, 4);
            little(central, crc, 4); little(central, static_cast<std::uint32_t>(packed.size()), 4); little(central, static_cast<std::uint32_t>(body.size()), 4);
            little(central, static_cast<std::uint32_t>(name.size()), 2); little(central, 0, 2); little(central, 0, 2); little(central, 0, 2); little(central, 0, 2);
            little(central, (type == '2' ? 0120777U : 0100644U) << 16, 4); little(central, static_cast<std::uint32_t>(offset), 4); central += name;
        } else {
            check(name.size() <= 100, "tar fixture name too long"); std::string header(512, '\0'); header.replace(0, name.size(), name);
            auto number = [&](std::size_t at, std::size_t count, std::uint64_t value) {
                std::ostringstream text; text << std::setfill('0') << std::setw(static_cast<int>(count - 1)) << std::oct << value;
                header.replace(at, count - 1, text.str());
            };
            number(100, 8, 0644); number(124, 12, body.size()); header.replace(148, 8, 8, ' '); header[156] = type;
            header.replace(257, 5, "ustar"); unsigned checksum = 0; for (auto c : header) checksum += static_cast<unsigned char>(c);
            number(148, 7, checksum); header[155] = ' '; result += header; result += body;
            result.append((512 - body.size() % 512) % 512, '\0');
        }
    }
    if (!zip) { result.append(1024, '\0'); return compressed(result, MAX_WBITS + 16); }
    const auto offset = result.size(); result += central;
    little(result, 0x06054b50, 4); little(result, 0, 4); little(result, static_cast<std::uint32_t>(entries.size()), 2); little(result, static_cast<std::uint32_t>(entries.size()), 2);
    little(result, static_cast<std::uint32_t>(central.size()), 4); little(result, static_cast<std::uint32_t>(offset), 4); little(result, 0, 2); return result;
}
struct Fixture {
    fs::path directory;
    UpdateOptions options;
    Json release, manifest;
    std::map<std::string, UpdateHttpResponse> responses;
    std::map<std::string, std::string> module_bodies;
    std::vector<std::string> requests;
    std::string version = "0.2.2", smtp, auth;
    bool archive_mode = true;
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
        module_bodies[name] = body;
    }
    void rebuild() {
        release = {{"tag_name", "v" + version}, {"draft", false}, {"prerelease", false}, {"assets", Json::array()}};
        auto& target = manifest["targets"][0];
        const auto name = "postplus-" + version + "-" + update_platform() + "-" + update_architecture() + (update_platform() == "windows" ? ".zip" : ".tar.gz");
        Entries entries;
        for (const auto& file : target["files"]) entries.emplace_back("postplus-" + version + "/" + file["path"].get<std::string>(), module_bodies.at(file["asset"].get<std::string>()));
        entries.emplace_back("postplus-" + version + "/README.md", "upstream documentation must never replace local documentation");
        entries.emplace_back("postplus-" + version + "/config/postplus.example.json", "upstream configuration must never be installed");
        const auto archive = package(entries, update_platform() == "windows");
        if (archive_mode) {
            target["download"] = "archive";
            target["archive"] = {{"asset", name}, {"sha256", sha(archive)}, {"size", archive.size()}};
            responses[asset_url(name)] = {200, {}, archive};
        } else { target.erase("download"); target.erase("archive"); }
        const auto body = manifest.dump(); std::string sums = sha(body) + "  postplus-update.json\n";
        for (const auto& file : manifest["targets"][0]["files"]) sums += file["sha256"].get<std::string>() + "  " + file["asset"].get<std::string>() + "\n";
        if (archive_mode) { sums += sha(archive) + "  " + name + "\n"; release["assets"].push_back({{"name", name}, {"browser_download_url", asset_url(name)}}); }
        for (const auto& metadata_name : {std::string("postplus-update.json"), std::string("SHA256SUMS")}) release["assets"].push_back({{"name", metadata_name}, {"browser_download_url", asset_url(metadata_name)}});
        for (const auto& file : manifest["targets"][0]["files"]) release["assets"].push_back({{"name", file["asset"]}, {"browser_download_url", asset_url(file["asset"].get<std::string>())}});
        responses[asset_url("postplus-update.json")] = {200, {}, body};
        responses[asset_url("SHA256SUMS")] = {200, {}, sums};
        responses["https://api.github.com/repos/TabNahida/PostPlus/releases?per_page=20"] = {200, {}, Json::array({release}).dump()};
    }
    Json stage(const std::string& id) { std::atomic<bool> cancel = false; return stage_update(options, version, id, cancel); }
    void preserved() {
        check(read(options.install_directory / "README.md") == "user edited documentation", "updater changed user documentation");
        check(read(directory / "data/message.eml") == "user mail and secrets remain untouched", "updater changed user data");
        check(read(options.install_directory / auth) == "old AUTH", "unchanged source fingerprint downloaded a rebuilt binary");
    }
};
}
int main(int argc, char** argv) {
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--archive") {
            const auto archive = fs::path(std::u8string(reinterpret_cast<const char8_t*>(argv[2])));
            const auto metadata = Json::parse(read(fs::path(std::u8string(reinterpret_cast<const char8_t*>(argv[3])))));
            std::atomic<bool> cancel = false; std::size_t count = 0;
            extract_update_modules(read(archive), archive.filename().string(), metadata.at("version").get<std::string>(), metadata.at("files"), cancel,
                [&](const Json& file, std::string_view body) { check(sha(body) == file.at("sha256").get<std::string>(), "real package module hash mismatch"); ++count; });
            check(count == metadata.at("files").size(), "real package native extractor omitted modules");
            std::cout << "PASS native ZIP/tar.gz decoder verified every real package module\n"; return 0;
        }
        const auto workspace = fs::absolute("build/test-runs").lexically_normal(); fs::create_directories(workspace);
        const auto root = workspace / ("update-unit-" + random_hex(12)); fs::create_directory(root);
        Fixture fixture(root);
        const auto checked = check_update(fixture.options);
        check(checked.at("available") == true && checked.at("supported") == true && checked.at("component_aware") == true, "release check lost compatibility metadata");
        check(checked.at("files").size() == 2 && checked.at("services") == Json::array({"smtp", "web", "admin"}), "unchanged modules or web resource consumers omitted");
        check(checked.at("changed_bytes") == 15 && checked.at("download_bytes") == checked.at("archive").at("size") && checked.at("download_format") == "archive" && !checked.contains("installation_manifest"), "incorrect archive download plan or private state leak");
        const auto first = random_hex(16);
        check(fixture.stage(first).at("state") == "staged", "modules were not staged");
        check(std::none_of(fixture.requests.begin(), fixture.requests.end(), [](const auto& url) { return url.ends_with(".module"); }), "archive update downloaded legacy raw modules");
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
        const auto archive = corrupt.manifest["targets"][0]["archive"];
        corrupt.responses[corrupt.asset_url(archive["asset"].get<std::string>())].body = "tampered";
        const auto corrupt_id = random_hex(16);
        rejects("checksum_mismatch", [&] { corrupt.stage(corrupt_id); });
        check(update_job_status(corrupt.options, corrupt_id).at("state") == "failed", "download corruption did not persist terminal state");
        check(read(corrupt.options.install_directory / corrupt.smtp) == "old SMTP", "bad download changed installation");

        Fixture module_corrupt(root / "module-corrupt");
        module_corrupt.manifest["targets"][0]["files"][1]["sha256"] = sha("bad module"); module_corrupt.rebuild();
        rejects("checksum_mismatch", [&] { module_corrupt.stage(random_hex(16)); });

        Fixture legacy(root / "legacy"); legacy.archive_mode = false; legacy.rebuild();
#ifdef POSTPLUS_LEGACY_UPDATES
        check(legacy.stage(random_hex(16)).at("state") == "staged", "migration bridge dropped old module downloads");
        check(std::any_of(legacy.requests.begin(), legacy.requests.end(), [](const auto& url) { return url.ends_with(".module"); }), "legacy download was not exercised");
#else
        rejects("incompatible_release", [&] { check_update(legacy.options); });
#endif

        const auto prefix = "postplus-0.2.2/";
        std::atomic<bool> extraction_cancel = false;
        const Json selected = Json::array({{{"path", "web/style.css"}, {"size", 3}}});
        for (bool zip : {false, true}) {
            unsigned accepted = 0;
            auto extract = [&](const Entries& entries, char type = '0') {
                extract_update_modules(package(entries, zip, type), zip ? "fixture.zip" : "fixture.tar.gz", "0.2.2", selected, extraction_cancel,
                    [&](const Json&, std::string_view bytes) { check(bytes == "CSS", "archive extraction changed module"); ++accepted; });
            };
            extract({{std::string(prefix) + "web/style.css", "CSS"}, {std::string(prefix) + "README.md", "preserved docs"}});
            check(accepted == 1, "ZIP/tar archive did not select its reviewed module");
            rejects("invalid_archive", [&] { extract({{std::string(prefix) + "../escape", "x"}}); });
            rejects("invalid_archive", [&] { extract({{std::string(prefix) + "linked", "x"}}, '2'); });
            rejects("invalid_archive", [&] { extract({{std::string(prefix) + "web/style.css", "CSS"}, {std::string(prefix) + "web/style.css", "CSS"}}); });
            rejects("invalid_archive", [&] { extract({{std::string(prefix) + "README.md", "no module"}}); });
        }

        // The legacy Latest badge can stay on 0.3.1 while semantic discovery
        // selects a newer normal stable release, ignoring prereleases/drafts.
        Fixture discovery(root / "discovery");
        auto old_release = discovery.release; old_release["tag_name"] = "v0.2.1";
        auto preview = discovery.release; preview["tag_name"] = "v9.0.0"; preview["prerelease"] = true;
        discovery.responses["https://api.github.com/repos/TabNahida/PostPlus/releases?per_page=20"].body = Json::array({old_release, preview, discovery.release}).dump();
        check(check_update(discovery.options).at("version") == "0.2.2", "legacy Latest bridge hid the newest semantic stable release");

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
