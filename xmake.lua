set_project("PostPlus")
set_version("0.3.4")
set_xmakever("2.9.8")
set_languages("c++20")
set_warnings("allextra")
-- Keep relative configuration paths consistent with the repository quick start.
set_rundir("$(projectdir)")
add_rules("mode.debug", "mode.release")

add_requires("asio 1.34.2", {system = false})
add_requires("nlohmann_json 3.12.0", {system = false})
-- Ship OpenSSL and SQLite in the executables; packages must not depend on a
-- developer machine's package cache or an unpinned system installation.
add_requires("openssl3 3.6.1", {system = false, configs = {shared = false}})
add_requires("sqlite3 3.51.0+300", {system = false, configs = {shared = false}})
add_requires("zlib 1.3.1", {system = false, configs = {shared = false}})

target("postplus-core")
    set_kind("static")
    add_files("src/core/*.cpp")
    add_headerfiles("include/(postplus/*.hpp)")
    add_includedirs("include", {public = true})
    add_defines("ASIO_STANDALONE", "ASIO_NO_DEPRECATED", {public = true})
    add_defines('POSTPLUS_VERSION="0.3.4"', {public = true})
    add_packages("asio", "nlohmann_json", "openssl3", "sqlite3", "zlib", {public = true})
    if is_plat("windows") then
        add_defines("_WIN32_WINNT=0x0A00", "WIN32_LEAN_AND_MEAN", "NOMINMAX", "_CRT_SECURE_NO_WARNINGS", {public = true})
        add_syslinks("ws2_32", "mswsock", "advapi32", "crypt32", {public = true})
        add_cxflags("/utf-8", {tools = {"cl", "clang_cl"}, public = true})
    else
        add_syslinks("pthread", {public = true})
        if is_plat("macosx") then
            add_syslinks("iconv", {public = true})
            add_frameworks("Security", "CoreFoundation", {public = true})
        end
    end

for _, service in ipairs({"auth", "storage", "filter", "smtp", "pop3", "imap", "delivery", "transfer", "web"}) do
    target("postplus-" .. service)
        set_kind("binary")
        add_files("src/services/" .. service .. ".cpp")
        add_deps("postplus-core")
        if service == "auth" or service == "storage" then
            add_packages("sqlite3")
        end
end

target("postplus-admin")
    set_kind("binary")
    add_files("src/services/web.cpp")
    add_defines("POSTPLUS_ADMIN")
    add_deps("postplus-core")

target("postplus")
    set_kind("binary")
    add_files("src/tools/main.cpp")
    add_deps("postplus-core", "postplus-admin")
    for _, service in ipairs({"auth", "storage", "filter", "smtp", "pop3", "imap", "delivery", "transfer", "web"}) do
        add_deps("postplus-" .. service, {inherit = false})
    end
    after_build(function (target)
        local destination = path.join(target:targetdir(), "web")
        os.mkdir(destination)
        os.cp(path.join(os.projectdir(), "web", "*"), destination)
    end)
    before_run(function (target)
        -- Refresh assets even when only HTML, CSS, or JavaScript has changed.
        local destination = path.join(target:targetdir(), "web")
        os.mkdir(destination)
        os.cp(path.join(os.projectdir(), "web", "*"), destination)
    end)

target("postplus-ctl")
    set_kind("binary")
    add_files("src/tools/ctl.cpp")
    add_deps("postplus-core")

target("postplus-clean-data")
    set_kind("binary")
    add_files("src/tools/clean_data.cpp")
    add_deps("postplus-core")

target("postplus-update")
    set_kind("binary")
    add_files("src/tools/update.cpp")
    add_deps("postplus-core")

task("clean-data")
    set_menu {
        usage = "xmake clean-data [--config=PATH] [--dry-run]",
        description = "Remove PostPlus databases and reopen first-run setup (stop services first).",
        options = {
            {nil, "config", "kv", "config/postplus.json", "Configuration selecting the data directory"},
            {nil, "dry-run", "k", nil, "Show database files without deleting them"}
        }
    }
    on_run(function ()
        import("core.base.option")
        import("core.base.task")
        import("core.project.project")
        local arguments = {"--config", path.absolute(option.get("config"), os.projectdir())}
        if option.get("dry-run") then table.insert(arguments, "--dry-run") end
        task.run("build", {target = "postplus-clean-data"})
        os.execv(path.absolute(project.target("postplus-clean-data"):targetfile()), arguments)
    end)
task_end()

target("postplus-tests")
    set_kind("binary")
    add_files("tests/unit.cpp")
    add_deps("postplus-core")
    add_tests("unit")

target("postplus-mime-tests")
    set_kind("binary")
    add_files("tests/mime_test.cpp")
    add_deps("postplus-core")
    add_tests("mime")

target("postplus-remote-image-tests")
    set_kind("binary")
    add_files("tests/remote_image_test.cpp")
    add_deps("postplus-core")
    add_tests("remote-image")

target("postplus-logging-tests")
    set_kind("binary")
    add_files("tests/logging_test.cpp")
    add_deps("postplus-core")
    add_tests("logging")

target("postplus-process-tests")
    set_kind("binary")
    add_files("tests/process_test.cpp")
    add_deps("postplus-core")
    add_tests("process")

target("postplus-restart-tests")
    set_kind("binary")
    add_files("tests/restart_test.cpp")
    add_deps("postplus-core")
    add_tests("restart")

target("postplus-update-tests")
    set_kind("binary")
    add_files("tests/update_test.cpp")
    add_deps("postplus-core")
    add_tests("update")

target("postplus-mail-clients-tests")
    set_kind("binary")
    add_files("tests/mail_clients_test.cpp")
    add_deps("postplus-core")
    add_tests("mail-clients")

target("postplus-acme-tests")
    set_kind("binary")
    add_files("tests/acme_test.cpp")
    add_deps("postplus-core")
    add_tests("acme")

target("postplus-dns-tests")
    set_kind("binary")
    add_files("tests/dns_test.cpp")
    add_deps("postplus-core")
    add_tests("dns")

target("postplus-dkim-tests")
    set_kind("binary")
    add_files("tests/dkim_test.cpp")
    add_deps("postplus-core")
    add_tests("dkim")

target("postplus-outbound-tests")
    set_kind("binary")
    add_files("tests/outbound_test.cpp")
    add_deps("postplus-core")
    add_tests("outbound")

includes("@builtin/xpack")
target("postplus-verification-code-tests")
    set_kind("binary")
    add_files("tests/verification_code_test.cpp")
    add_deps("postplus-core")
    add_tests("verification-code")

xpack("postplus")
    set_formats("zip", "targz")
    set_title("PostPlus")
    set_description("A mail server with browser-based setup, administration, and Webmail.")
    set_homepage("https://github.com/TabNahida/PostPlus")
    set_license("GPL-3.0-only")
    set_licensefile("LICENSE")
    set_basename("postplus-$(version)-$(plat)-$(arch)")
    set_prefixdir("postplus-$(version)")
    -- The supervisor discovers services and web assets beside its executable.
    set_bindir(".")
    set_libdir(".")
    add_targets("postplus", "postplus-admin", "postplus-web", "postplus-auth",
                "postplus-storage", "postplus-filter", "postplus-smtp",
                "postplus-pop3", "postplus-imap", "postplus-delivery",
                "postplus-transfer", "postplus-ctl", "postplus-clean-data", "postplus-update")
    add_installfiles("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md")
    -- Explicit allowlist: never include the local configuration or mail data.
    add_installfiles("(web/**)", "(docs/**)", "(licenses/**)", "(config/postplus.example.json)",
                     "(scripts/install-systemd.sh)")
    after_package(function (package)
        import("lib.detect.find_tool")
        local python = find_tool("python3") or find_tool("python")
        assert(python, "Python 3 is required to generate the installed component manifest")
        os.execv(python.program, {path.join(os.projectdir(), "scripts", "release_manifest.py"),
            "installed", "--archive", path.absolute(package:outputfile()),
            "--platform", package:plat(), "--arch", package:arch()})
    end)
xpack_end()
