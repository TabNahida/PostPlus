set_project("PostPlus")
set_version("0.1.0")
set_xmakever("2.9.8")
set_languages("c++20")
set_warnings("allextra")
add_rules("mode.debug", "mode.release")

add_requires("asio 1.34.2")
add_requires("nlohmann_json 3.12.0")
add_requires("openssl3 3.6.1")
add_requires("sqlite3 3.51.0+300")

target("postplus-core")
    set_kind("static")
    add_files("src/core/*.cpp")
    add_headerfiles("include/(postplus/*.hpp)")
    add_includedirs("include", {public = true})
    add_defines("ASIO_STANDALONE", "ASIO_NO_DEPRECATED", {public = true})
    add_packages("asio", "nlohmann_json", "openssl3", {public = true})
    if is_plat("windows") then
        add_defines("_WIN32_WINNT=0x0A00", "WIN32_LEAN_AND_MEAN", "NOMINMAX", "_CRT_SECURE_NO_WARNINGS", {public = true})
        add_syslinks("ws2_32", "mswsock", "advapi32", "crypt32", {public = true})
        add_cxflags("/utf-8", {tools = {"cl", "clang_cl"}, public = true})
    else
        add_syslinks("pthread", {public = true})
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

target("postplus")
    set_kind("binary")
    add_files("src/tools/main.cpp")
    add_deps("postplus-core")
    for _, service in ipairs({"auth", "storage", "filter", "smtp", "pop3", "imap", "delivery", "transfer", "web"}) do
        add_deps("postplus-" .. service, {inherit = false})
    end

target("postplus-ctl")
    set_kind("binary")
    add_files("src/tools/ctl.cpp")
    add_deps("postplus-core")

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
