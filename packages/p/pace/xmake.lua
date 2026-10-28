-- Adapted from https://github.com/TabNahida/repo-xmake, MIT license: ../../LICENSE.
-- Pins the checksum-verified official PACE v0.4.0 release.
package("pace")
    set_homepage("https://github.com/TabNahida/PACE")
    set_description("Parallel Async Coroutine Engine: C++20 coroutine networking from sockets to HTTP/3.")
    set_license("MIT")

    add_urls("https://github.com/TabNahida/PACE/archive/refs/tags/v$(version).tar.gz",
             "https://github.com/TabNahida/PACE.git")
    add_versions("0.4.0", "46957eec8edaecc1d0806810f9114a8bfd3af685dad44018579288151afbeed6")

    add_configs("shared", {description = "Build shared libraries.", default = false, type = "boolean", readonly = true})
    add_configs("http1", {description = "Enable HTTP/1.0 and HTTP/1.1.", default = true, type = "boolean"})
    add_configs("websocket", {description = "Enable WebSocket.", default = true, type = "boolean"})
    add_configs("tls", {description = "Enable TLS/HTTPS with OpenSSL.", default = false, type = "boolean"})
    add_configs("dns", {description = "Enable asynchronous DNS with c-ares.", default = false, type = "boolean"})
    add_configs("quic", {description = "Enable QUIC (POSIX only).", default = false, type = "boolean"})
    add_configs("http2", {description = "Enable HTTP/2 with nghttp2.", default = false, type = "boolean"})
    add_configs("http3", {description = "Enable HTTP/3 and QUIC (POSIX only).", default = false, type = "boolean"})
    add_configs("profiling", {description = "Enable intrusive per-thread stage timings.", default = false, type = "boolean"})

    on_load(function (package)
        local quic = package:config("quic") or package:config("http3")
        if quic and package:is_plat("windows", "mingw") then
            raise("PACE QUIC/HTTP3 currently require a POSIX platform")
        end

        if package:config("tls") or quic then
            package:add("deps", "openssl3 3.5.7")
        end
        if package:config("dns") then
            package:add("deps", "c-ares 1.34.8")
        end
        if package:config("http2") then
            package:add("deps", "nghttp2 1.70.0")
        end
        if package:config("http3") then
            package:add("deps", "nghttp3 v1.18.0")
        end

        -- Static libraries must precede the PACE modules they depend on.
        for _, name in ipairs({"http3", "http2", "http1", "websocket", "quic", "tls", "dns"}) do
            if package:config(name) or (name == "quic" and quic) then
                package:add("links", "pace_" .. name)
                package:add("defines", "PACE_HAS_" .. name:upper())
            end
        end
        package:add("links", "pace_net", "pace_runtime")
        if package:config("profiling") then
            package:add("defines", "PACE_ENABLE_PROFILING")
        end
        if package:is_plat("windows", "mingw") then
            package:add("syslinks", "ws2_32", "bcrypt")
            package:add("defines", "WIN32_LEAN_AND_MEAN", "NOMINMAX", "_WIN32_WINNT=0x0A00")
        else
            package:add("syslinks", "pthread")
        end
    end)

    on_install("linux", "macosx", "bsd", "windows", "mingw", function (package)
        local configs = {
            cxxstandard = "cxx20",
            tests = false,
            examples = false,
            benchmarks = false,
            components = false,
            scaling = false
        }
        for _, name in ipairs({"http1", "websocket", "tls", "dns", "quic", "http2", "http3", "profiling"}) do
            configs[name] = package:config(name)
        end
        import("package.tools.xmake").install(package, configs)
    end)

    on_test(function (package)
        assert(package:check_cxxsnippets({test = [[
            #include <pace/pace.hpp>
            void test() {
                pace::io_context io;
                pace::tcp::stream socket(io);
            #ifdef PACE_HAS_HTTP1
                auto request = pace::http::async_get(io, pace::tcp::endpoint{"127.0.0.1", 8080});
            #endif
            #ifdef PACE_HAS_WEBSOCKET
                pace::websocket::stream websocket(std::move(socket), pace::websocket::role::client);
            #endif
            #ifdef PACE_HAS_TLS
                pace::tls::context tls;
            #endif
            #ifdef PACE_HAS_DNS
                (void)pace::dns::error_category();
            #endif
            #ifdef PACE_HAS_QUIC
                pace::quic::context quic;
            #endif
            #ifdef PACE_HAS_HTTP2
                auto http2 = pace::http2::async_exchange(pace::tcp::stream(io), "localhost", {});
            #endif
            #ifdef PACE_HAS_HTTP3
                auto http3 = pace::http3::async_exchange(pace::quic::connection(io, quic), "localhost", {});
            #endif
            }
        ]]}, {configs = {languages = "c++20"}}))
    end)
