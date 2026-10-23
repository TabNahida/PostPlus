#include <postplus/tls_stream.hpp>
#include <postplus/core.hpp>
#include <postplus/data_lock.hpp>
#include <postplus/trust.hpp>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <cerrno>
#include <fstream>
#include <list>
#include <map>
#include <mutex>
#include <stdexcept>
#include <system_error>
#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

namespace postplus {
namespace {
using NativeContext = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SharedContext = std::shared_ptr<SSL_CTX>;
[[noreturn]] void tls_error(const char* operation) {
    std::string message(operation);
    for (unsigned long code; (code = ERR_get_error()) != 0;) {
        char text[256]{};
        ERR_error_string_n(code, text, sizeof(text));
        message += ": ";
        message += text;
    }
    throw std::system_error(std::make_error_code(std::errc::protocol_error), message);
}
NativeContext context(bool server) {
    ERR_clear_error();
    NativeContext result(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()), SSL_CTX_free);
    if (!result || SSL_CTX_set_min_proto_version(result.get(), TLS1_2_VERSION) != 1)
        tls_error("cannot create TLS context");
    SSL_CTX_set_options(result.get(), SSL_OP_NO_COMPRESSION);
    // Preserve the existing policy: public servers reject renegotiation, while
    // outbound clients retain OpenSSL's default handling of a peer request.
    if (server) SSL_CTX_set_options(result.get(), SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_default_passwd_cb(result.get(), [](char*, int, int, void*) { return 0; });
    return result;
}
NativeContext server_context(const std::string& certificate, const std::string& key) {
    if (certificate.empty() || key.empty() || certificate.find('\0') != std::string::npos ||
        key.find('\0') != std::string::npos) throw std::invalid_argument("invalid TLS file path");
    auto result = context(true);
    if (SSL_CTX_use_certificate_chain_file(result.get(), certificate.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(result.get(), key.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(result.get()) != 1) tls_error("cannot load TLS certificate/private key");
    return result;
}

struct FileStamp {
    std::filesystem::file_type type = std::filesystem::file_type::none;
    std::filesystem::perms permissions = std::filesystem::perms::unknown;
    std::filesystem::file_time_type modified{};
    std::uintmax_t size = 0;
    std::error_code error;
    bool operator==(const FileStamp&) const = default;
};
FileStamp file_stamp(const std::string& filename) {
    FileStamp result;
    if (filename.empty() || filename.find('\0') != std::string::npos) {
        result.error = std::make_error_code(std::errc::invalid_argument);
        return result;
    }
    const std::filesystem::path path(filename);
    const auto status = std::filesystem::status(path, result.error);
    result.type = status.type();
    result.permissions = status.permissions();
    if (result.error || result.type != std::filesystem::file_type::regular) return result;
    result.modified = std::filesystem::last_write_time(path, result.error);
    if (!result.error) result.size = std::filesystem::file_size(path, result.error);
    return result;
}
struct ServerBundle {
    SharedContext fallback;
    // A null entry deliberately fails only the SNI name with broken credentials.
    std::map<std::string, SharedContext> names;
};
using PairPaths = std::pair<std::string, std::string>;
struct CachedPair {
    std::pair<FileStamp, FileStamp> stamps;
    SharedContext context;
    std::exception_ptr error;
    bool loaded = false;
};
struct CachedServer {
    std::string configuration;
    std::map<PairPaths, CachedPair> pairs;
    std::shared_ptr<const ServerBundle> bundle;
};
using ServernameCallback = int (*)(SSL*, int*, void*);
std::shared_ptr<const ServerBundle> server_bundle(const Config& config, ServernameCallback callback) {
    const PairPaths fallback{config.values.value("tls_certificate", std::string{}),
                             config.values.value("tls_private_key", std::string{})};
    Json names = Json::object();
    if (const auto it = config.values.find("domain_tls"); it != config.values.end() && it->is_object()) names = *it;
    const auto key = Json::array({fallback.first, fallback.second, names}).dump();
    // Only preparation workers touch this bounded LRU. Published bundles and
    // SSL_CTX objects are never mutated; in-flight connections retain snapshots.
    static std::mutex mutex;
    static std::list<CachedServer> cache;
    const std::lock_guard lock(mutex);
    auto found = std::find_if(cache.begin(), cache.end(), [&](const auto& entry) { return entry.configuration == key; });
    if (found == cache.end()) {
        cache.push_front({key, {}, {}});
        if (cache.size() > 4) cache.pop_back();
    } else cache.splice(cache.begin(), cache, found);
    auto& entry = cache.front();
    bool changed = !entry.bundle;
    // Metadata is checked on every preparation, without a TTL. An unchanged
    // certificate/key pair is not reopened or reparsed, even across many names.
    std::map<std::string, FileStamp> stamps;
    auto stamp = [&](const std::string& path) -> const FileStamp& {
        const auto [it, inserted] = stamps.try_emplace(path);
        if (inserted) it->second = file_stamp(path);
        return it->second;
    };
    auto prepare = [&](const PairPaths& paths) -> CachedPair& {
        auto& pair = entry.pairs[paths];
        const auto current = std::make_pair(stamp(paths.first), stamp(paths.second));
        if (!pair.loaded || pair.stamps != current) {
            changed = true;
            // A failed refresh must never leave the preceding bundle reusable.
            entry.bundle.reset();
            pair = {current, {}, {}, true};
            try {
                if (current.first.error || current.second.error ||
                    current.first.type != std::filesystem::file_type::regular ||
                    current.second.type != std::filesystem::file_type::regular)
                    throw std::runtime_error("cannot inspect TLS certificate/private key");
                auto prepared = server_context(paths.first, paths.second);
                if (!names.empty()) {
                    // The shared callback retrieves per-connection state from
                    // SSL app_data; it never retains a connection argument.
                    SSL_CTX_set_tlsext_servername_callback(prepared.get(), callback);
                    SSL_CTX_set_session_cache_mode(prepared.get(), SSL_SESS_CACHE_OFF);
                    SSL_CTX_set_options(prepared.get(), SSL_OP_NO_TICKET);
                    if (SSL_CTX_set_num_tickets(prepared.get(), 0) != 1) tls_error("cannot disable TLS session tickets");
                }
                pair.context = SharedContext(std::move(prepared));
            } catch (...) { pair.error = std::current_exception(); }
        }
        return pair;
    };
    const auto& primary = prepare(fallback);
    if (primary.error) std::rethrow_exception(primary.error);
    auto bundle = std::make_shared<ServerBundle>();
    bundle->fallback = primary.context;
    for (const auto& item : names.items()) {
        SharedContext selected;
        try {
            selected = prepare({item.value().at("tls_certificate").get<std::string>(),
                                item.value().at("tls_private_key").get<std::string>()}).context;
        } catch (const Json::exception&) { /* Keep invalid optional entries isolated. */ }
        bundle->names.emplace(item.key(), std::move(selected));
    }
    if (changed) entry.bundle = std::move(bundle);
    return entry.bundle;
}
bool interrupted() noexcept {
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}
bool would_block() noexcept {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

// Adapted from PACE's socket BIO to preserve pointer-width Windows handles and
// SIGPIPE-safe POSIX writes. Copyright (c) 2026 Tab Nahida.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
int bio_read(BIO* bio, char* bytes, int size) {
    BIO_clear_retry_flags(bio);
    if (!bytes || size <= 0) return 0;
    const auto fd = static_cast<pace::tcp::stream*>(BIO_get_data(bio))->native_handle();
    int result;
    do { result = static_cast<int>(::recv(fd, bytes, size, 0)); } while (result < 0 && interrupted());
    if (result < 0 && would_block()) BIO_set_retry_read(bio);
    return result;
}
int bio_write(BIO* bio, const char* bytes, int size) {
    BIO_clear_retry_flags(bio);
    if (!bytes || size <= 0) return 0;
    const auto fd = static_cast<pace::tcp::stream*>(BIO_get_data(bio))->native_handle();
#ifdef MSG_NOSIGNAL
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;
#endif
    int result;
    do { result = static_cast<int>(::send(fd, bytes, size, flags)); } while (result < 0 && interrupted());
    if (result < 0 && would_block()) BIO_set_retry_write(bio);
    return result;
}
BIO_METHOD* socket_method() {
    static const auto method = [] {
        std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> result(
            BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "PostPlus PACE socket"), BIO_meth_free);
        if (!result || !BIO_meth_set_read(result.get(), bio_read) || !BIO_meth_set_write(result.get(), bio_write) ||
            !BIO_meth_set_create(result.get(), [](BIO* bio) { BIO_set_init(bio, 1); return 1; }) ||
            !BIO_meth_set_destroy(result.get(), [](BIO*) { return 1; }) ||
            !BIO_meth_set_ctrl(result.get(), [](BIO*, int command, long, void*) -> long {
                return command == BIO_CTRL_FLUSH ? 1 : 0;
            })) tls_error("cannot create socket BIO");
        return result;
    }();
    return method.get();
}
}

struct TlsStream::Impl {
    pace::tcp::stream& transport;
    SharedContext configuration;
    std::shared_ptr<const ServerBundle> server;
    std::shared_ptr<X509> pinned;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
    bool client = false, handshaken = false, busy = false;

    explicit Impl(pace::tcp::stream& value) : transport(value) {}
    void active() const {
        if (transport.context().stopped()) throw std::system_error(std::make_error_code(std::errc::operation_canceled));
        if (!transport.is_open()) throw std::system_error(std::make_error_code(std::errc::bad_file_descriptor));
        if (pace::io_context::current() != &transport.context())
            throw std::logic_error("TLS operation must run on the transport reactor");
        if (!ssl) throw std::logic_error("TLS is not configured");
    }
    struct Operation {
        Impl& state;
        explicit Operation(Impl& value, bool require_handshake = true) : state(value) {
            state.active();
            if (state.busy) throw std::logic_error("concurrent TLS operations are unsupported");
            if (require_handshake && !state.handshaken) throw std::logic_error("TLS handshake is incomplete");
            state.busy = true;
        }
        ~Operation() { state.busy = false; }
    };
    void initialize(SharedContext value, bool is_client) {
        if (ssl) throw std::logic_error("TLS is already configured");
        configuration = std::move(value);
        client = is_client;
        ssl.reset(SSL_new(configuration.get()));
        if (!ssl) tls_error("cannot create TLS stream");
        SSL_set_app_data(ssl.get(), this);
        auto* bio = BIO_new(socket_method());
        if (!bio) tls_error("cannot create TLS socket BIO");
        BIO_set_data(bio, &transport);
        SSL_set_bio(ssl.get(), bio, bio);
        if (client) SSL_set_connect_state(ssl.get()); else SSL_set_accept_state(ssl.get());
    }
    pace::task<void> wait(int error) {
        if (error == SSL_ERROR_WANT_READ) co_await transport.context().wait_readable(transport.native_handle());
        else if (error == SSL_ERROR_WANT_WRITE) co_await transport.context().wait_writable(transport.native_handle());
        else tls_error("TLS operation failed");
    }
    static int select_certificate(SSL* connection, int* alert, void*) noexcept {
        auto* self = static_cast<Impl*>(SSL_get_app_data(connection));
        if (!self || !self->server) { *alert = SSL_AD_INTERNAL_ERROR; return SSL_TLSEXT_ERR_ALERT_FATAL; }
        const auto* requested = SSL_get_servername(connection, TLSEXT_NAMETYPE_host_name);
        if (!requested) return SSL_TLSEXT_ERR_NOACK;
        try {
            std::string name(requested);
            for (auto& c : name) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            if (name.ends_with('.')) name.pop_back();
            const auto entry = self->server->names.find(name);
            if (entry == self->server->names.end()) return SSL_TLSEXT_ERR_NOACK;
            if (!entry->second || !SSL_set_SSL_CTX(connection, entry->second.get())) {
                *alert = SSL_AD_INTERNAL_ERROR;
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            return SSL_TLSEXT_ERR_OK;
        } catch (...) {
            *alert = SSL_AD_INTERNAL_ERROR;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }
    static int verify_pin(int, X509_STORE_CTX* verification) noexcept {
        auto* connection = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(verification, SSL_get_ex_data_X509_STORE_CTX_idx()));
        auto* self = connection ? static_cast<Impl*>(SSL_get_app_data(connection)) : nullptr;
        if (!self || !self->pinned) return 0;
        if (X509_STORE_CTX_get_error_depth(verification) != 0) return 1;
        const auto* presented = X509_STORE_CTX_get_current_cert(verification);
        return presented && X509_cmp(self->pinned.get(), presented) == 0;
    }
};

TlsStream::TlsStream(pace::tcp::stream& transport) : impl_(std::make_unique<Impl>(transport)) {}
TlsStream::~TlsStream() = default;
void TlsStream::configure_server(const Config& config) {
    impl_->server = server_bundle(config, Impl::select_certificate);
    impl_->initialize(impl_->server->fallback, false);
}
void TlsStream::configure_client(const std::string& hostname) {
    if (hostname.empty() || hostname.find('\0') != std::string::npos)
        throw std::invalid_argument("TLS peer name is required");
    auto configuration = context(false);
    (void)SSL_CTX_set_default_verify_paths(configuration.get());
    add_platform_trust_roots(SSL_CTX_get_cert_store(configuration.get()));
    ERR_clear_error();
    SSL_CTX_set_verify(configuration.get(), SSL_VERIFY_PEER, nullptr);
    impl_->initialize(std::move(configuration), true);
    auto* parameters = SSL_get0_param(impl_->ssl.get());
    // Preserve asio::ssl::host_name_verification's X509_check_host(flags = 0).
    X509_VERIFY_PARAM_set_hostflags(parameters, 0);
    unsigned char address[16];
    if (::inet_pton(AF_INET, hostname.c_str(), address) == 1 || ::inet_pton(AF_INET6, hostname.c_str(), address) == 1) {
        if (X509_VERIFY_PARAM_set1_ip_asc(parameters, hostname.c_str()) != 1) tls_error("cannot set TLS peer IP");
    } else if (SSL_set1_host(impl_->ssl.get(), hostname.c_str()) != 1) tls_error("cannot set TLS peer hostname");
    if (SSL_set_tlsext_host_name(impl_->ssl.get(), hostname.c_str()) != 1) tls_error("cannot set TLS SNI");
}
void TlsStream::configure_pinned(const std::string& certificate_file) {
    const std::filesystem::path path(certificate_file);
    require_plain_path(path);
    if (std::filesystem::file_size(path) > 1024 * 1024) throw std::runtime_error("readiness certificate is too large");
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot read readiness certificate");
    const std::string pem{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!input) tls_error("cannot read readiness certificate");
    impl_->pinned.reset(PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
    if (!impl_->pinned) tls_error("invalid readiness certificate");
    auto configuration = context(false);
    SSL_CTX_set_verify(configuration.get(), SSL_VERIFY_PEER, Impl::verify_pin);
    impl_->initialize(std::move(configuration), true);
}
pace::task<void> TlsStream::handshake() {
    Impl::Operation guard(*impl_, false);
    if (impl_->handshaken) throw std::logic_error("TLS handshake already completed");
    for (;;) {
        impl_->active();
        ERR_clear_error();
        const auto result = SSL_do_handshake(impl_->ssl.get());
        if (result == 1) {
            if (impl_->client && !impl_->pinned && SSL_get_verify_result(impl_->ssl.get()) != X509_V_OK)
                tls_error("TLS peer verification failed");
            impl_->handshaken = true;
            co_return;
        }
        co_await impl_->wait(SSL_get_error(impl_->ssl.get(), result));
    }
}
pace::task<std::size_t> TlsStream::read_some(std::span<char> bytes) {
    Impl::Operation guard(*impl_);
    if (bytes.empty()) co_return 0;
    for (;;) {
        impl_->active();
        ERR_clear_error();
        std::size_t received = 0;
        const auto result = SSL_read_ex(impl_->ssl.get(), bytes.data(), bytes.size(), &received);
        if (result == 1) co_return received;
        const auto error = SSL_get_error(impl_->ssl.get(), result);
        if (error == SSL_ERROR_ZERO_RETURN) co_return 0;
        co_await impl_->wait(error);
    }
}
pace::task<void> TlsStream::write_all(std::string_view bytes) {
    Impl::Operation guard(*impl_);
    while (!bytes.empty()) {
        impl_->active();
        ERR_clear_error();
        std::size_t written = 0;
        const auto result = SSL_write_ex(impl_->ssl.get(), bytes.data(), bytes.size(), &written);
        if (result == 1) { bytes.remove_prefix(written); continue; }
        co_await impl_->wait(SSL_get_error(impl_->ssl.get(), result));
    }
}
pace::task<void> TlsStream::wait_readable() {
    Impl::Operation guard(*impl_);
    char byte{};
    for (;;) {
        impl_->active();
        ERR_clear_error();
        std::size_t received = 0;
        const auto result = SSL_peek_ex(impl_->ssl.get(), &byte, 1, &received);
        if (result == 1) co_return;
        const auto error = SSL_get_error(impl_->ssl.get(), result);
        if (error == SSL_ERROR_ZERO_RETURN) co_return;
        co_await impl_->wait(error);
    }
}
}

