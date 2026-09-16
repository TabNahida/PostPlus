#include <postplus/trust.hpp>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace postplus {
void add_platform_trust_roots(X509_STORE* store) {
    if (!store) return;
#ifdef _WIN32
    HCERTSTORE roots = CertOpenSystemStoreW(0, L"ROOT");
    if (!roots) return;
    PCCERT_CONTEXT entry = nullptr;
    while ((entry = CertEnumCertificatesInStore(roots, entry)) != nullptr) {
        const unsigned char* bytes = entry->pbCertEncoded;
        if (X509* certificate = d2i_X509(nullptr, &bytes, static_cast<long>(entry->cbCertEncoded))) {
            (void)X509_STORE_add_cert(store, certificate);
            X509_free(certificate);
        }
    }
    CertCloseStore(roots, 0);
#elif defined(__APPLE__)
    CFArrayRef roots = nullptr;
    if (SecTrustCopyAnchorCertificates(&roots) != errSecSuccess || !roots) return;
    for (CFIndex index = 0; index < CFArrayGetCount(roots); ++index) {
        auto certificate = static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(roots, index)));
        CFDataRef der = SecCertificateCopyData(certificate);
        if (!der) continue;
        const unsigned char* bytes = CFDataGetBytePtr(der);
        if (X509* parsed = d2i_X509(nullptr, &bytes, static_cast<long>(CFDataGetLength(der)))) {
            (void)X509_STORE_add_cert(store, parsed);
            X509_free(parsed);
        }
        CFRelease(der);
    }
    CFRelease(roots);
#endif
}
}
