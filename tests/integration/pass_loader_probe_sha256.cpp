// Bare OpenSSL SHA256 call loaded by pass_loader_probe, with no HBFSim code.
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <cstring>

extern "C" int hbfsim_probe_sha256(const char* text, unsigned long length,
                                   unsigned char* digest)
{
    std::memset(digest, 0, SHA256_DIGEST_LENGTH);
    return SHA256(reinterpret_cast<const unsigned char*>(text), length, digest) ==
                   nullptr
               ? -1
               : 0;
}

extern "C" const char* hbfsim_probe_openssl_version()
{
    return OpenSSL_version(OPENSSL_VERSION);
}
