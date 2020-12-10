#ifndef __NKN_HASH_H__
#define __NKN_HASH_H__

#include <string>
#include <vector>

extern "C" {
#include <openssl/evp.h>
#include <openssl/kdf.h>
}

#include "include/uBigInt.h"

using namespace std;

namespace NKN{
    struct HASH {
        inline HASH(const string& name) : HASH(name.c_str()) {}
        HASH(const char* name) : algo(name), ctx(EVP_MD_CTX_new()), closed(false) {
            if (const EVP_MD* md = EVP_get_digestbyname(name))
                EVP_DigestInit_ex(ctx, md, NULL);
            else {
                closed = true;
                std::cerr << "EVP_get_digestbyname NOT found such algo: " << std::string(name) << std::endl;
                // TODO throw
            }
        }
        inline ~HASH() { EVP_MD_CTX_free(ctx); }

        // write method
        inline bool write(const void* msg, size_t n);
        inline bool write(const uint8_t c) { return write(&c, sizeof(uint8_t)); }
        template<template<typename...>class C, typename... Args>
        inline bool write(C<Args...> msg)  { return write(msg.data(), msg.size()); };

        // read method
        template<template<typename...>class C, typename... Args>
        C<Args...> read();  // template read() for general dynamic size container

        template<template<size_t>class Uint, size_t N>
        Uint<N> read();     // template read() for uBigInt<N>

        template<template <typename> class Ptr, template<size_t> class Uint, size_t N>
        Ptr<Uint<N>> read();// template read() for shared_ptr<uBigInt<N>>

    private:
        string algo;
        EVP_MD_CTX* ctx;
        bool closed;

        uint32_t _flush(void* buf);
    };

    inline bool HASH::write(const void* msg, size_t n) {
        if (closed) {/* TODO throw */}
        return EVP_DigestUpdate(ctx, msg, n) == 1;
    }

    template<template<typename...>class C, typename... Args>
    C<Args...> HASH::read() {
        uint8_t buf[EVP_MAX_MD_SIZE];
        uint32_t md_len = _flush(buf);
        return C<Args...>(buf, buf+md_len);
    }

    template<template<size_t>class Uint, size_t N>
    Uint<N> HASH::read() {
        char buf[EVP_MAX_MD_SIZE];
        uint32_t md_len = _flush(buf);
        return Uint<N>(buf, md_len, Uint<N>::BINARY);
    }

    template<template <typename> class Ptr, template<size_t> class Uint, size_t N>
    Ptr<Uint<N>> HASH::read() {
        char buf[EVP_MAX_MD_SIZE];
        uint32_t md_len = _flush(buf);
        return make_shared<Uint<N>>((const char*)buf, md_len, Uint<N>::BINARY);
    }

    // Dump hash result to buf and mark closed
    inline uint32_t HASH::_flush(void* buf) {
        uint32_t md_len = 0;

        if (closed) {/* TODO throw */}

        closed = true;
        if (int err = EVP_DigestFinal_ex(ctx, (uint8_t*)buf, &md_len) != 1 ) {
            fprintf(stderr, "%s:%d DigestFinal fail %d\n", __PRETTY_FUNCTION__, __LINE__, err);
            // TODO throw
        }
        return md_len;
    }
};  // namespace NKN

#endif // __NKN_HASH_H__
