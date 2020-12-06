#ifndef __NKN_AES_H__
#define __NKN_AES_H__

#include "include/crypto/crypto.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/kdf.h>
}

using namespace std;

namespace NKN {
typedef Uint128 AES_IV_t;
typedef Uint256 AES_Key_t;

struct _Base {
    const string algo;
    const string key_str;
    const string iv_str;
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER* cipher;

    _Base(const AES_Key_t& key, const AES_IV_t& iv, const char* name="aes-256-cbc")
        : algo(name), key_str(key.toBytes()), iv_str(iv.toBytes()), ctx(EVP_CIPHER_CTX_new()) {
            cipher = EVP_get_cipherbyname(name);
            if (cipher == NULL) {
                fprintf(stderr, "EVP_get_cipherbyname(%s) result %p\n", name, cipher);
                // TODO throw
            }
        }
    ~_Base() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
};

// match all template
template<typename Any> struct AES;

// partial specialization for generalize dynamic size container
template <template<typename...> class Container, typename... Args>
struct AES<Container<Args...>>: public _Base {
    AES<Container<Args...>>(const AES_Key_t& key, const AES_IV_t& iv, const char* name="aes-256-cbc") : _Base(key,iv,name) {}

    Container<Args...> Enc(const char* plaintext, size_t len);  // To be implement if required in future
    Container<Args...> Enc(const Container<Args...>& plaintext) { return Enc((const char*)plaintext.data(), plaintext.size()); }

    Container<Args...> Dec(const char* ciphertext, size_t len);  // To be implement if required in future
    Container<Args...> Dec(const Container<Args...>& ciphertext){ return Dec((const char*)ciphertext.data(), ciphertext.size()); }
};

// partial specialization for shared_ptr of general container
template <template<typename...> class C, typename... Args>
struct AES<shared_ptr<C<Args...>>>: public _Base {
    AES<shared_ptr<C<Args...>>>(const AES_Key_t& key, const AES_IV_t& iv, const char* name="aes-256-cbc") : _Base(key,iv,name) {}

    shared_ptr<C<Args...>> Enc(const char* plaintext, size_t len);  // To be implement if required in future
    shared_ptr<C<Args...>> Enc(const C<Args...>& plaintext)  { return Enc((const char*)plaintext.data(), plaintext.size()); }

    shared_ptr<C<Args...>> Dec(const char* ciphertext, size_t len);  // To be implement if required in future
    shared_ptr<C<Args...>> Dec(const C<Args...>& ciphertext) { return Dec((const char*)ciphertext.data(), ciphertext.size()); }
};

// partial specialization for std::array
template <typename T, size_t N>
struct AES<array<T,N>>: public _Base {
    AES<array<T,N>>(const AES_Key_t& key, const AES_IV_t& iv, const char* name="aes-256-cbc") : _Base(key,iv,name) {}

    array<T,N> Enc(const char* plaintext, size_t len);  // To be implement if required in future
    array<T,N> Enc(const string& plaintext)          { return Enc(plaintext.c_str(), plaintext.size()); }
    array<T,N> Enc(const vector<uint8_t>& plaintext) { return Enc((const char*)plaintext.data(), plaintext.size()); }

    array<T,N> Dec(const char* ciphertext, size_t len);  // To be implement if required in future
    array<T,N> Dec(const string& ciphertext)         { return Dec(ciphertext.c_str(), ciphertext.size()); }
    array<T,N> Dec(const vector<uint8_t> ciphertext) { return Dec((const char*)ciphertext.data(), ciphertext.size()); }
};

// partial specialization for uBigInt<N>
template <size_t N>
struct AES<uBigInt<N>>: public _Base {
    AES<uBigInt<N>>(const AES_Key_t& key, const AES_IV_t& iv, const char* name="aes-256-cbc") : _Base(key,iv,name) {}

    uBigInt<N> Enc(const char* plaintext, size_t len);
    uBigInt<N> Enc(const string& plaintext)          { return Enc(plaintext.c_str(), plaintext.size()); }
    uBigInt<N> Enc(const vector<uint8_t>& plaintext) { return Enc((const char*)plaintext.data(), plaintext.size()); }
    uBigInt<N> Enc(const uBigInt<N>& plaintext)      { return Enc(plaintext.toBytes().c_str(), N/8); }

    uBigInt<N> Dec(const char* ciphertext, size_t len);
    uBigInt<N> Dec(const string& ciphertext)         { return Dec(ciphertext.c_str(), ciphertext.size()); }
    uBigInt<N> Dec(const vector<uint8_t> ciphertext) { return Dec((const char*)ciphertext.data(), ciphertext.size()); }
    uBigInt<N> Dec(const uBigInt<N>& ciphertext)     { return Dec(ciphertext.toBytes().c_str(), N/8); }
};

// partial specialization for shared_ptr of uBigInt<N>
template <size_t N>
struct AES<shared_ptr<uBigInt<N>>>: public _Base {
    AES<shared_ptr<uBigInt<N>>>(const AES_Key_t& key, const AES_IV_t& iv, const char* name="aes-256-cbc") : _Base(key,iv,name) {}

    shared_ptr<uBigInt<N>> Enc(const char* plaintext, size_t len);  // To be implement if required in future
    shared_ptr<uBigInt<N>> Enc(const string& plaintext)         { return Enc(plaintext.c_str(), plaintext.size()); }
    shared_ptr<uBigInt<N>> Enc(const vector<uint8_t> plaintext) { return Enc((const char*)plaintext.data(), plaintext.size()); }
    shared_ptr<uBigInt<N>> Enc(const uBigInt<N>& plaintext)     { return Enc(plaintext.toBytes().c_str(), N/8); }

    shared_ptr<uBigInt<N>> Dec(const char* ciphertext, size_t len);  // To be implement if required in future
    shared_ptr<uBigInt<N>> Dec(const string& ciphertext)         { return Dec(ciphertext.c_str(), ciphertext.size()); }
    shared_ptr<uBigInt<N>> Dec(const vector<uint8_t> ciphertext) { return Dec((const char*)ciphertext.data(), ciphertext.size()); }
    shared_ptr<uBigInt<N>> Dec(const uBigInt<N>& ciphertext)     { return Dec(ciphertext.toBytes().c_str(), N/8); }
};

template <size_t N>
uBigInt<N> AES<uBigInt<N>>::Enc(const char* plaintext, size_t len) {
    // TODO check len % BLOCK_SIZE == 0

    int outl=0, padding_len=0;
    uint8_t buf[len+EVP_MAX_BLOCK_LENGTH], *p=buf;

    bool ok = EVP_EncryptInit_ex(ctx, cipher, NULL, (const uint8_t*)key_str.c_str(), (const uint8_t*)iv_str.c_str()) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_EncryptUpdate(ctx, p, &outl, (const uint8_t*)plaintext, len) == 1;

    if (!ok) {/*TODO*/}

    p += outl;
    if (EVP_EncryptFinal_ex(ctx, p, &padding_len) != 1) {
        // TODO log error
    }
    p += padding_len;
    assert(p < &buf[len+EVP_MAX_BLOCK_LENGTH]);    // outl out of bound if assert false

    return uBigInt<N>((const char*)buf, p-buf, uBigInt<N>::BINARY);
}

template <size_t N>
uBigInt<N> AES<uBigInt<N>>::Dec(const char* ciphertext, size_t len) {
    // TODO check len % BLOCK_SIZE == 0

    int outl=0, padding_len=0;
    uint8_t buf[len+EVP_MAX_BLOCK_LENGTH], *p=buf;

    bool ok = EVP_DecryptInit_ex(ctx, cipher, NULL, (const uint8_t*)key_str.c_str(), (const uint8_t*)iv_str.c_str()) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_DecryptUpdate(ctx, p, &outl, (const uint8_t*)ciphertext, len) == 1;

    if (!ok) {/*TODO*/}

    p += outl;
    if (EVP_DecryptFinal_ex(ctx, p, &padding_len) != 1) {
        // TODO log error
    }
    p += padding_len;
    assert(p < &buf[len+EVP_MAX_BLOCK_LENGTH]);    // outl out of bound if assert false

    return uBigInt<N>((const char*)buf, p-buf, uBigInt<N>::BINARY);
}

template <size_t N>
shared_ptr<uBigInt<N>> AES<shared_ptr<uBigInt<N>>>::Enc(const char* plaintext, size_t len) {
    // TODO check len % BLOCK_SIZE == 0

    int outl=0, padding_len=0;
    uint8_t buf[len+EVP_MAX_BLOCK_LENGTH], *p=buf;

    bool ok = EVP_EncryptInit_ex(ctx, cipher, NULL, (const uint8_t*)key_str.c_str(), (const uint8_t*)iv_str.c_str()) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_EncryptUpdate(ctx, p, &outl, (const uint8_t*)plaintext, len) == 1;

    if (!ok) {/*TODO*/}

    p += outl;
    if (EVP_EncryptFinal_ex(ctx, p, &padding_len) != 1) {
        // TODO log error
    }
    p += padding_len;
    assert(p < &buf[len+EVP_MAX_BLOCK_LENGTH]);    // outl out of bound if assert false

    return make_shared<uBigInt<N>>((const char*)buf, p-buf, uBigInt<N>::BINARY);
}

template <size_t N>
shared_ptr<uBigInt<N>> AES<shared_ptr<uBigInt<N>>>::Dec(const char* ciphertext, size_t len) {
    // TODO check len % BLOCK_SIZE == 0

    int outl=0, padding_len=0;
    uint8_t buf[len+EVP_MAX_BLOCK_LENGTH], *p=buf;

    bool ok = EVP_DecryptInit_ex(ctx, cipher, NULL, (const uint8_t*)key_str.c_str(), (const uint8_t*)iv_str.c_str()) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_DecryptUpdate(ctx, p, &outl, (const uint8_t*)ciphertext, len) == 1;

    if (!ok) {/*TODO*/}

    p += outl;
    if (EVP_DecryptFinal_ex(ctx, p, &padding_len) != 1) {
        // TODO log error
    }
    p += padding_len;
    assert(p < &buf[len+EVP_MAX_BLOCK_LENGTH]);    // outl out of bound if assert false

    return make_shared<uBigInt<N>>((const char*)buf, p-buf, uBigInt<N>::BINARY);
}

};  // namespace NKN

#endif //__NKN_AES_H__
