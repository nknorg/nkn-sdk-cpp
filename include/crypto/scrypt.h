#ifndef __NKN_SCRYPT_H__
#define __NKN_SCRYPT_H__

extern "C" {
#include <openssl/evp.h>
#include <openssl/kdf.h>
}

#include "include/uBigInt.h"

namespace NKN {

typedef Uint64 Salt_t;

// match all template.
template<typename AnyType> struct SCRYPT;

// partial specialization for general dynamic size container which has push_back API
template <template<typename...> class C, typename... Args> struct SCRYPT<C<Args...>>;

// partial specialization for fixed size container
template <template<typename, size_t> class C, typename T, size_t N> struct SCRYPT<C<T,N>>;

// partial specialization for uBigInt<N>
template <size_t N>
struct SCRYPT<uBigInt<N>> {

    static uBigInt<N> KeyDerive(const std::string& pswd, const Salt_t& salt, int n, int r, int p) {
        uint8_t out[N/8];
        size_t  outlen = sizeof(out);
        std::string s = salt.toBytes();
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

        if (pctx != NULL) {
            bool ok = EVP_PKEY_derive_init(pctx) > 0
                && EVP_PKEY_CTX_set1_pbe_pass(pctx, pswd.c_str(), pswd.size()) > 0
                && EVP_PKEY_CTX_set1_scrypt_salt(pctx, s.c_str(), s.size()) > 0
                && EVP_PKEY_CTX_set_scrypt_N(pctx, n) > 0
                && EVP_PKEY_CTX_set_scrypt_r(pctx, r) > 0
                && EVP_PKEY_CTX_set_scrypt_p(pctx, p) > 0;

            if (ok) {
                int err = EVP_PKEY_derive(pctx, out, &outlen);
                if (err > 0) {  // success exit
                    // fprintf(stderr, "%s:%d Key derive success with len %lu\n", __PRETTY_FUNCTION__, __LINE__, outlen);
                    return uBigInt<N>((const char*)out, outlen, uBigInt<N>::BINARY);
                }
                fprintf(stderr, "%s:%d Key derive met error %d\n", __PRETTY_FUNCTION__, __LINE__, err);
            }
            fprintf(stderr, "%s:%d init fail\n", __PRETTY_FUNCTION__, __LINE__);
        }else
            fprintf(stderr, "%s:%d malloc EVP_PKEY context fail\n", __PRETTY_FUNCTION__, __LINE__);

        return uBigInt<N>(); // abnormal exit
    }
};

}; // namespace NKN

#endif // __NKN_SCRYPT_H__

