#ifndef __NKN_XCHACHA20_H__
#define __NKN_XCHACHA20_H__

extern "C" {
#include <sodium.h>
}
#define HMAC_LEN crypto_aead_xchacha20poly1305_ietf_ABYTES

#include "include/uBigInt.h"

using namespace std;

namespace NKN {
namespace AEAD {

// match all template
template<typename Any> struct xchacha20_poly1305;

// partial specialization for generalize dynamic size container
template <template<typename...> class C, typename... Args>
struct xchacha20_poly1305<C<Args...>> {
    typedef typename C<Args...>::value_type _CharT;

    const Uint256 Key;
    const Uint192 Nonce;
    string Additional;

    xchacha20_poly1305<C<Args...>>(const Uint256& key=Uint256::Random<Uint256>(),
                                  const Uint192& nonce=Uint192::Random<Uint192>(),
                                  const string& additional={})
        : Key  (key   ? key   : Uint256::Random<Uint256>()),
          Nonce(nonce ? nonce : Uint192::Random<Uint192>()),
          Additional(additional) {}

    /************ Return Encrypted ************/
           C<Args...> Encrypt(const uint8_t* msg, size_t msgLen, uint8_t* mac=NULL);
    inline C<Args...> Encrypt(const uint8_t* msg, size_t msgLen, C<Args...>* mac);
    inline C<Args...> Encrypt(const C<Args...>& msg, uint8_t* mac=NULL);
    inline C<Args...> Encrypt(const C<Args...>& msg, C<Args...>* mac);

    /************ Encrypt to dest ************/
           int EncryptTo(const uint8_t* msg, size_t msgLen, uint8_t* dest, uint8_t* mac=NULL);
    inline int EncryptTo(const uint8_t* msg, size_t msgLen, uint8_t* dest, C<Args...>* mac);
    inline int EncryptTo(const uint8_t* msg, size_t msgLen, C<Args...>* dest, uint8_t* mac=NULL);
    inline int EncryptTo(const uint8_t* msg, size_t msgLen, C<Args...>* dest, C<Args...>* mac);
    inline int EncryptTo(const C<Args...>& msg, uint8_t* dest, uint8_t* mac=NULL);
    inline int EncryptTo(const C<Args...>& msg, uint8_t* dest, C<Args...>* mac);
    inline int EncryptTo(const C<Args...>& msg, C<Args...>* dest, uint8_t* mac=NULL);
    inline int EncryptTo(const C<Args...>& msg, C<Args...>* dest, C<Args...>* mac);

    /************ Return Decrypted plaintext ************/
           C<Args...> Decrypt(const uint8_t* ciphertext, size_t cLen, const uint8_t* mac=NULL);
    inline C<Args...> Decrypt(const uint8_t* ciphertext, size_t cLen, const C<Args...>* mac);
    inline C<Args...> Decrypt(const C<Args...>& ciphertext, const C<Args...>* mac);
    inline C<Args...> Decrypt(const C<Args...>& ciphertext, const uint8_t* mac=NULL);

    /************ Decrypt plaintext to dest ************/
           int DecryptTo(const uint8_t* ciphertext, size_t cLen, uint8_t* dest, const uint8_t* mac=NULL);
    inline int DecryptTo(const uint8_t* ciphertext, size_t cLen, uint8_t* dest, const C<Args...>* mac);
    inline int DecryptTo(const uint8_t* ciphertext, size_t cLen, C<Args...>* dest, const uint8_t* mac=NULL);
    inline int DecryptTo(const uint8_t* ciphertext, size_t cLen, C<Args...>* dest, const C<Args...>* mac);
    inline int DecryptTo(const C<Args...>& ciphertext, uint8_t* dest, const uint8_t* mac=NULL);
    inline int DecryptTo(const C<Args...>& ciphertext, uint8_t* dest, const C<Args...>* mac);
    inline int DecryptTo(const C<Args...>& ciphertext, C<Args...>* dest, const uint8_t* mac=NULL);
    inline int DecryptTo(const C<Args...>& ciphertext, C<Args...>* dest, const C<Args...>* mac);
};  // template xchacha20_poly1305<C<Args...>>

/********************
 * Return Encrypted *
 ****************** */
// Combined Mode Encrypt if mac==NULL, otherwise Detached Mode
// CAUTION: Caller MUST make sure enough space of mac if it not NULL
template <template<typename...> class C, typename... Args>
C<Args...> xchacha20_poly1305<C<Args...>>::Encrypt(const uint8_t* msg, size_t msgLen, uint8_t* mac) {
    const string key   = Key.toBytes();
    const string nonce = Nonce.toBytes();
    size_t adLen = Additional.size();
    uint8_t* adPtr = adLen ? (uint8_t*)Additional.data() : NULL;

    if (mac) {  // Detached Mode
        uint64_t mac_len;
        C<Args...> ret(msgLen, _CharT());
        int err = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                                (uint8_t*)(ret.data()), mac, &mac_len, msg, msgLen,
                                adPtr, adLen, NULL, (uint8_t*)nonce.data(), (uint8_t*)key.data());
        assert(mac_len == HMAC_LEN);
        return ret; } else {  // Combined Mode
        uint64_t encrypted_len;
        C<Args...> ret(msgLen+HMAC_LEN, _CharT());
        int err = crypto_aead_xchacha20poly1305_ietf_encrypt(
                                (uint8_t*)(ret.data()), &encrypted_len, msg, msgLen,
                                adPtr, adLen, NULL, (uint8_t*)nonce.data(), (uint8_t*)key.data());
        assert(encrypted_len == msgLen+HMAC_LEN); // ret.resize(encrypted_len);
        return ret;
    }
}
template <template<typename...> class C, typename... Args>
inline C<Args...> xchacha20_poly1305<C<Args...>>::Encrypt(const uint8_t* msg, size_t msgLen, C<Args...>* mac) {
    if (mac) {
        mac->resize(HMAC_LEN, _CharT());    // reset mac
        return Encrypt(msg, msgLen, (uint8_t*)mac->data());
    }
    return Encrypt(msg, msgLen);
}
template <template<typename...> class C, typename... Args>
inline C<Args...> xchacha20_poly1305<C<Args...>>::Encrypt(const C<Args...>& msg, uint8_t* mac) {
    return Encrypt((uint8_t*)msg.data(), msg.size(), mac);
}
template <template<typename...> class C, typename... Args>
inline C<Args...> xchacha20_poly1305<C<Args...>>::Encrypt(const C<Args...>& msg, C<Args...>* mac) {
    if (mac) {
        mac->resize(HMAC_LEN, _CharT());    // reset mac
        return Encrypt(msg, (uint8_t*)mac->data());
    }
    return Encrypt(msg);
}

/*******************
 * Encrypt to dest *
 *******************/
// Encrypt to dest. Combined Mode if mac==NULL, otherwise Detached Mode
// CAUTION: Caller MUST make sure dest and mac have enough space. dest must NOT NULL
template <template<typename...> class C, typename... Args>
int xchacha20_poly1305<C<Args...>>::EncryptTo(const uint8_t* msg, size_t msgLen, uint8_t* dest, uint8_t* mac) {
    const string key   = Key.toBytes();
    const string nonce = Nonce.toBytes();
    size_t adLen = Additional.size();
    uint8_t* adPtr = adLen ? (uint8_t*)Additional.data() : NULL;
    assert(dest!=NULL);

    int err;
    if (mac) {  // Detached Mode
        uint64_t mac_len;
        err = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                                dest, mac, &mac_len, msg, msgLen,
                                adPtr, adLen, NULL, (uint8_t*)nonce.data(), (uint8_t*)key.data());
        assert(mac_len == HMAC_LEN);
    } else {
        uint64_t encrypted_len;
        err = crypto_aead_xchacha20poly1305_ietf_encrypt(
                                dest, &encrypted_len, msg, msgLen,
                                adPtr, adLen, NULL, (uint8_t*)nonce.data(), (uint8_t*)key.data());
        assert(encrypted_len == msgLen+HMAC_LEN); // ret.resize(encrypted_len);
    }
    return err;
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::EncryptTo(const uint8_t* msg, size_t msgLen, uint8_t* dest, C<Args...>* mac) {
    if (mac) {
        mac->resize(HMAC_LEN, _CharT());    // reset mac
        return EncryptTo(msg, msgLen, dest, (uint8_t*)mac->data());
    }
    return EncryptTo(msg, msgLen, dest);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::EncryptTo(const uint8_t* msg, size_t msgLen, C<Args...>* dest, uint8_t* mac) {
    assert(dest!=NULL);

    size_t pos = dest->size();  // marked current pos before preAlloc
    size_t cnt = mac ? msgLen /*DetachedMode*/ : msgLen+HMAC_LEN /*CombinedMode*/;
    dest->insert(dest->end(), cnt, _CharT()); // preAlloc at end of dest
    return EncryptTo(msg, msgLen, (uint8_t*)(dest->data()+pos), mac);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::EncryptTo(const uint8_t* msg, size_t msgLen, C<Args...>* dest, C<Args...>* mac) {
    if (mac) {
        mac->resize(HMAC_LEN, _CharT());    // reset mac
        return EncryptTo(msg, msgLen, dest, (uint8_t*)mac->data());
    }
    return EncryptTo(msg, msgLen, dest);
}

template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::EncryptTo(const C<Args...>& msg, uint8_t* dest, uint8_t* mac) {
    return EncryptTo((uint8_t*)msg, msg.size(), dest, mac);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::EncryptTo(const C<Args...>& msg, uint8_t* dest, C<Args...>* mac) {
    return EncryptTo((uint8_t*)msg, msg.size(), dest, mac);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::EncryptTo(const C<Args...>& msg, C<Args...>* dest, uint8_t* mac) {
    return EncryptTo((uint8_t*)msg, msg.size(), dest, mac);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::EncryptTo(const C<Args...>& msg, C<Args...>* dest, C<Args...>* mac) {
    return EncryptTo((uint8_t*)msg, msg.size(), dest, mac);
}

/******************************
 * Return Decrypted plaintext *
 ******************************/
template <template<typename...> class C, typename... Args>
C<Args...> xchacha20_poly1305<C<Args...>>::Decrypt(const uint8_t* ciphertext, size_t cLen, const uint8_t* mac) {
    const string key   = Key.toBytes();
    const string nonce = Nonce.toBytes();
    size_t adLen = Additional.size();
    uint8_t* adPtr = adLen ? (uint8_t*)Additional.data() : NULL;

    int err;
    uint64_t decrypted_len;
    C<Args...> ret;
    if (mac) {  // Detached Mode
        ret.resize(cLen, _CharT());
        err = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                            (uint8_t*)(ret.data()), NULL, ciphertext, cLen, mac,
                            adPtr, adLen, (uint8_t*)nonce.data(), (uint8_t*)key.data());
    } else {    // Combined Mode
        ret.resize(cLen-HMAC_LEN, _CharT());
        err = crypto_aead_xchacha20poly1305_ietf_decrypt(
                            (uint8_t*)(ret.data()), &decrypted_len, NULL, ciphertext, cLen,
                            adPtr, adLen, (uint8_t*)nonce.data(), (uint8_t*)key.data());
        assert(decrypted_len == cLen-HMAC_LEN);
    }

    if (0 != err) {
        fprintf(stderr, "Decrypt: ciphertext is not consistent with hmac[%p], err=%d\n", mac, err);
        return C<Args...>();
    }
    return ret;
}
template <template<typename...> class C, typename... Args>
inline C<Args...> xchacha20_poly1305<C<Args...>>::Decrypt(const uint8_t* ciphertext, size_t cLen, const C<Args...>* mac) {
    return mac ? Decrypt(ciphertext, cLen, (const uint8_t*)(mac->data())) : Decrypt(ciphertext, cLen);
}
template <template<typename...> class C, typename... Args>
inline C<Args...> xchacha20_poly1305<C<Args...>>::Decrypt(const C<Args...>& ciphertext, const uint8_t* mac) {
    return Decrypt((uint8_t*)ciphertext.data(), ciphertext.size(), mac);
}
template <template<typename...> class C, typename... Args>
inline C<Args...> xchacha20_poly1305<C<Args...>>::Decrypt(const C<Args...>& ciphertext, const C<Args...>* mac) {
    return Decrypt((uint8_t*)ciphertext.data(), ciphertext.size(), mac);
}

/*****************************
 * Decrypt plaintext to dest *
 *****************************/
template <template<typename...> class C, typename... Args>
int xchacha20_poly1305<C<Args...>>::DecryptTo(const uint8_t* ciphertext, size_t cLen, uint8_t* dest, const uint8_t* mac) {
    const string key   = Key.toBytes();
    const string nonce = Nonce.toBytes();
    size_t adLen = Additional.size();
    uint8_t* adPtr = adLen ? (uint8_t*)Additional.data() : NULL;

    int err;
    uint64_t decrypted_len;
    if (mac) {  // Detached Mode
        err = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                            (uint8_t*)dest, NULL, ciphertext, cLen, mac,
                            adPtr, adLen, (uint8_t*)nonce.data(), (uint8_t*)key.data());
    } else {    // Combined Mode
        err = crypto_aead_xchacha20poly1305_ietf_decrypt(
                            (uint8_t*)dest, &decrypted_len, NULL, ciphertext, cLen,
                            adPtr, adLen, (uint8_t*)nonce.data(), (uint8_t*)key.data());
        assert(decrypted_len == cLen-HMAC_LEN);
    }

    if (0 != err) {
        fprintf(stderr, "DecryptTo: ciphertext is not consistent with hmac[%p], err=%d\n", mac, err);
    }
    return err;
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::DecryptTo(const uint8_t* ciphertext, size_t cLen, uint8_t* dest, const C<Args...>* mac) {
    return mac ? DecryptTo(ciphertext, cLen, dest, (const uint8_t*)(mac->data()))
                : DecryptTo(ciphertext, cLen, dest);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::DecryptTo(const uint8_t* ciphertext, size_t cLen, C<Args...>* dest, const uint8_t* mac) {
    assert(dest!=NULL);

    size_t pos = dest->size();  // marked current pos before preAlloc
    size_t cnt = mac ? cLen /*DetachedMode*/ : cLen-HMAC_LEN /*CombinedMode*/ ;
    dest->insert(dest->end(), cnt, _CharT()); // preAlloc at end of dest
    return DecryptTo(ciphertext, cLen, (uint8_t*)(dest->data()+pos), mac);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::DecryptTo(const uint8_t* ciphertext, size_t cLen, C<Args...>* dest, const C<Args...>* mac) {
    return mac ? DecryptTo(ciphertext, cLen, dest, (const uint8_t*)(mac->data()))
                : DecryptTo(ciphertext, cLen, dest);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::DecryptTo(const C<Args...>& ciphertext, uint8_t* dest, const uint8_t* mac) {
    return DecryptTo((uint8_t*)ciphertext, ciphertext.size(), dest, mac);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::DecryptTo(const C<Args...>& ciphertext, uint8_t* dest, const C<Args...>* mac) {
    return mac ? DecryptTo(ciphertext, dest, (const uint8_t*)(mac->data()))
                : DecryptTo(ciphertext, dest);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::DecryptTo(const C<Args...>& ciphertext, C<Args...>* dest, const uint8_t* mac) {
    return DecryptTo((uint8_t*)ciphertext.data(), ciphertext.size(), dest, mac);
}
template <template<typename...> class C, typename... Args>
inline int xchacha20_poly1305<C<Args...>>::DecryptTo(const C<Args...>& ciphertext, C<Args...>* dest, const C<Args...>* mac) {
    return mac ? DecryptTo(ciphertext, dest, (const uint8_t*)(mac->data()))
                : DecryptTo(ciphertext, dest);
}

};  // namespace AEAD
};  // namespace NKN

#endif // __NKN_XCHACHA20_H__
