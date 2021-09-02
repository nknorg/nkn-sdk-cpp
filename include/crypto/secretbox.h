#ifndef __NKN_SECRETBOX_H__
#define __NKN_SECRETBOX_H__
#include <memory>
#include <string>
#include <cassert>

#include <sodium.h>

#include "include/crypto/hex.h"
#include "include/uBigInt.h"

using namespace std;

namespace NKN {
namespace SecretBox {

template <template<typename...>class C, typename CharT, class _Traits = char_traits<CharT>>
shared_ptr<C<CharT>> Encrypt(const C<CharT>& msg, shared_ptr<Uint256> key, shared_ptr<Uint192>nonce=nullptr) {
    auto ret = make_shared<C<CharT>>(msg.length()+crypto_secretbox_MACBYTES, 0);    // pre-alloc enough space

    auto k = key->toBytes();
    auto n = nonce ? nonce->toBytes() : string(crypto_secretbox_NONCEBYTES, 0);
    if (!nonce)
        randombytes_buf((uint8_t*)n.data(), n.length());

    int err = crypto_secretbox_easy((uint8_t*)(ret->data()), (uint8_t*)msg.data(),
            msg.length(), (uint8_t*)n.data(), (uint8_t*)k.data());

    if (err) {
        cerr << "secretbox::Encrypt met error:" << err << endl;
        //TODO throw
        return nullptr;
    }
    return ret;
}

template <template<typename...>class C, typename CharT, class _Traits = char_traits<CharT>>
shared_ptr<C<CharT>> Encrypt(uint8_t* msg, size_t len, shared_ptr<Uint256> key, shared_ptr<Uint192>nonce=nullptr) {
    auto ret = make_shared<C<CharT>>(len+crypto_secretbox_MACBYTES, 0);    // pre-alloc enough space

    auto k = key->toBytes();
    auto n = nonce ? nonce->toBytes() : string(crypto_secretbox_NONCEBYTES, 0);
    if (!nonce)
        randombytes_buf((uint8_t*)n.data(), n.length());

    int err = crypto_secretbox_easy((uint8_t*)(ret->data()), msg, len, (uint8_t*)n.data(), (uint8_t*)k.data());

    if (err) {
        cerr << "secretbox::Encrypt met error:" << err << endl;
        //TODO throw
        return nullptr;
    }
    return ret;
}

template <template<typename...>class C, typename CharT, class _Traits = char_traits<CharT>>
shared_ptr<C<CharT>> Decrypt(const C<CharT>& cipher, shared_ptr<Uint256> key, shared_ptr<Uint192>nonce) {
    shared_ptr<C<CharT>> plain = make_shared<C<CharT>>(cipher.length()-crypto_secretbox_MACBYTES, 0);
    auto k = key->toBytes();
    auto n = nonce->toBytes();

    int err = crypto_secretbox_open_easy((uint8_t*)(plain->data()), (uint8_t*)cipher.data(),
            cipher.length(), (uint8_t*)n.data(), (uint8_t*)k.data());

    if (err) {
        cerr << "secretbox::Decrypt met error:" << err << endl;
        //TODO throw
        return nullptr;
    }
    return plain;
}

template <template<typename...>class C, typename CharT, class _Traits = char_traits<CharT>>
shared_ptr<C<CharT>> Decrypt(uint8_t* cipher, size_t len, shared_ptr<Uint256> key, shared_ptr<Uint192>nonce) {
    assert(cipher != nullptr);

    shared_ptr<C<CharT>> plain = make_shared<C<CharT>>(len-crypto_secretbox_MACBYTES, 0);
    auto k = key->toBytes();
    auto n = nonce->toBytes();

    int err = crypto_secretbox_open_easy((uint8_t*)(plain->data()), cipher, len, (uint8_t*)n.data(), (uint8_t*)k.data());

    if (err) {
        cerr << "secretbox::Decrypt met error:" << err << endl;
        //TODO throw
        return nullptr;
    }
    return plain;
}

template <typename T> const T Precompute(const Uint256& peerCurvePub, const Uint256& myCurvePriv);
template<>
const shared_ptr<vector<uint8_t>> Precompute<shared_ptr<vector<uint8_t>>>(const Uint256& peerCurvePub, const Uint256& myCurvePriv) {
    const string peer = peerCurvePub.toBytes();
    const string me   = myCurvePriv.toBytes();
    auto shareKey = make_shared<vector<uint8_t>>(crypto_scalarmult_curve25519_BYTES, 0);

    int err = crypto_box_beforenm(shareKey->data(), (uint8_t*)(peer.data()), (uint8_t*)(me.data()));
    if (err) {
        //TODO throw
        cerr << "secretbox::Precompute met error:" << err << endl;
        return nullptr;
    }
    return shareKey;
}
template<>
inline const shared_ptr<Uint256> Precompute<shared_ptr<Uint256>>(const Uint256& peerCurvePub, const Uint256& myCurvePriv) {
    return make_shared<Uint256>(*Precompute<shared_ptr<vector<uint8_t>>>(peerCurvePub, myCurvePriv));
}

};  // namespace SecretBox
};  // namespace NKN
#endif // __NKN_SECRETBOX_H__
