#ifndef __NKN_BASE58_H__
#define __NKN_BASE58_H__

#include <iostream>
#include <vector>
#include <array>

#include <gmpxx.h>

#include "include/uBigInt.h"

using namespace std;

namespace NKN {

constexpr char b58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// match all template.
template<typename AnyType> struct Base58;

// partial specialization for general dynamic size container which has push_back API
template <template<typename...> class C, typename... Args>
struct Base58<C<Args...>> {
    static const C<Args...> Enc(const mpz_class& m);
    template <size_t N>
    inline static const C<Args...> Enc(const uBigInt<N>& u) { return Enc(u.Value()); }
    // inline static const C<Args...> Enc(const string& s) { return Enc(s.data(), s.size()); } // C<Args...> is inclusive of string
    inline static const C<Args...> Enc(const C<Args...>& c) { return Enc(c.data(), c.size()); }
    inline static const C<Args...> Enc(const void* p, size_t len) {
        mpz_class n;
        mpz_import(n.get_mpz_t(), len, 1/*MSB*/, sizeof(uint8_t), 0/*endian*/, 0, p);
        return Enc(n);
    }

    static const C<Args...> Dec(const string& s);
};

// template implement for Base58<C<Args...>>::Enc
template <template<typename...> class C, typename... Args>
const C<Args...> Base58<C<Args...>>::Enc(const mpz_class& m) {
    assert(m>=0);    // NOT support negative number
    mpz_class q(m); // quotient of math division

    C<Args...> buf;
    do {
        unsigned long int r = mpz_fdiv_q_ui(q.get_mpz_t(), q.get_mpz_t(), 58L); // r = q % 58L, q %= 58L
        buf.insert(buf.begin(), b58_alphabet[r]);
    } while (q>0);

    return buf;
}

// template implement for Base58<C<Args...>>::Dec
template <template<typename...> class C, typename... Args>
const C<Args...> Base58<C<Args...>>::Dec(const string& s) {
    uint32_t idx = 0;
    mpz_class val, exp;
    const string alphabet(b58_alphabet);

    for (auto it=s.rbegin(); it!=s.rend(); it++, idx++) {
        auto n = alphabet.find(*it);

        if (n == string::npos) { /* TODO error log*/ break; }

        mpz_ui_pow_ui(exp.get_mpz_t(), 58L, idx);   // exp = 58L ** idx
        val += exp * n;
    }
    // for (auto& c: s)    // discarded. replace with rbegin for performance optimized
        // val = val*58L + alphabet.find(c);

    size_t cnt = 0;
    auto ret = make_shared<C<Args...>>( mpz_sizeinbase(val.get_mpz_t(), 16), 0 );   // new C<Args...>(size_t, 0)
    mpz_export((void*)ret->data(), &cnt, 1, sizeof(char), 0/*endian?*/, 0, val.get_mpz_t());
    ret->resize(cnt);
    return *ret;
}

// partial specialization for shared_ptr of general dynamic size container which has push_back API
template <template<typename...> class C, typename... Args>
struct Base58<shared_ptr<C<Args...>>> {
    static shared_ptr<C<Args...>> Enc(const mpz_class& m);
    template <size_t N>
    inline static shared_ptr<C<Args...>> Enc(const uBigInt<N>& u) { return Enc(u.Value()); }
    // inline static shared_ptr<C<Args...>> Enc(const string& s) { return Enc((const uint8_t*)s.data(), s.size()); }
    inline static shared_ptr<C<Args...>> Enc(const C<Args...>& c) { return Enc(c.data(), c.size()); }
    inline static shared_ptr<C<Args...>> Enc(const void* p, size_t len) {
        mpz_class n;
        mpz_import(n.get_mpz_t(), len, 1/*MSB*/, sizeof(uint8_t), 0/*endian*/, 0, p);
        return Enc(n);
    }

    static shared_ptr<C<Args...>> Dec(const string& s);
};

// template implement for Base58<shared_ptr<C<Args...>>>::Enc
template <template<typename...> class C, typename... Args>
shared_ptr<C<Args...>> Base58<shared_ptr<C<Args...>>>::Enc(const mpz_class& m) {
    assert(m>=0);    // NOT support negative number
    mpz_class q(m); // quotient of math division

    shared_ptr<C<Args...>> ret(new C<Args...>());
    do {
        unsigned long int r = mpz_fdiv_q_ui(q.get_mpz_t(), q.get_mpz_t(), 58L);
        ret->insert(ret->begin(), b58_alphabet[r]);
    } while (q>0);
    return ret;
}

// template implement for Base58<shared_ptr<C<Args...>>>::Dec
template <template<typename...> class C, typename... Args>
shared_ptr<C<Args...>> Base58<shared_ptr<C<Args...>>>::Dec(const string& s) {
    uint32_t idx = 0;
    mpz_class val, exp;
    const string alphabet(b58_alphabet);

    for (auto it=s.rbegin(); it!=s.rend(); it++, idx++) {
        auto n = alphabet.find(*it);

        if (n == string::npos) { /* TODO error log*/ break; }

        mpz_ui_pow_ui(exp.get_mpz_t(), 58L, idx);   // exp = 58L ** idx
        val += exp * n;
    }
    // for (auto& c: s)    // discarded. replace with rbegin for performance optimized
        // val = val*58L + alphabet.find(c);

    size_t cnt = 0;
    auto ret = make_shared<C<Args...>>( mpz_sizeinbase(val.get_mpz_t(), 16), 0 );   // new C<Args...>(size_t, 0)
    mpz_export((void*)ret->data(), &cnt, 1, sizeof(char), 0/*endian?*/, 0, val.get_mpz_t());
    ret->resize(cnt);
    return ret;
}

// partial specialization for std::array
template <typename T, size_t N> struct Base58<array<T,N>>;  // TODO base58 not fixed len, and input.len() != output.len()

};  // namespace NKN
#endif // __NKN_BASE58_H__

