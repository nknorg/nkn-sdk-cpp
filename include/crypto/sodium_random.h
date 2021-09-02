#ifndef __NKN_RANDOM_H__
#define __NKN_RANDOM_H__

#include <type_traits>
#include <cassert>

extern "C" {
#include <sodium.h>
}

#include "include/uBigInt.h"
#include "include/SFINAE.h"

using namespace std;

namespace NKN {

#ifdef DEBUG
#define DEBUG_RANDOM(T) random_dbg_t _dbg(__PRETTY_FUNCTION__, __LINE__, typeid(T).name());
struct random_dbg_t {
    const char* _func;
    uint32_t _line;
    const char* typ;

    random_dbg_t(const char* f, uint32_t l, const char* t) : _func(f), _line(l), typ(t) {
        fprintf(stderr, "%s:%d match template type %s\n", _func, _line, typ);
    }
};
#else
#define DEBUG_RANDOM(T)
#endif

// sink-hold template. Catch all unmatched type and throw out an kindly error msg.
template<typename UnsupportedType, typename _ = UnsupportedType> struct Random {
    UnsupportedType operator()(...) {
        static_assert(sizeof(UnsupportedType) != sizeof(UnsupportedType),
                "Random<T> template NOT support this type yet. \
                You have to implement the specialization template for this type");
    }
};

// partial specialization for any primitive integer types
template<typename AnyInt>
struct Random<AnyInt, typename enable_if<is_integral<AnyInt>::value, AnyInt>::type> {
    AnyInt operator()(size_t cnt=sizeof(AnyInt)) {
        DEBUG_RANDOM(AnyInt)
        assert(cnt<=sizeof(AnyInt));

        AnyInt ret=0;
        randombytes_buf(&ret, min(cnt, sizeof(ret)));
        return ret;
    }
};

// partial specialization for std::array<primitive integer>
template <typename Elem, size_t N>
struct Random<array<Elem,N>, typename enable_if<is_integral<Elem>::value, array<Elem,N>>::type> {
    array<Elem,N> operator()(size_t cnt=N) {
        DEBUG_RANDOM(AnyInt)
        assert(cnt<=N);

        array<Elem,N> buf{};    // preAlloc and fill 0
        randombytes_buf((uint8_t*)buf.data(), cnt*sizeof(Elem));
        return buf;
    }
};

// partial specialization for all container instantiation
template<template<typename...> class _Tp, typename... Args>
struct Random<_Tp<Args...>> {
    typedef _Tp<Args...> AnyContainer;
    typedef typename AnyContainer::value_type _Elem;

    _Tp<Args...> operator()(size_t cnt) {
        return _impl<_Tp<Args...>>(cnt);
    }

    // for non-contiguous container. We have to general _Elem one by one and push_back into container
    template <typename C>
    typename enable_if< !is_contiguous_container<C>::value
                        && is_integral<typename C::value_type>::value,
                        C
                    >::type _impl(size_t cnt) {
        DEBUG_RANDOM(AnyType)

        _Elem e;
        AnyContainer buf;
        while(cnt--) {
            randombytes_buf(&e, sizeof(e));
            buf.push_back(e);
        }
        return buf;
    }

    // for contiguous container. General cnt*sizeof(_Elem) random bytes directly
    template <typename C>
    typename enable_if< is_contiguous_container<C>::value
                        && is_integral<typename C::value_type>::value,
                        C
                    >::type _impl(size_t cnt) {
        DEBUG_RANDOM(AnyType)

        auto size = cnt * sizeof(_Elem);
        AnyContainer buf(size, _Elem());    // preAlloc and initialized
        randombytes_buf((uint8_t*)buf.data(), size);
        return buf;
    }

    template <typename C>
    typename enable_if< !is_integral<typename C::value_type>::value, C>::type _impl(...) {
        static_assert(is_integral<typename C::value_type>::value,
                "Don't know how to construct a non primitive integer type Elem from random bytes. \
                You MUST explicit specialization the template for your case");
    }
};

// partial specialization for shared_ptr of all container instantiation
template <template<typename...> class _Tp, typename... Args>
struct Random<shared_ptr<_Tp<Args...>>>;  // TODO

// partial specialization for uBigInt<N>
template <size_t N>
struct Random< uBigInt<N>,
               typename enable_if<
                           is_uBigInt<uBigInt<N>>::value,
                           shared_ptr<uBigInt<N>>
               >::type>
{
    uBigInt<N> operator()(size_t cnt=N/8) {
        DEBUG_RANDOM(AnyInt)
        assert(cnt<=N/8);

        vector<uint8_t> buf(N/8, 0);    // initialize zero cover cnt<N/8 case
        randombytes_buf(buf.data(), cnt);
        return uBigInt<N>(buf);
    }
};

// partial specialization for uBigInt<N>
template <size_t N>
struct Random< shared_ptr<uBigInt<N>>,
               typename enable_if<
                           is_uBigInt<uBigInt<N>>::value,
                           shared_ptr<uBigInt<N>>
               >::type>
{
    shared_ptr<uBigInt<N>> operator()(size_t cnt=N/8) {
        DEBUG_RANDOM(AnyInt)
        assert(cnt<=N/8);

        vector<uint8_t> buf(N/8, 0);    // initialize zero cover cnt<N/8 case
        randombytes_buf(buf.data(), cnt);
        return make_shared<uBigInt<N>>(buf);
    }
};

};  // namespace NKN
#endif //__NKN_RANDOM_H__
