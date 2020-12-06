#ifndef __NKN_RANDOM_H__
#define __NKN_RANDOM_H__

#include <iomanip>
#include <random>
#include <vector>
#include <array>
#include <assert.h>

#include "include/uBigInt.h"

using namespace std;

namespace NKN {

// match all template.
// General read and return any type which has push_back API
template<typename AnyType>
struct Random {
    static AnyType read(size_t cnt) {
        random_device rd;
        AnyType buf;
        while(cnt--) {
            buf.push_back(rd());
        }
        return buf;
    }
};

// partial specialization for std::array
template <typename T, size_t N>
struct Random<array<T,N>> {
    static array<T,N> read(size_t cnt=N) {
        assert(cnt<=N);

        random_device rd;
        array<T,N> buf;
        for (int i=0; i<cnt; i++) {
            buf[i] = reinterpret_cast<T>(rd());
        }
        return buf;
    }
};

// partial specialization for shared_ptr of general dynamic size container
template <template<typename...> class C, typename... Args>
struct Random<shared_ptr<C<Args...>>>;  // TODO

// partial specialization for uBigInt<N>
template <size_t N>
struct Random<uBigInt<N>> {
    static uBigInt<N> read(size_t cnt=N/8) {
        assert(cnt<=N/8);

        random_device rd;
        vector<uint8_t> buf(N/8, 0);    // initialize zero cover cnt<N/8 case
        while(cnt) {
            buf[N/8 - cnt--] = (uint8_t)rd();   // keep leading zero when cnt<N/8
        }
        return uBigInt<N>(buf);
    }
};

// partial specialization for shared_ptr of uBigInt<N>
template <size_t N>
struct Random<shared_ptr<uBigInt<N>>> {
    static shared_ptr<uBigInt<N>> read(size_t cnt=N/8) {
        assert(cnt<=N/8);

        random_device rd;
        vector<uint8_t> buf(N/8, 0);    // initialize zero cover cnt<N/8 case
        while(cnt) {
            buf[N/8 - cnt--] = (uint8_t)rd();   // keep leading zero when cnt<N/8
        }
        return shared_ptr<uBigInt<N>>(new uBigInt<N>(buf));
    }
};

};  // namespace NKN

#endif //__NKN_RANDOM_H__
