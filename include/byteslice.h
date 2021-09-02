#ifndef __BYTE_SLICE_H__
#define __BYTE_SLICE_H__

#include <iostream>
#include <vector>
#include <cassert>

// corresponding to golang's byte slice
class byteSlice: public std::basic_string<char> {
    typedef std::basic_string<char> super;

public:
    template<typename... Args>
    byteSlice(Args... args): super(args...) {}

    // constructor from string
    byteSlice(std::string const& str): super(str.data(), str.length()) {}

    // TODO toString
};

// User-defined literals for byteSlice
// inline constexpr const uint8_t* operator"" _us(const char *s, size_t) { return (const uint8_t*) s; }
inline byteSlice operator"" _bytes(const char *s, size_t len) { return byteSlice(s, s+len); }

// input stream
inline std::istream& operator>>(std::istream &s, byteSlice& dest) {
    // CAUTION: copy will be truncated at dest.end() if it has no enough allocated mem. Just like golang's copy
    auto end = std::copy(std::istreambuf_iterator<char>(s), std::istreambuf_iterator<char>(), dest.begin());

    // if istream shorter than dest
    auto len = end - dest.begin();
    assert( len >= 0 );

    if ((size_t)len < dest.size())
        dest.resize(len);   // truncated dest

    return s;
}

// output stream
inline std::ostream& operator<<(std::ostream &s, const byteSlice& slice) {
    std::copy(slice.begin(), slice.end(), std::ostream_iterator<char>(s));
    return s;
}
#endif  // __BYTE_SLICE_H__
