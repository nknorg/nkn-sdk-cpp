#ifndef __NKN_HEX_H__
#define __NKN_HEX_H__

#include <iostream>
#include <iomanip>
#include <sstream>

#include "include/uBigInt.h"

using namespace std;

namespace NKN {
namespace HEX {
    constexpr bool is_hex_digit(int8_t c) {
        return (c>='0' && c<='9') || (c>='A' && c<='F') || (c>='a' && c<='f');
    }
    inline uint8_t hex2byte(const uint8_t hex) {
        // 0x31~0x39, 0x41~0x46, 0x61~0x66
        return (hex<='9') ? hex & 0x0f : (hex+9) & 0x0f;
    }
    inline string EncodeToString(const void* src, size_t n) {
        ostringstream oss;
        const uint8_t* p = (const uint8_t*)src;
        for (size_t i=0; i<n; i++,p++)
            oss << setfill('0') << setw(2) << hex << (short)(*p);
        return oss.str();
    }
    inline string EncodeToString(const char* src) { return EncodeToString(src, strlen(src)); }
    inline string EncodeToString(const byteSlice& src) {
        ostringstream oss;
        for (auto& c: src) {
            oss << setfill('0') << setw(2) << hex << (short)(c & 0xff);
        }
        return oss.str();
    }

    // Not support '0x' prefix. Need to strip it ahead when invoke DecodeString
    template<template<typename...>class C=basic_string, typename... Args>
    C<Args...> DecodeString(const string& src) {
        typedef typename C<Args...>::value_type _CharT;

        C<Args...> ret;
        size_t n = src.size();

        char h4bit, l4bit;
        const char* p = src.data();

        if (! is_hex_digit(*p)) // if first byte is not valid hex_digit
            return ret;

        if (0 != n%2) { // odd len case
            l4bit = *p++;
            ret.push_back((_CharT)l4bit);
        }

        while (p < &src[n]) {
            if (! is_hex_digit(*p)) // termination at the first not hex_digit
                break;
            h4bit = *p++;
            l4bit = *p++;
            ret.push_back( (_CharT)(hex2byte(h4bit)<<4 | hex2byte(l4bit)) );
        }
        return ret;
    }
};  // namespace HEX
};  // namespace NKN

#endif // __NKN_HEX_H__
