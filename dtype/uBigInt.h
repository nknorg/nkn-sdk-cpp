#ifndef __U_BIG_INT__
#define __U_BIG_INT__

#include <iostream>
#include <cstring>
#include <cassert>
#include <sstream>
#include <iomanip>

#include <gmpxx.h>

template <size_t N> class uBigInt;

#ifdef DEBUG
#define DEBUG_U_BIG_INT uBigInt_dbg_t<N> _dbg(this, __PRETTY_FUNCTION__, __LINE__);
#else
#define DEBUG_U_BIG_INT
#endif

#ifdef DEBUG_U_BIG_INT
template <size_t N>
class uBigInt_dbg_t {
public:
    std::string _func;
    unsigned int _line;
    uBigInt<N> *outer;

    uBigInt_dbg_t(uBigInt<N> *o, std::string f, unsigned int l) : _func(f), _line(l), outer(o)  {
        printf("%s:%d Entry:\t\tthis=%p, ringSize=0x%s, val=0x%s\n", _func.c_str(), _line,
                outer, outer->ringSize.get_str(16).c_str(), outer->val.get_str(16).c_str());
    }
    ~uBigInt_dbg_t() {
        printf("%s:%d Exit :\t\tthis=%p, ringSize=0x%s, val=0x%s\n", _func.c_str(), _line,
                outer, outer->ringSize.get_str(16).c_str(), outer->val.get_str(16).c_str());
    }
};
#endif // _DEBUG_U_BIG_INT_T

template <size_t N>
class uBigInt
{
#ifdef DEBUG_U_BIG_INT
    friend class uBigInt_dbg_t<N>;
#endif

    template <size_t U>
    friend std::ostream& operator<<(std::ostream &s, const uBigInt<U> &n);
    template <size_t U>
    friend std::istream& operator>>(std::istream &s, uBigInt<U> &val);

private:
    const mpz_class ringSize;
    mpz_class val;

protected:
    inline bool startsWith(const std::string& s, const std::string& prefix) {
        return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
    }

public:
    enum ENDIAN {
        LSB = -1,   // Little endian
        NATIVE = 0, // Host native
        MSB = 1,    // Big endian
    };

    /* constructors */
    uBigInt(const std::string& s) : ringSize("0x1" + std::string(2*N/8, '0'))   { DEBUG_U_BIG_INT FromHexString(s); } // throw
    uBigInt(const char* c)  : ringSize("0x1" + std::string(2*N/8, '0'))         { DEBUG_U_BIG_INT FromHexString(c); } // throw
    uBigInt()               : ringSize("0x1" + std::string(2*N/8, '0')), val(0) { DEBUG_U_BIG_INT }
    uBigInt(int l)          : ringSize("0x1" + std::string(2*N/8, '0')), val(l) { DEBUG_U_BIG_INT val %= ringSize; if (val<0) val+=ringSize; }
    uBigInt(long l)         : ringSize("0x1" + std::string(2*N/8, '0')), val(l) { DEBUG_U_BIG_INT val %= ringSize; if (val<0) val+=ringSize; }
    uBigInt(unsigned int l) : ringSize("0x1" + std::string(2*N/8, '0')), val(l) { DEBUG_U_BIG_INT val %= ringSize; }
    uBigInt(unsigned long l): ringSize("0x1" + std::string(2*N/8, '0')), val(l) { DEBUG_U_BIG_INT val %= ringSize; }
    // TODO signed/unsigned long long constructors
    uBigInt(const mpz_class& l) : ringSize("0x1" + std::string(2*N/8, '0')), val(l)    { DEBUG_U_BIG_INT val %= ringSize; if (val<0) val+=ringSize; }
    uBigInt(const uBigInt& l)   : ringSize("0x1" + std::string(2*N/8, '0')), val(l.val){ DEBUG_U_BIG_INT val %= ringSize; if (val<0) val+=ringSize; };

    /* assignment operators */
    const uBigInt& operator=(const char* c)         { FromHexString(c); DEBUG_U_BIG_INT return *this; } // throw
    const uBigInt& operator=(const std::string& s)  { FromHexString(s); DEBUG_U_BIG_INT return *this; } // throw
    const uBigInt& operator=(int l)                 { val= (mpz_class(l) % ringSize); if (val<0) val+=ringSize; return *this; }
    const uBigInt& operator=(long l)                { val= (mpz_class(l) % ringSize); if (val<0) val+=ringSize; return *this; }
    const uBigInt& operator=(unsigned int l)        { val= (mpz_class(l) % ringSize); return *this; }
    const uBigInt& operator=(unsigned long l)       { val= (mpz_class(l) % ringSize); return *this; }
    // TODO signed/unsigned long long assignment operators
    const uBigInt& operator=(const mpz_class& l)    { val=l;     val %= ringSize; if (val<0) val+=ringSize; DEBUG_U_BIG_INT return *this; }
    const uBigInt& operator=(const uBigInt& l)      { val=l.val; val %= ringSize; if (val<0) val+=ringSize; DEBUG_U_BIG_INT return *this; }

    /* unary increment/decrement operators */
    const uBigInt& operator++();
    const uBigInt& operator--();
    uBigInt operator++(int);
    uBigInt operator--(int);

    /* operational assignments */
    const uBigInt& operator+=(const uBigInt& rhs);
    const uBigInt& operator-=(const uBigInt& rhs);
    const uBigInt& operator*=(const uBigInt& rhs);
    const uBigInt& operator/=(const uBigInt& rhs); // throw
    const uBigInt& operator%=(const uBigInt& rhs); // throw
    // const uBigInt& operator*=(const mpz_class& rhs); //TODO

    /* operations */
    uBigInt operator-() const { return uBigInt(ringSize - val); }
    uBigInt operator+(const uBigInt& rhs) const { return uBigInt(val + rhs.val); }
    uBigInt operator-(const uBigInt& rhs) const { return uBigInt(val - rhs.val); }
    uBigInt operator*(const uBigInt& rhs) const { return uBigInt(val * rhs.val); }
    uBigInt operator/(const uBigInt& rhs) const { return uBigInt(val / rhs.val); } // throw
    uBigInt operator%(const uBigInt& rhs) const { return uBigInt(val % rhs.val); } // throw
    // uBigInt operator*(const mpz_class& rhs) const;  //TODO

    /* relational operations */
    bool operator==(const uBigInt& rhs) const { return val == rhs.val; }
    bool operator!=(const uBigInt& rhs) const { return val != rhs.val; }
    bool operator<(const uBigInt& rhs) const  { return val <  rhs.val; };
    bool operator<=(const uBigInt& rhs) const { return val <= rhs.val; };
    bool operator>(const uBigInt& rhs) const  { return val >  rhs.val; };
    bool operator>=(const uBigInt& rhs) const { return val >= rhs.val; };

    /* string conversion */
    void FromHexString(const std::string& s);
    inline void FromBytes(const char* src,    size_t n=N/8, uBigInt::ENDIAN endian = uBigInt::MSB) {
        FromBytes(reinterpret_cast<const uint8_t*>(src), n, endian);
    }
    inline void FromBytes(const uint8_t* src, size_t n=N/8, uBigInt::ENDIAN endian = uBigInt::MSB) {
        mpz_import(val.get_mpz_t(), std::min<size_t>(n,N/8), endian, sizeof(char), 0/*endian?*/, 0, src);
    }
    std::string toString(int base=16) const;
    std::string toHexString() const;
    std::string toBytes(uBigInt::ENDIAN endian = uBigInt::MSB);

    /* Access Data buffer directly */
    inline const mpz_class& Value() const { return val; }
    // WARNING: access internal merber mpz_t._mp_d has no guarantee for compatibility in future or cross platform.
    // inline void* _DataPtr() const { return (void *)(val.get_mpz_t()->_mp_d); }

    /* conversion to primitive types */	// TODO implement later if necessary in future
    // int toInt() const;
    // long toLong() const;
    // long long toLongLong() const;
    // unsigned int toUnsignedInt() const;
    // unsigned long toUnsignedLong() const;
    // unsigned long long toUnsignedLongLong() const;
};

template <size_t N>
const uBigInt<N>& uBigInt<N>::operator++() {
    val++;
    if (val == ringSize)
        val = 0;
    return *this;
}

template <size_t N>
const uBigInt<N>& uBigInt<N>::operator--() {
    if (val == 0)
        val = ringSize;
    val--;
    return *this;
}

template <size_t N>
uBigInt<N> uBigInt<N>::operator++(int) {
    uBigInt<N> ret = *this;
    val++;
    if (val == ringSize)
        val = 0;
    return ret;
}

template <size_t N>
uBigInt<N> uBigInt<N>::operator--(int) {
    uBigInt<N> ret = *this;
    if (val == 0)
        val = ringSize;
    val--;
    return ret;
}

template <size_t N>
const uBigInt<N>& uBigInt<N>::operator+=(const uBigInt<N>& rhs) {
    val += rhs.val;
    if (val >= ringSize)
        val %= ringSize;
    return *this;
}

template <size_t N>
const uBigInt<N>& uBigInt<N>::operator-=(const uBigInt<N>& rhs) {
    val -= rhs.val;
    if(val < 0)
        val += ringSize;
    return *this;
}

template <size_t N>
const uBigInt<N>& uBigInt<N>::operator*=(const uBigInt<N>& rhs) {
    val *= rhs.val;
    if (val >= ringSize)
        val %= ringSize;
    return *this;
}

template <size_t N>
const uBigInt<N>& uBigInt<N>::operator/=(const uBigInt<N>& rhs) { // throw
    val /= rhs.val;
    return *this;
}

template <size_t N>
const uBigInt<N>& uBigInt<N>::operator%=(const uBigInt<N>& rhs) { // throw
    val %= rhs.val;
    return *this;
}

template <size_t N>
void uBigInt<N>::FromHexString(const std::string& s) {
    DEBUG_U_BIG_INT
    startsWith(s, "0x") ? val.set_str(s, 0) : val.set_str(s, 16);

    val %= ringSize;
    if (val < 0)
        val += ringSize;
}

template <size_t N>
std::string uBigInt<N>::toString(int base) const {
    switch (base) {
        case 16: { return toHexString(); break; }
        default: return val.get_str(base);
    }
}

template <size_t N>
std::string uBigInt<N>::toHexString() const {
    std::ostringstream os;
    os << std::right << std::setfill('0') << std::setw(2*N/8) << val.get_str(16);
    return os.str();
}

template <size_t N>
std::string uBigInt<N>::toBytes(uBigInt::ENDIAN endian) {
    size_t cnt=0;
    char* bytes = (char*)mpz_export(NULL, &cnt, endian, sizeof(char), 0/*endian?*/, 0, val.get_mpz_t());
    assert(N/8>=cnt);   // this->val shoule never overflow ringSize

    std::ostringstream out;
    /* ENDIAN::MSB implement */
    for (size_t padding_len = N/8-cnt; padding_len; padding_len--) {
        out.put(0);   // padding leading zero if cnt < N/8
    }
    out.write(bytes, cnt);

    // TODO: implement for ENDIAN::LSB && ENDIAN::NATIVE

    // free the allocated memory by mpz_export()
    void (*free_fn) (void *, size_t) = NULL;
    mp_get_memory_functions(NULL, NULL, &free_fn);
    free_fn(bytes, cnt*sizeof(char));

    return out.str();
}

// input stream
template <unsigned long N>
std::istream& operator>>(std::istream &s, uBigInt<N> &n) {
#if __cplusplus >= 201103L	// supported after c++11
    std::string buf = {std::istreambuf_iterator<char>(s), std::istreambuf_iterator<char>()};
#else
    std::string buf;
    s >> buf;
#endif
    n.FromHexString(buf);
    return s;
}

// output stream
template <size_t N>
std::ostream& operator<<(std::ostream &s, const uBigInt<N> &n) {
    s << std::right << std::setfill('0') << std::setw(2*N/8) << n.val.get_str(16);
    return s;
}

#endif /* __U_BIG_INT__ */
