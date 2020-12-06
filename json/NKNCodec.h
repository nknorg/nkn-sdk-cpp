#ifndef __JSON_CODEC_H__
#define __JSON_CODEC_H__

#include <cstddef>
#include <string>
#include <stack>

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include <include/uBigInt.h>

using namespace rapidjson;

namespace NKN {
namespace JSON {

#ifdef DEBUG
#define DEBUG_JSON_CODEC(msg) codec_dbg_t _dbg(static_cast<const void*>(this), __PRETTY_FUNCTION__, __LINE__, msg);
#else
#define DEBUG_JSON_CODEC(msg)
#endif

#ifdef DEBUG_JSON_CODEC
class codec_dbg_t {
public:
    std::string _func;
    unsigned int _line;
    const void *ptr;
    char *msg;

    codec_dbg_t(const void *ptr, std::string f, unsigned int l, char *msg) : _func(f), _line(l), ptr(ptr), msg(msg) {
        printf("%s:%d Entry:\t\tthis=%p %s\n", _func.c_str(), _line, ptr, msg);
    }
    ~codec_dbg_t() {
        printf("%s:%d Exit :\t\tthis=%p\n", _func.c_str(), _line, ptr);
    }
};
#endif // DEBUG_JSON_CODEC

struct DecoderStackItem {
    enum State {
        BeforeStart,    //!< An object/array is in the stack but it is not yet called by StartObject()/StartArray().
        Started,        //!< An object/array is called by StartObject()/StartArray().
        Closed          //!< An array is closed after read all element, but before EndArray().
    };

    DecoderStackItem(const Value* value, State state) : value(value), state(state), index() {}

    const Value* value;
    State state;
    SizeType index;   // For array iteration
};

typedef std::stack<DecoderStackItem> DecoderStack;

#define DOCUMENT reinterpret_cast<Document*>(mDocument)
#define STACK (reinterpret_cast<DecoderStack*>(mStack))
#define TOP (STACK->top())
#define CURRENT (*TOP.value)

/// Represents a JSON reader which implements Archiver concept.
class Decoder {
public:
    /// Constructor.
    /**
        \param json A non-const source json string for in-situ parsing.
        \note in-situ means the source JSON string will be modified after parsing.
    */
    Decoder(const char* json);
    Decoder(const std::string& json);

    /// Destructor.
    ~Decoder();

    // Archive concept
    operator bool() const { return !mError; }

    virtual Decoder& StartObject();
    virtual Decoder& Member(const char* name);
    bool HasMember(const char* name) const;
    virtual Decoder& EndObject();

    virtual Decoder& StartArray(size_t* size = 0);
    virtual Decoder& EndArray();

    virtual Decoder& operator&(bool& b);
    virtual Decoder& operator&(unsigned& u);
    virtual Decoder& operator&(int& i);
    virtual Decoder& operator&(double& d);
    virtual Decoder& operator&(std::string& s);
    template <size_t N>
    Decoder& operator&(uBigInt<N> &bi);

    virtual Decoder& SetNull();
    virtual inline ParseErrorCode ErrCode() const { return errCode; }

    static const bool IsReader = true;
    static const bool IsWriter = !IsReader;

private:
    Decoder(const Decoder&);
    Decoder& operator=(const Decoder&);

    void Next();

    // PIMPL
    void* mDocument;              ///< DOM result of parsing.
    void* mStack;                 ///< Stack for iterating the DOM
    bool mError;                  ///< Whether an error has occurred.
    ParseErrorCode errCode;
};

template <size_t N>
Decoder& Decoder::operator&(uBigInt<N> &bi) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
        return *this;
    }

    if (CURRENT.IsString()) {
        bi.FromHexString(CURRENT.GetString());
        Next();
    }
    return *this;
}

////////////////////////////////////////////////////////////////////////////////
// Encoder

#define WRITER reinterpret_cast<PrettyWriter<StringBuffer>*>(mWriter)
#define STREAM reinterpret_cast<StringBuffer*>(mStream)

class Encoder {
public:
    /// Constructor.
    Encoder();

    /// Destructor.
    ~Encoder();

    /// Obtains the serialized JSON string.
    const char* GetString() const;

    // Archive concept

    operator bool() const { return true; }

    virtual Encoder& StartObject();
    virtual Encoder& Member(const char* name);
    bool HasMember(const char* name) const;
    virtual Encoder& EndObject();

    virtual Encoder& StartArray(size_t* size = 0);
    virtual Encoder& EndArray();

    virtual Encoder& operator&(bool& b);
    virtual Encoder& operator&(unsigned& u);
    virtual Encoder& operator&(int& i);
    virtual Encoder& operator&(double& d);
    virtual Encoder& operator&(std::string& s);
    template <size_t N>
    Encoder& operator&(const uBigInt<N> &bi);
    virtual Encoder& SetNull();

    static const bool IsReader = false;
    static const bool IsWriter = !IsReader;

private:
    Encoder(const Encoder&);
    Encoder& operator=(const Encoder&);

    // PIMPL idiom
    void* mWriter;      ///< JSON writer.
    void* mStream;      ///< Stream buffer.
};

template <size_t N>
Encoder& Encoder::operator&(const uBigInt<N> &bi){
    std::string s = bi.toHexString();
    WRITER->String(s.c_str(), static_cast<SizeType>(s.size()));
    return *this;
}
};  // namespace JSON
};  // namespace NKN

#endif // ARCHIVER_H__
