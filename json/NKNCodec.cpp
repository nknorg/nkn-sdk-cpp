#include <iostream>
#include <iomanip>
#include <sstream>
#include <typeinfo>
#include <exception>
#include <stdexcept>
// #include <cassert>

#include "NKNCodec.h"

using namespace rapidjson;
using namespace NKN::JSON;

Decoder::Decoder(const char* json) : mDocument(), mStack(), mError(false) {
    mDocument = new GenericDocument<UTF8<> >();

    // Parse and check
    DOCUMENT->Parse(json);
    errCode = DOCUMENT->GetParseError();
    switch (errCode) {
        case kParseErrorNone:   // valid json
            break;
        case kParseErrorDocumentRootNotSingular: // TODO: support multiple json obj from input
        case kParseErrorDocumentEmpty:
        case kParseErrorValueInvalid:   // invalid json
        default: { // Others specific error
            // TODO stderr, throw while #ifdef __EXCEPTIONS
            DEBUG_JSON_CODEC("ParseError");
            mError = true;
            return;
        }
    }

    mStack = new DecoderStack;
    STACK->push(DecoderStackItem(DOCUMENT, DecoderStackItem::BeforeStart));
}

Decoder::Decoder(const std::string& json) : mDocument(), mStack(), mError(false) {
    mDocument = new GenericDocument<UTF8<> >();

    // Parse and check
    DOCUMENT->Parse(json.c_str(), json.length());
    errCode = DOCUMENT->GetParseError();
    switch (errCode) {
        case kParseErrorNone:   // valid json
            break;
        case kParseErrorDocumentRootNotSingular:    // TODO: support multiple json obj from input
        case kParseErrorDocumentEmpty:
        case kParseErrorValueInvalid:   // invalid json
        default: {  // Others specific error
            // TODO stderr, throw while #ifdef __EXCEPTIONS
            DEBUG_JSON_CODEC("ParseError");
            mError = true;
            return;
        }
    }

    mStack = new DecoderStack;
    STACK->push(DecoderStackItem(DOCUMENT, DecoderStackItem::BeforeStart));
}

Decoder::~Decoder() {
    delete DOCUMENT;
    delete STACK;
}

// Archive concept
Decoder& Decoder::StartObject() {
    if (kParseErrorNone == errCode) {
        if (CURRENT.IsObject() && TOP.state == DecoderStackItem::BeforeStart)
            TOP.state = DecoderStackItem::Started;
        else{
            DEBUG_JSON_CODEC("Not Obj or Not start yet")
            errCode = kParseErrorObjectMissCommaOrCurlyBracket;
            mError = true;
            // TODO stderr
        }
    }
    return *this;
}

Decoder& Decoder::EndObject() {
    if (kParseErrorNone == errCode) {
        if (CURRENT.IsObject() && TOP.state == DecoderStackItem::Started)
            Next();
        else {
            DEBUG_JSON_CODEC("Not Obj or Not start yet")
            errCode = kParseErrorObjectMissCommaOrCurlyBracket;
            mError = true;
            // TODO stderr
        }
    }
    return *this;
}

Decoder& Decoder::Member(const char* name) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsObject() && TOP.state == DecoderStackItem::Started) {
        Value::ConstMemberIterator memberItr = CURRENT.FindMember(name);
        if (memberItr != CURRENT.MemberEnd())   // Member Found
            STACK->push(DecoderStackItem(&memberItr->value, DecoderStackItem::BeforeStart));
        // else // Not found
            // mError = true;
    } else {    // CURRENT not an object
            DEBUG_JSON_CODEC("Not Obj or Not start yet")
        errCode = kParseErrorObjectMissName;
        // TODO stderr
        mError = true;
    }
    return *this;
}

bool Decoder::HasMember(const char* name) const {
    // if (!mError && CURRENT.IsObject() && TOP.state == DecoderStackItem::Started)
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsObject() && TOP.state == DecoderStackItem::Started)
        return CURRENT.HasMember(name);

    // TODO warning stderr
    return false;
}

Decoder& Decoder::StartArray(size_t* size) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    // NOT an array or array error
    if (!CURRENT.IsArray() || TOP.state != DecoderStackItem::BeforeStart) {
            DEBUG_JSON_CODEC("Not Array or Not start yet")
        errCode = kParseErrorArrayMissCommaOrSquareBracket;
        // TODO stderr
        mError = true;
        return *this;
    }

    TOP.state = DecoderStackItem::Started;
    if (size)
        *size = CURRENT.Size();

    if (CURRENT.Empty())
        TOP.state = DecoderStackItem::Closed;

    const Value* value = &CURRENT[TOP.index];
    STACK->push(DecoderStackItem(value, DecoderStackItem::BeforeStart));
    return *this;
}

Decoder& Decoder::EndArray() {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsArray() && TOP.state == DecoderStackItem::Closed)
        Next();
    else{
            DEBUG_JSON_CODEC("Not Array or Not closed")
        errCode = kParseErrorArrayMissCommaOrSquareBracket;
        mError = true;
    }
    return *this;
}

Decoder& Decoder::operator&(bool& b) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsBool()) {
        b = CURRENT.GetBool();
        Next();
    }
    // else
        // mError = true;
    return *this;
}

Decoder& Decoder::operator&(unsigned& u) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsUint()) {
        u = CURRENT.GetUint();
        Next();
    }
    // else
        // mError = true;
    return *this;
}

Decoder& Decoder::operator&(int& i) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsInt()) {
        i = CURRENT.GetInt();
        Next();
    }
    // else
        // mError = true;
    return *this;
}

Decoder& Decoder::operator&(double& d) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsNumber()) {
        d = CURRENT.GetDouble();
        Next();
    }
    // else
        // mError = true;
    return *this;
}

Decoder& Decoder::operator&(std::string& s) {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return *this;
    }

    if (CURRENT.IsString()) {
        s = CURRENT.GetString();
        Next();
    }
    // else
        // mError = true;
    return *this;
}

Decoder& Decoder::SetNull() {
    // This function is for Encoder only.
    mError = true;
    return *this;
}

void Decoder::Next() {
    if (kParseErrorNone != errCode) {   // Do nothing if Parse error
            DEBUG_JSON_CODEC("Had ParseError")
        return;
    }

    assert(!STACK->empty());
    STACK->pop();

    if (!STACK->empty() && CURRENT.IsArray()) {
        if (TOP.state == DecoderStackItem::Started) { // Otherwise means reading array item pass end
            if (TOP.index < CURRENT.Size() - 1) {
                const Value* value = &CURRENT[++TOP.index];
                STACK->push(DecoderStackItem(value, DecoderStackItem::BeforeStart));
            }
            else
                TOP.state = DecoderStackItem::Closed;
        }
        // else
            // mError = true;
    }
}

// #undef DOCUMENT
// #undef STACK
// #undef TOP
// #undef CURRENT

////////////////////////////////////////////////////////////////////////////////
// Encoder

Encoder::Encoder() : mWriter(), mStream() {
    mStream = new StringBuffer;
    mWriter = new PrettyWriter<StringBuffer>(*STREAM);
}

Encoder::~Encoder() {
    delete WRITER;
    delete STREAM;
}

const char* Encoder::GetString() const {
    return STREAM->GetString();
}

Encoder& Encoder::StartObject() {
    WRITER->StartObject();
    return *this;
}

Encoder& Encoder::EndObject() {
    WRITER->EndObject();
    return *this;
}

Encoder& Encoder::Member(const char* name) {
    WRITER->String(name, static_cast<SizeType>(strlen(name)));
    return *this;
}

bool Encoder::HasMember(const char*) const {
    // This function is for Decoder only.
    assert(false);
    return false;
}

Encoder& Encoder::StartArray(size_t*) {
    WRITER->StartArray();
    return *this;
}

Encoder& Encoder::EndArray() {
    WRITER->EndArray();
    return *this;
}

Encoder& Encoder::operator&(const bool& b) {
    WRITER->Bool(b);
    return *this;
}

Encoder& Encoder::operator&(const unsigned& u) {
    WRITER->Uint(u);
    return *this;
}

Encoder& Encoder::operator&(const int& i) {
    WRITER->Int(i);
    return *this;
}

Encoder& Encoder::operator&(const double& d) {
    WRITER->Double(d);
    return *this;
}

Encoder& Encoder::operator&(const std::string& s) {
    WRITER->String(s.c_str(), static_cast<SizeType>(s.size()));
    return *this;
}

Encoder& Encoder::SetNull() {
    WRITER->Null();
    return *this;
}

// #undef STREAM
// #undef WRITER
