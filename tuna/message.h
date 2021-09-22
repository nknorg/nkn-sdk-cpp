#ifndef __NKN_TUNA_MSG_H__
#define __NKN_TUNA_MSG_H__

#include <string>
#include <vector>
#include <memory>
#include <algorithm>
// #include <stdlib.h>
#include <cstdlib>

#include <cpprest/json.h>

// #include "include/message.h"

namespace NKN {
namespace TUNA {
using namespace std;
using namespace web;

typedef struct PubAddr {
    string  IP;
    string  InPrice;
    string  OutPrice;
    uint32_t    Port;

    PubAddr() = default;
    PubAddr(const PubAddr&) = default;
    PubAddr& operator=(const PubAddr&) = default;

    PubAddr(const string& ip, uint32_t port, const string& inPrice, const string& outPrice)
        : IP(ip), InPrice(inPrice), OutPrice(outPrice), Port(port) {}

    PubAddr(const json::value& js) {
        if (js.has_field("ip"))         IP   = js.at("ip").as_string();
        if (js.has_field("port"))       Port = js.at("port").as_integer();
        if (js.has_field("inPrice"))    InPrice  = js.at("inPrice").as_string();
        if (js.has_field("outPrice"))   OutPrice = js.at("outPrice").as_string();
    }
} PubAddr_t;
typedef shared_ptr<PubAddr_t> PubAddr_ptr;

typedef struct PubAddrs: public vector<PubAddr_ptr> {
    // Addrs;

    PubAddrs() = default;
    PubAddrs(const PubAddrs&) = default;
    PubAddrs& operator=(const PubAddrs&) = default;

    PubAddrs(initializer_list<PubAddr_ptr> list): vector<PubAddr_ptr>(list.begin(), list.end()) {}

    PubAddrs(const json::value& js) {
        if (!js.has_field("addrs")) {
            return;
        }

        auto& arr = js.at("addrs").as_array();
        for_each(arr.begin(), arr.end(), [this](json::value it){
            this->emplace_back(make_shared<PubAddr_t>(it));
            // this->Addrs.emplace_back(make_shared<PubAddr_t>(it));
        });
    }

    static shared_ptr<PubAddrs> NewFromMsg(const string& jsStr) {
        std::error_code err;
        auto js = json::value::parse(jsStr, err);
        if (err) { cerr << __PRETTY_FUNCTION__ << ":" << __LINE__ << " failed. json: " << jsStr << endl;
            return nullptr;
        }

        return make_shared<PubAddrs>(js);
    }
} PubAddrs_t;

/* typedef union MsgFrame {
    static constexpr size_t KB   = 1024;
    static constexpr size_t PAGE = 4*KB;
    char*       p;
    struct {
        uint32_t    len;
        char        data[];
    }*          buff;

    MsgFrame(size_t size, bool aligned=false) {
        if (aligned) {
            auto scale = size >= PAGE ? PAGE : KB;
            auto multiple = size / scale;
            if (size % scale != 0)
                multiple++;

            p = (char*)aligned_alloc(scale, multiple*scale);
            fprintf(stderr, "MsgFrame alloc %zu/%zu = %lu page at %p\n", size, scale, multiple, p);
        }else{
            p = (char*)malloc(size);
            fprintf(stderr, "MsgFrame alloc %zu bytes at %p\n", size, p);
        }
        fprintf(stderr, "MsgFrame alloc %zu mem at %p:%p\n", size, p, buff);
        buff->len = 0;
    }

    ~MsgFrame() {
        free(p);
    }
} MsgFrame_t;

constexpr size_t MsgFrame::KB;
constexpr size_t MsgFrame::PAGE; */

};  // namespace TUNA
};  // namespace NKN
#endif  // __NKN_TUNA_MSG_H__
