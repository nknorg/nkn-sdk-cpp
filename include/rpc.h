#ifndef __NKN_RPC_H__
#define __NKN_RPC_H__

#include <iostream>
#include <random>
#include <vector>
#include <initializer_list>

#include <cpprest/json.h>
#include <cpprest/ws_client.h>
#include <cpprest/http_client.h>
#include <cpprest/interopstream.h>

#include "include/uBigInt.h"

using namespace std;
using namespace web;

extern const vector<string> DefaultRPCConfig;
const string GetRandomSeedRPCServerAddr(const vector<string>& cfg = DefaultRPCConfig);

typedef pair<string, json::value> kvPair_t;

inline shared_ptr<json::value> NewJson(const initializer_list<kvPair_t>& pairs) {
    auto jsPtr = make_shared<json::value>(json::value::object());
    for (auto& it: pairs)
        (*jsPtr)[_XPLATSTR(it.first)] = json::value(it.second);
    return jsPtr;
}
shared_ptr<json::value> NewRequest(const string& method, const vector<kvPair_t>& pairs, uint8_t id=0);
shared_ptr<json::value> NewRequest(const string& method, const initializer_list<kvPair_t>& pairs, uint8_t id=0);
shared_ptr<json::value> NewRequest(const string& method, const json::value& params=json::value::object(), uint8_t id=0);

class JsonRPC {
    const string rpcSrv;
    http::client::http_client cli;

public:
    JsonRPC(const string& server): rpcSrv(server), cli(_XPLATSTR(rpcSrv)) {}

    inline json::value Call(const string& method, const initializer_list<kvPair_t>& params, uint8_t id=0) {
        json::value req = json::value::object();
        for (auto& it: params)
            req[_XPLATSTR(it.first)] = json::value(it.second);
        return Call(method, req, id);
    }
    inline json::value Call(const string& method, const vector<kvPair_t>& params, uint8_t id=0) {
        json::value req = json::value::object();
        for (auto& it: params)
            req[_XPLATSTR(it.first)] = json::value(it.second);
        return Call(method, req, id);
    }
    json::value Call(const string& method, const json::value& params, uint8_t id=0) {
        auto req = NewRequest(method, params, id);
        cerr << __PRETTY_FUNCTION__ << " req body:\n" << *req << endl;  // for DEBUG
        // TODO try catch cli.request.get()
        auto resp = cli.request(http::methods::POST, "", *req).get();
        // TODO http code != 200
        return resp.extract_json().get();
    }

    uint32_t GetHeight();
    const string GetBalance(const string& addr);
    uint64_t GetNonce(const string& addr, bool txPool=true);
    uint32_t GetSubscribersCount(const string& topic);
};

class Node {
public:
    Node() = default;
    Node(const Node& other) = default;
    template <typename T>
    Node(const string& addr, const string& rpcAddr, const T& pk, const T& id)
        : Addr(addr), RPCAddr(rpcAddr), PubKey(pk), ID(id) {}
    Node(const json::value& js) {
        cerr << __PRETTY_FUNCTION__ << " js value:\n" << js << endl;  // for DEBUG
        if (js.has_field("addr"))    Addr    = js.at("addr").as_string();
        if (js.has_field("rpcAddr")) RPCAddr = js.at("rpcAddr").as_string();
        if (js.has_field("pubkey"))  PubKey  = js.at("pubkey").as_string();
        if (js.has_field("id"))      ID      = js.at("id").as_string();
    }

    inline bool Equal(const Node& other) {
        return Addr.compare(other.Addr) == 0 &&
            RPCAddr.compare(other.RPCAddr) == 0 &&
            PubKey == other.PubKey && ID == other.ID;
    }

    string Addr;
    string RPCAddr;
    NKN::Uint256 PubKey;
    NKN::Uint256 ID;
};

json::value RPCCall(const string& action, const initializer_list<kvPair_t>& params, const vector<string>& cfg=DefaultRPCConfig);
json::value RPCCall(const string& action, const json::value& params, const vector<string>& cfg=DefaultRPCConfig);

uint32_t GetHeight(const vector<string>& cfg=DefaultRPCConfig);
const string GetBalance(const string& addr, const vector<string>& cfg=DefaultRPCConfig);
uint64_t GetNonce(const string& addr, bool txPool=true, const vector<string>& cfg=DefaultRPCConfig);
uint32_t GetSubscribersCount(const string& topic, const vector<string>& cfg=DefaultRPCConfig);
json::value GetSubscribers(const string& topic, int32_t offset, int32_t limit, bool meta, bool txPool, const vector<string>& cfg=DefaultRPCConfig);
json::value GetSubscription(const string& topic, const NKN::Uint256& subscriber, const vector<string>& cfg=DefaultRPCConfig);  //TODO
json::value GetSubscription(const string& topic, const string& subscriber, const vector<string>& cfg=DefaultRPCConfig);

template <typename ReturnType>
ReturnType GetWSAddress(const string& addr, const vector<string>& cfg);
template <>
json::value GetWSAddress<json::value>(const string& addr, const vector<string>& cfg);
template <>
shared_ptr<Node> GetWSAddress<shared_ptr<Node>>(const string& addr, const vector<string>& cfg);

#endif /* __NKN_RPC_H__ */
