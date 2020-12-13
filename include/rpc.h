#include <iostream>
#include <random>
#include <vector>
#include <initializer_list>

#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <cpprest/interopstream.h>

#include "include/uBigInt.h"

using namespace std;
using namespace web;

extern const vector<const string> DefaultRPCConfig;
const string GetRandomSeedRPCServerAddr(const vector<const string>&);

typedef pair<string, json::value> kvPair_t;

shared_ptr<json::value> NewRequest(const string& method, const vector<kvPair_t>& pairs, uint8_t id=0);
shared_ptr<json::value> NewRequest(const string& method, const initializer_list<kvPair_t>& pairs, uint8_t id=0);
shared_ptr<json::value> NewRequest(const string& method, const json::value& params=json::value::object(), uint8_t id=0);

class JsonRPC {
    const string rpcSrv;
    http::client::http_client cli;

public:
    JsonRPC(const string& server): rpcSrv(server), cli(U(rpcSrv)) {}

    inline json::value Call(const string& method, const initializer_list<kvPair_t>& params, uint8_t id=0) {
        json::value req = json::value::object();
        for (auto& it: params)
            req[U(it.first)] = json::value(it.second);
        return Call(method, req, id);
    }
    inline json::value Call(const string& method, const vector<kvPair_t>& params, uint8_t id=0) {
        json::value req = json::value::object();
        for (auto& it: params)
            req[U(it.first)] = json::value(it.second);
        return Call(method, req, id);
    }
    json::value Call(const string& method, const json::value& params, uint8_t id=0) {
        auto req = NewRequest(method, params, id);
        // cerr << __PRETTY_FUNCTION__ << " req body:\n" << *req << endl;  // for DEBUG
        auto resp = cli.request(http::methods::POST, "", *req).get();
        // TODO http code != 200
        return resp.extract_json().get();
    }

    uint32_t GetHeight();
    const string GetBalance(const string& addr);
    uint64_t GetNonce(const string& addr, bool txPool=true);
    uint32_t GetSubscribersCount(const string& topic);
};

json::value RPCCall(const string& action, const initializer_list<kvPair_t>& params, const vector<const string>& cfg=DefaultRPCConfig);
json::value RPCCall(const string& action, const json::value& params, const vector<const string>& cfg=DefaultRPCConfig);

uint32_t GetHeight(const vector<const string>& cfg=DefaultRPCConfig);
const string GetBalance(const string& addr, const vector<const string>& cfg=DefaultRPCConfig);
uint64_t GetNonce(const string& addr, bool txPool=true, const vector<const string>& cfg=DefaultRPCConfig);
uint32_t GetSubscribersCount(const string& topic, const vector<const string>& cfg=DefaultRPCConfig);
json::value GetSubscribers(const string& topic, int32_t offset, int32_t limit, bool meta, bool txPool, const vector<const string>& cfg=DefaultRPCConfig);
json::value GetSubscription(const string& topic, const NKN::Uint256& subscriber, const vector<const string>& cfg=DefaultRPCConfig);  //TODO
json::value GetSubscription(const string& topic, const string& subscriber, const vector<const string>& cfg=DefaultRPCConfig);
