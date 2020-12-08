#include <iostream>
#include <random>
#include <vector>
#include <initializer_list>

#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <cpprest/interopstream.h>

#include "include/rpc.h"
#include "include/uBigInt.h"

using namespace std;
using namespace web;

shared_ptr<json::value> NewRequest(const string& method, const vector<kvPair_t>& pairs, uint8_t id) {
    auto ret = make_shared<json::value>();

    if (!id)
        id = random_device()();

    json::value params = json::value::object();
    for (auto& it: pairs) {
        params[U(it.first)] = json::value(it.second);
    }

    (*ret)[U("jsonrpc")] = json::value("3.0");
    (*ret)[U("id")]      = json::value(to_string(id));
    (*ret)[U("method")]  = json::value(method);
    (*ret)[U("params")]  = json::value(params);
    return ret;
}

shared_ptr<json::value> NewRequest(const string& method, const initializer_list<kvPair_t>& pairs, uint8_t id) {
    auto ret = make_shared<json::value>();

    if (!id)
        id = random_device()();

    json::value params = json::value::object();
    for (auto& it: pairs) {
        params[U(it.first)] = json::value(it.second);
    }

    (*ret)[U("jsonrpc")] = json::value("3.0");
    (*ret)[U("id")]      = json::value(to_string(id));
    (*ret)[U("method")]  = json::value(method);
    (*ret)[U("params")]  = json::value(params);
    return ret;
}
shared_ptr<json::value> NewRequest(const string& method, const json::value& params, uint8_t id) {
    auto ret = make_shared<json::value>();

    if (!id)
        id = random_device()();
    if (params.is_null())
        params.object();
    cerr << "Params: " << params << endl;

    (*ret)[U("jsonrpc")] = json::value("3.0");
    (*ret)[U("id")]      = json::value(to_string(id));
    (*ret)[U("method")]  = json::value(method);
    (*ret)[U("params")]  = json::value(params);
    return ret;
}

json::value RPCCall(const string& action, const initializer_list<kvPair_t>& params, const vector<const string>& cfg) {
    JsonRPC cli(GetRandomSeedRPCServerAddr(cfg));
    auto resp = cli.Call(action, params).as_object();

    if (resp.find("error") != resp.cend()) {
        auto err = resp["error"];
        cerr << __PRETTY_FUNCTION__ << " got error resp:\n" << err << endl;
        return err;
    }
    return resp["result"];
}

json::value RPCCall(const string& action, const json::value& params, const vector<const string>& cfg) {
    JsonRPC cli(GetRandomSeedRPCServerAddr(cfg));
    auto resp = cli.Call(action, params).as_object();

    if (resp.find("error") != resp.cend()) {
        auto err = resp["error"];
        cerr << __PRETTY_FUNCTION__ << " got error resp: " << err << endl;
        return err;
    }
    return resp["result"];
}

uint32_t GetHeight(const vector<const string>& cfg) {
    auto resp = RPCCall("getlatestblockheight", {}, cfg);
    return resp.as_number().to_uint32();
}

const string GetBalance(const string& addr, const vector<const string>& cfg) {
    auto resp = RPCCall("getbalancebyaddr", {kvPair_t("address", addr)}, cfg);
    return resp["amount"].as_string();

}

uint64_t GetNonce(const string& addr, bool txPool, const vector<const string>& cfg) {
    auto resp = RPCCall("getnoncebyaddr", {kvPair_t("address", addr)}, cfg);
    auto nonce = resp["nonce"].as_number().to_uint64();
    auto nonceInTxPool = resp["nonceInTxPool"].as_number().to_uint64();
    return (txPool && nonceInTxPool>nonce) ? nonceInTxPool : nonce;
}

uint32_t GetSubscribersCount(const string& topic, const vector<const string>& cfg) {
    auto resp = RPCCall("getsubscriberscount", {kvPair_t("topic", topic)}, cfg);
    return resp.as_number().to_uint32();
}

json::value GetSubscribers(const string& topic, int32_t offset, int32_t limit,
        bool meta, bool txPool, const vector<const string>& cfg) {
    return RPCCall("getsubscribers", {
                    kvPair_t("topic",  topic),
                    kvPair_t("offset", offset),
                    kvPair_t("limit",  limit),
                    kvPair_t("meta",   meta),
                    kvPair_t("txPool", txPool),
                }, cfg);
}

json::value GetSubscription(const string& topic, const NKN::Uint256& subscriber, const vector<const string>& cfg);  //TODO
json::value GetSubscription(const string& topic, const string& subscriber, const vector<const string>& cfg) {
    return RPCCall("getsubscription", {
                    kvPair_t("topic", topic),
                    kvPair_t("subscriber", subscriber)
                }, cfg);
}
