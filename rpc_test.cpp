#include <iostream>
#include <vector>
#include <initializer_list>

#include <cpprest/json.h>
#include <cpprest/http_client.h>
#include <cpprest/interopstream.h>

#include "include/rpc.h"

using namespace std;
using namespace web;

int main(int argc, char* argv[]) {
    json::value params = json::value::object();
    random_device rd;

    string uri(argv[1]);
    string method(argv[2]);
    for (int i=3; i<argc; i++) {    // kvPair from argv[]
        string k,v;
        istringstream ss(argv[i]);
        if (getline(ss, k, '=') && getline(ss, v))
            params[U(k)] = json::value(v);
    }

    // type convertor
    if(params.has_field("offset")) {
        int32_t offset = stoul(params[U("offset")].as_string());
        params[U("offset")] = json::value(offset);
    }
    if(params.has_field("limit")) {
        int32_t limit = stoul(params[U("limit")].as_string());
        params[U("limit")] = json::value(limit);
    }
    if(params.has_field("meta")) {
        if(0 == params["meta"].as_string().compare("true")) {
            params["meta"] = json::value(true);
        } else {
            params["meta"] = json::value(false);
        }
    }
    if(params.has_field("txPool")) {
        if(0 == params["txPool"].as_string().compare("true")) {
            params["txPool"] = json::value(true);
        } else {
            params["txPool"] = json::value(false);
        }
    }

    auto js = RPCCall(method, params);
    cout << js << endl;
}
