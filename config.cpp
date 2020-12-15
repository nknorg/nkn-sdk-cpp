#include <iostream>
#include <array>
#include <vector>
#include <random>

#include "include/rpc.h"

using namespace std;

extern const vector<const string> DefaultRPCConfig;
const vector<const string> DefaultRPCConfig = {{"http://seed.nkn.org:30003"}};

// Copy construction from const DefaultRPCConfig and return a mutable RPCConfig
inline vector<const string> GetDefaultRPCConfig() {
    return vector<const string>(DefaultRPCConfig.begin(), DefaultRPCConfig.end());
}

const string GetRandomSeedRPCServerAddr(const vector<const string>& cfg) {
    random_device rd;
    if (0 == cfg.size()) {    // TODO Empty cfg warning
        cerr << "RPC config is Empty. " << cfg.size() << endl;
        return "";
    }
    return cfg[ rd() % cfg.size() ];
}
