#include "client/config.h"

namespace NKN {
namespace Client {

const Client::ClientConfig_t DefaultClientConfig = {
    .SeedRPCServerAddr = nullptr,
	.RPCTimeout        = 10000,
	.RPCConcurrency    = 1,
	.MsgChanLen        = 1024,
	.ConnectRetries    = 3,
	.MsgCacheExpiration= 300000,
	.MsgCacheCleanupInterval = 60000,
	.WsHandshakeTimeout= 5000,
	.WsWriteTimeout    = 10000,
	.MinReconnectInterval = 1000,
	.MaxReconnectInterval = 64000,
	.MessageConfig     = nullptr,
	.SessionConfig     = nullptr,
};
};  // namespace Client
};  // namespace NKN

std::ostream& operator<<(std::ostream &s, const vector<string>& vec) {
    s << "[ ";
    for (auto& e: vec)
        s << e << ", ";
    return s << " ]" << endl;
}
