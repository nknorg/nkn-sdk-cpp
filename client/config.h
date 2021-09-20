#ifndef __NKN_CLIENT_CFG_H__
#define __NKN_CLIENT_CFG_H__

#include <iostream>
#include <vector>
#include <memory>

#include "include/uBigInt.h"
#include "ncp/config.h"

using namespace std;

namespace NKN {
namespace Client {

const vector<string> DefaultSeedRPCServerAddr = {"http://seed.nkn.org:30003"};

typedef struct MessageConfig MessageConfig_t;
struct MessageConfig {
	bool Unencrypted;          // Whether message body should be unencrypted. It is not recommended to send unencrypted message as anyone in the middle can see the message content.
	bool NoReply;              // Indicating the message will not have any reply or ACK, so client will not allocate any resources waiting for it.
	int32_t MaxHoldingSeconds; // Message will be held at node for at most this time if the destination client is not online. Note that message might be released earlier than this time if node runs out of resources.
	shared_ptr<Uint64> MessageID; // Message ID. If nil, a random ID will be generated for each message. MessageID should be unique per message and has size MessageIDSize.

	bool TxPool;    // Whether to include subscribers in txpool when publishing.
	int32_t Offset; // Offset for getting subscribers.
	int32_t Limit;  // Single request limit for getting subscribers

    MessageConfig() = default;
    MessageConfig(const MessageConfig& cfg) = default;
    MessageConfig& operator=(const MessageConfig& cfg) = default;

    const MessageConfig_t& MergeConfig(const std::shared_ptr<MessageConfig_t> cfg) {
        return cfg ? MergeConfig(*cfg) : *this;
    }
    const MessageConfig_t& MergeConfig(const MessageConfig_t& cfg) {
        Unencrypted = cfg.Unencrypted;
        NoReply = cfg.NoReply;
        TxPool = cfg.TxPool;
        if (cfg.MaxHoldingSeconds)  MaxHoldingSeconds = cfg.MaxHoldingSeconds;
        if (MessageID)  MessageID = cfg.MessageID;
        if (Offset) Offset = cfg.Offset;
        if (Limit)  Limit= cfg.Limit;
        return *this;
    }
};
const MessageConfig_t DefaultMessageConfig = {
    .Unencrypted = false,
    .NoReply     = false,
    .MaxHoldingSeconds = 0,
    .MessageID   = nullptr,
    .TxPool      = false,
    .Offset      = 0,
    .Limit       = 1000,
};

constexpr NCP::Config_t DefaultSessionConfig = {
    .MTU = 1024,
};

typedef struct ClientConfig ClientConfig_t;
extern const ClientConfig_t DefaultClientConfig;
struct ClientConfig {
    shared_ptr<vector<string>> SeedRPCServerAddr;   // Seed RPC server address that client uses to find its node and make RPC requests (e.g. get subscribers).
	int32_t RPCTimeout;               // Timeout for each RPC call in millisecond
	int32_t RPCConcurrency;           // If greater than 1, the same rpc request will be concurrently sent to multiple seed rpc nodes
	int32_t MsgChanLen;               // Channel length for received but unproccessed messages.
	int32_t ConnectRetries;           // Connnect to node retries (including the initial connect). 0 means unlimited retries.
	int32_t MsgCacheExpiration;       // Message cache expiration in millisecond for response channel, multiclient message id deduplicate, etc.
	int32_t MsgCacheCleanupInterval;  // Message cache cleanup interval in millisecond.
	int32_t WsHandshakeTimeout;       // WebSocket handshake timeout in millisecond.
	int32_t WsWriteTimeout;           // WebSocket write timeout in millisecond.
	int32_t MinReconnectInterval;     // Min reconnect interval in millisecond.
	int32_t MaxReconnectInterval;     // Max reconnect interval in millisecond.
    shared_ptr<MessageConfig_t> MessageConfig; // Default message config of the client if per-message config is not provided.
    shared_ptr<NCP::Config_t>   SessionConfig; // Default session config of the client if per-session config is not provided.

    ClientConfig() = default;
    ClientConfig(const ClientConfig& cfg) = default;
    ClientConfig& operator=(const ClientConfig& cfg) = default;

    const ClientConfig_t& MergeConfig(const std::shared_ptr<ClientConfig_t> cfg) {
        if (!SeedRPCServerAddr)
            SeedRPCServerAddr   = make_shared<vector<string>>(DefaultSeedRPCServerAddr);
        return cfg ? MergeConfig(*cfg) : *this;
    }
    const ClientConfig_t& MergeConfig(const ClientConfig_t& cfg) {
        if (cfg.SeedRPCServerAddr) {
            if (SeedRPCServerAddr) {
                SeedRPCServerAddr->insert(SeedRPCServerAddr->end(), cfg.SeedRPCServerAddr->cbegin(), cfg.SeedRPCServerAddr->cend());
            } else {
                SeedRPCServerAddr = cfg.SeedRPCServerAddr;
            }
        }
        if (!SeedRPCServerAddr)         SeedRPCServerAddr   = make_shared<vector<string>>(DefaultSeedRPCServerAddr);
        if (cfg.RPCTimeout)             RPCTimeout          = cfg.RPCTimeout;
        if (cfg.RPCConcurrency)         RPCConcurrency      = cfg.RPCConcurrency;
        if (cfg.MsgChanLen)             MsgChanLen          = cfg.MsgChanLen;
        if (cfg.ConnectRetries)         ConnectRetries      = cfg.ConnectRetries;
        if (cfg.MsgCacheExpiration)     MsgCacheExpiration  = cfg.MsgCacheExpiration;
        if (cfg.MsgCacheCleanupInterval)MsgCacheCleanupInterval = cfg.MsgCacheCleanupInterval;
        if (cfg.WsHandshakeTimeout)     WsHandshakeTimeout  = cfg.WsHandshakeTimeout;
        if (cfg.WsWriteTimeout)         WsWriteTimeout      = cfg.WsWriteTimeout;
        if (cfg.MinReconnectInterval)   MinReconnectInterval= cfg.MinReconnectInterval;
        if (cfg.MaxReconnectInterval)   MaxReconnectInterval= cfg.MaxReconnectInterval;

        MessageConfig->MergeConfig(cfg.MessageConfig);
        SessionConfig->MergeConfig(cfg.SessionConfig);
        return *this;
    }

    static shared_ptr<ClientConfig_t> GetDefaultClientConfig() {
        auto ptr = make_shared<ClientConfig_t>(DefaultClientConfig);
        ptr->SeedRPCServerAddr = make_shared<vector<string>>(DefaultSeedRPCServerAddr);
        ptr->MessageConfig     = make_shared<MessageConfig_t>(DefaultMessageConfig);
        ptr->SessionConfig     = make_shared<NCP::Config_t>(DefaultSessionConfig);

        return ptr;
    }

    static shared_ptr<ClientConfig_t> MergeClientConfig(shared_ptr<ClientConfig_t> cfg) {
        auto ptr = GetDefaultClientConfig();
        ptr->MergeConfig(cfg);

        if (!ptr->SeedRPCServerAddr || !ptr->SeedRPCServerAddr->size())
            ptr->SeedRPCServerAddr = make_shared<vector<string>>(DefaultSeedRPCServerAddr);

        return ptr;
    }
};

extern const ClientConfig_t DefaultClientConfig;

};  // namespace Client
};  // namespace NKN

std::ostream& operator<<(std::ostream &s, const vector<string>& vec);
#endif  // __NKN_CLIENT_CFG_H__
