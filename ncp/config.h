#ifndef __NCP_CONFIG_H__
#define __NCP_CONFIG_H__

#include <iostream>
#include <memory>

#include "json/NKNCodec.h"

namespace NKN {
namespace NCP {
typedef class Session Session_t;
typedef struct Config Config_t;
struct Config {
    bool     NonStream;
    uint32_t SessionWindowSize;            // in bytes
    uint32_t MTU;                          // in bytes
    uint32_t InitialConnectionWindowSize;  // in packets
    uint32_t MaxConnectionWindowSize;      // in packets
    uint32_t MinConnectionWindowSize;      // in packets
    uint32_t MaxAckSeqListSize;
    uint32_t FlushInterval;                // in millisecond
    uint32_t Linger;                       // in millisecond
    uint32_t InitialRetransmissionTimeout; // in millisecond
    uint32_t MaxRetransmissionTimeout;     // in millisecond
    uint32_t SendAckInterval;              // in millisecond
    uint32_t CheckTimeoutInterval;         // in millisecond
    uint32_t CheckBytesReadInterval;       // in millisecond
    uint32_t SendBytesReadThreshold;       // in millisecond

    Config() = default;
    Config(const Config_t& cfg) = default;
    Config_t& operator=(const Config_t& cfg) = default;

    inline const Config_t& MergeConfig(const std::shared_ptr<Config_t>& cfg) {
        return cfg ? MergeConfig(*cfg) : *this;
    }
    const Config_t& MergeConfig(const Config_t& cfg);

    static std::shared_ptr<Config_t> MergeDefaultConfig(std::shared_ptr<Config_t> cfg);
};
extern const Config_t DefaultConfig;

}; // namespace NCP
}; // namespace NKN

// NCP::Config_t json Parser
template <typename T>
T& operator&(T& jsonCodec, NKN::NCP::Config_t &cfg) {
    jsonCodec.StartObject();
    jsonCodec.Member("NonStream") & cfg.NonStream;
    jsonCodec.Member("SessionWindowSize") & cfg.SessionWindowSize;
    jsonCodec.Member("MTU") & cfg.MTU;
    jsonCodec.Member("InitialConnectionWindowSize") & cfg.InitialConnectionWindowSize;
    jsonCodec.Member("MaxConnectionWindowSize") & cfg.MaxConnectionWindowSize;
    jsonCodec.Member("MinConnectionWindowSize") & cfg.MinConnectionWindowSize;
    jsonCodec.Member("MaxAckSeqListSize") & cfg.MaxAckSeqListSize;
    jsonCodec.Member("FlushInterval") & cfg.FlushInterval;
    jsonCodec.Member("Linger") & cfg.Linger;
    jsonCodec.Member("InitialRetransmissionTimeout") & cfg.InitialRetransmissionTimeout;
    jsonCodec.Member("MaxRetransmissionTimeout") & cfg.MaxRetransmissionTimeout;
    jsonCodec.Member("SendAckInterval") & cfg.SendAckInterval;
    jsonCodec.Member("CheckTimeoutInterval") & cfg.CheckTimeoutInterval;
    jsonCodec.Member("CheckBytesReadInterval") & cfg.CheckBytesReadInterval;
    jsonCodec.Member("SendBytesReadThreshold") & cfg.SendBytesReadThreshold;
    return jsonCodec.EndObject();
}

/*** NCP::Config_t I/O stream operation ***/
std::ostream& operator<<(std::ostream &s, const NKN::NCP::Config_t& cfg);
std::istream& operator>>(std::istream &s, NKN::NCP::Config_t& cfg);

#endif // __NCP_CONFIG_H__
