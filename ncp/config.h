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

    const Config_t& MergeConfig(const std::shared_ptr<Config_t>& cfg) {
        return cfg ? MergeConfig(*cfg) : *this;
    }
    const Config_t& MergeConfig(const Config_t& cfg) {
        NonStream = cfg.NonStream;
        if (cfg.SessionWindowSize > 0)	            SessionWindowSize = cfg.SessionWindowSize;
        if (cfg.MTU > 0)	                        MTU = cfg.MTU;
        if (cfg.InitialConnectionWindowSize > 0)	InitialConnectionWindowSize = cfg.InitialConnectionWindowSize;
        if (cfg.MaxConnectionWindowSize > 0)	    MaxConnectionWindowSize = cfg.MaxConnectionWindowSize;
        if (cfg.MinConnectionWindowSize > 0)	    MinConnectionWindowSize = cfg.MinConnectionWindowSize;
        if (cfg.MaxAckSeqListSize > 0)              MaxAckSeqListSize = cfg.MaxAckSeqListSize;
        if (cfg.FlushInterval > 0)	                FlushInterval = cfg.FlushInterval;
        if (cfg.Linger > 0)	                        Linger = cfg.Linger;
        if (cfg.InitialRetransmissionTimeout > 0)	InitialRetransmissionTimeout = cfg.InitialRetransmissionTimeout;
        if (cfg.MaxRetransmissionTimeout > 0)	    MaxRetransmissionTimeout = cfg.MaxRetransmissionTimeout;
        if (cfg.SendAckInterval > 0)	            SendAckInterval = cfg.SendAckInterval;
        if (cfg.CheckTimeoutInterval > 0)	        CheckTimeoutInterval = cfg.CheckTimeoutInterval;
        if (cfg.CheckBytesReadInterval > 0)	    CheckBytesReadInterval = cfg.CheckBytesReadInterval;
        if (cfg.SendBytesReadThreshold > 0)	    SendBytesReadThreshold = cfg.SendBytesReadThreshold;
        return *this;
    }

    static std::shared_ptr<Config_t> MergeDefaultConfig(std::shared_ptr<Config_t> cfg);
};

constexpr Config_t DefaultConfig {
      .NonStream                    = false,
      .SessionWindowSize            = 4 << 20,
      .MTU                          = 1024,
      .InitialConnectionWindowSize  = 16,
      .MaxConnectionWindowSize      = 256,
      .MinConnectionWindowSize      = 1,
      .MaxAckSeqListSize            = 32,
      .FlushInterval                = 10,
      .Linger                       = 1000,
      .InitialRetransmissionTimeout = 5000,
      .MaxRetransmissionTimeout     = 10000,
      .SendAckInterval              = 50,
      .CheckTimeoutInterval         = 50,
      .CheckBytesReadInterval       = 100,
      .SendBytesReadThreshold       = 200,
};

std::shared_ptr<Config_t> Config::MergeDefaultConfig(std::shared_ptr<Config_t> cfg) {
    auto ret = std::make_shared<Config_t>(DefaultConfig);
    ret->MergeConfig(cfg);
    return ret;
}
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
std::ostream& operator<<(std::ostream &s, const NKN::NCP::Config_t& cfg) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::NCP::Config_t&>(cfg);
    return s << out.GetString();
}

std::istream& operator>>(std::istream &s, NKN::NCP::Config_t& cfg) {
    std::string json(std::istreambuf_iterator<char>(s), *(new std::istreambuf_iterator<char>()));
    NKN::JSON::Decoder dec(json);
    dec & cfg;
    return s;
}

#endif // __NCP_CONFIG_H__
