#ifndef __NKN_TUNA_CFG_H__
#define __NKN_TUNA_CFG_H__

#include <string>
#include <memory>

#include "ncp/config.h"

namespace NKN {
namespace TUNA {

using namespace std;

const string DefaultSubscriptionPrefix = "tuna_v1.";
const string DefaultReverseServiceName = "reverse";

typedef struct Config Config_t;
extern const Config_t defaultConfig;

typedef struct DialConfig   DialConfig_t;
extern  const  DialConfig_t defaultDialConfig;

struct DialConfig {
    int32_t DialTimeout;    //in millisecond
    shared_ptr<NCP::Config_t>   SessionConfig;

    DialConfig() = default;
    DialConfig(const DialConfig& cfg) = default;
    DialConfig& operator=(const DialConfig& cfg) = default;

    inline DialConfig& MergeConfig(const shared_ptr<DialConfig_t> cfg) {
        return cfg ? MergeConfig(*cfg) : *this;
    }
    DialConfig& MergeConfig(const DialConfig_t& cfg) {
        if (cfg.DialTimeout)
            DialTimeout = cfg.DialTimeout;
        SessionConfig->MergeConfig(cfg.SessionConfig);
        return *this;
    }

    inline static shared_ptr<DialConfig_t> DefaultDialConfig(const shared_ptr<NCP::Config_t>& cfg) {
        auto ptr = make_shared<DialConfig_t>(defaultDialConfig);
        ptr->SessionConfig = make_shared<NCP::Config_t>(*cfg);
        return ptr;
    }

    static shared_ptr<DialConfig_t> MergeDialConfig(const shared_ptr<NCP::Config_t> ncpCfg, const shared_ptr<DialConfig> dialCfg) {
        auto ptr = DefaultDialConfig(ncpCfg);
        ptr->MergeConfig(dialCfg);
        return ptr;
    }
};

const DialConfig_t defaultDialConfig {
    .DialTimeout = 0,
    .SessionConfig = nullptr,
};

extern const NCP::Config_t defaultSessionConfig;
inline shared_ptr<NCP::Config_t> DefaultSessionConfig();

struct Config {
public:
    Config() = default;
    Config(const Config& cfg) = default;
    Config& operator=(const Config& cfg) = default;

	int NumTunaListeners;
	int TunaDialTimeout;    // in millisecond
	bool TunaDownloadGeoDB;
	bool TunaMeasureBandwidth;
	string TunaMaxPrice;
	string TunaNanoPayFee;
	string TunaServiceName;
	string TunaGeoDBPath;
	string TunaSubscriptionPrefix;
	string TunaMeasureStoragePath;
	// TunaIPFilter           *geo.IPFilter
    shared_ptr<NCP::Config_t> SessionConfig;

    inline static shared_ptr<Config_t> DefaultConfig() {
        auto ptr = make_shared<Config_t>(defaultConfig);
        ptr->SessionConfig = DefaultSessionConfig();
        return ptr;
    }

    static shared_ptr<Config_t> MergedConfig(const Config_t& cfg) {
        auto ptr = DefaultConfig();

        ptr->TunaDownloadGeoDB    = cfg.TunaDownloadGeoDB;
        ptr->TunaMeasureBandwidth = cfg.TunaMeasureBandwidth;

        if (cfg.NumTunaListeners)   ptr->NumTunaListeners = cfg.NumTunaListeners;
        if (cfg.TunaDialTimeout)    ptr->TunaDialTimeout  = cfg.TunaDialTimeout;
        if (cfg.TunaMaxPrice.length())  ptr->TunaMaxPrice = cfg.TunaMaxPrice;
        if (cfg.TunaNanoPayFee.length())  ptr->TunaNanoPayFee = cfg.TunaNanoPayFee;
        if (cfg.TunaServiceName.length()) ptr->TunaServiceName= cfg.TunaServiceName;
        if (cfg.TunaGeoDBPath.length())   ptr->TunaGeoDBPath  = cfg.TunaGeoDBPath;
        if (cfg.TunaSubscriptionPrefix.length()) ptr->TunaSubscriptionPrefix = cfg.TunaSubscriptionPrefix;
        if (cfg.TunaMeasureStoragePath.length()) ptr->TunaMeasureStoragePath = cfg.TunaMeasureStoragePath;

        ptr->SessionConfig->MergeConfig(cfg.SessionConfig);
        return ptr;
    }
    inline static shared_ptr<Config_t> MergedConfig(shared_ptr<Config_t> cfg) {
        return cfg ? MergedConfig(*cfg) : DefaultConfig();
    }
};  // struct Config

const Config_t defaultConfig = {
    .NumTunaListeners = 4,
    .TunaDialTimeout  = 10*1000,
    .TunaDownloadGeoDB = false,
    .TunaMeasureBandwidth = false,
    .TunaMaxPrice     = "0",
    .TunaNanoPayFee   = "0",
    .TunaServiceName  = DefaultReverseServiceName,
    .TunaGeoDBPath    = "",
    .TunaSubscriptionPrefix = DefaultSubscriptionPrefix,
    .TunaMeasureStoragePath = "",
    // .TunaIPFilter     = nullptr,
    .SessionConfig    = nullptr,
};

constexpr NCP::Config_t defaultSessionConfig = {
    .MTU = 1300,
};

inline shared_ptr<NCP::Config_t> DefaultSessionConfig() {
    return make_shared<NCP::Config_t>(defaultSessionConfig);
}

};  // namespace TUNA
};  // namespace NKN
#endif  // __NKN_TUNA_CFG_H__
