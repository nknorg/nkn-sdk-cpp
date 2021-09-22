#include "tuna/config.h"

namespace NKN {
namespace TUNA {

using namespace std;

const DialConfig_t defaultDialConfig {
    .DialTimeout = 0,
    .SessionConfig = nullptr,
};

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

};  // namespace TUNA
};  // namespace NKN
