#include <iostream>

#include "include/wallet.h"

namespace NKN{
namespace Wallet{
    const string WalletCfg::GetRandomSeedRPCServerAddr() {
        auto len = SeedRPCServerAddr.size();
        uint32_t r = random_device()() % len;

        if (0 == len) {    // TODO Empty cfg warning
    	cerr << "RPC config is Empty. " << len << endl;
    	return "";
        }
        return SeedRPCServerAddr[r];
    }

    const WalletCfg_t DefaultWalletConfig {
        0,      // IV
        0,      // MasterKey
        "",     // Password
        1000,   // RPCTimeout
        1,      // RPCConcurrency
        DefaultScryptConfig,
        DefaultSeedRPCServerAddr
    };

    shared_ptr<Wallet_t> NewWallet(shared_ptr<const Account_t> acc, shared_ptr<WalletCfg_t> walletcfg) {
        assert(acc != NULL);
        shared_ptr<WalletData_t> wd(NULL);
        auto cfg = WalletCfg::MergeWalletConfig(walletcfg);

        if(0 != cfg->Password.length() || 0 != cfg->MasterKey) {
            wd = WalletData::NewWalletData(acc, cfg->Password, cfg->MasterKey, cfg->IV,
                    cfg->ScryptConfig.Salt, cfg->ScryptConfig.N, cfg->ScryptConfig.R, cfg->ScryptConfig.P);
        }

        return make_shared<Wallet_t>(acc, cfg, wd);
    }

    shared_ptr<Wallet_t> WalletFromJSON(string jsonStr, shared_ptr<WalletCfg_t> cfg) {
        auto Mergedcfg = WalletCfg::MergeWalletConfig(cfg);
        auto wd = make_shared<WalletData>();
        NKN::JSON::Decoder dec(jsonStr);

        dec & *wd;

        if ( ! wd->isSupportedVer() ) {
            fprintf(stderr, "Only support V2 wallet at current\n");
            return NULL;
        }

        auto acc = wd->DecryptAccount(Mergedcfg->Password);
        if ( 0 != acc->WalletAddress().compare(wd->Address) ) {
            fprintf(stderr, "Wrong Password\n");
            return NULL;
        }
        return make_shared<Wallet_t>(acc, Mergedcfg, wd);
    }
};  // namespace Wallet
};  // namespace NKN

/* Implement insertion/extration template specialized for Object
 * Otherwise it will match default insertion & extration from json/NKNCodec.h
*/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::WalletCfg_t& w) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::Wallet::WalletCfg_t&>(w);
    return s << out.GetString();
};

std::istream& operator>>(std::istream &s, NKN::Wallet::WalletCfg_t& w) {
    string json(istreambuf_iterator<char>(s), *(new istreambuf_iterator<char>()));
    NKN::JSON::Decoder dec(json);
    dec & w;
    return s;
}

std::ostream& operator<<(std::ostream &s, const NKN::Wallet::Wallet& w) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::Wallet::Wallet&>(w);
    return s << out.GetString();
};
