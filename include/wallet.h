#ifndef __NKN_WALLET_H__
#define __NKN_WALLET_H__

#include <json/NKNCodec.h>
#include <memory>

#include "include/crypto/crypto.h"
#include "include/crypto/ed25519.h"
#include "include/account.h"
#include "include/walletData.h"

using namespace std;

namespace NKN {

const vector<string> DefaultSeedRPCServerAddr = {"http://seed.nkn.org:30003"};

namespace Wallet {
    typedef struct WalletCfg WalletCfg_t;
    extern const WalletCfg_t DefaultWalletConfig;
    typedef struct WalletCfg {
        AES_IV_t        IV;
        AES_Key_t MasterKey;
        string           Password;
        ScryptCfg_t      ScryptConfig;
        vector<string>   SeedRPCServerAddr;

        // WalletCfg() {}
        inline WalletCfg(const WalletCfg_t& cfg) :
                IV(cfg.IV), MasterKey(cfg.MasterKey), Password(cfg.Password),
                ScryptConfig(cfg.ScryptConfig), SeedRPCServerAddr(cfg.SeedRPCServerAddr) {}
        inline WalletCfg(AES_IV_t iv, AES_Key_t mstKey, string pswd,
                const ScryptCfg_t& cfg=DefaultScryptConfig,
                const vector<string>& rpcSrvs=DefaultSeedRPCServerAddr) :
                    IV(iv), MasterKey(mstKey), Password(pswd), ScryptConfig(cfg), SeedRPCServerAddr(rpcSrvs) {}

        inline static const WalletCfg_t& GetDefaultWalletConfig() { return DefaultWalletConfig; }
        const string GetRandomSeedRPCServerAddr() {
            auto len = SeedRPCServerAddr.size();
            uint32_t r = random_device()() % len;

            if (0 == len) {    // TODO Empty cfg warning
                cerr << "RPC config is Empty. " << len << endl;
                return "";
            }
            return SeedRPCServerAddr[r];
        }

        static shared_ptr<WalletCfg_t> MergeWalletConfig(const shared_ptr<const WalletCfg_t> cfg);

        const WalletCfg_t& operator=(const WalletCfg_t& cfg) {
            IV = cfg.IV;
            MasterKey = cfg.MasterKey;
            Password = cfg.Password;
            ScryptConfig = cfg.ScryptConfig;
            SeedRPCServerAddr = cfg.SeedRPCServerAddr;
            return *this;
        }
        WalletCfg_t& operator&&(const WalletCfg_t& cfg);        // TODO Merge & Update myself with given cfg
        WalletCfg_t& operator&&(const WalletCfg_t& cfg) const;  // TODO Merge cfg with myself and return a new one
        bool isContainedServAddr(const string& s);  // TODO
    } WalletCfg_t;
    const WalletCfg_t DefaultWalletConfig {
        "",
        "",
        "",
        DefaultScryptConfig,
        DefaultSeedRPCServerAddr
    };
    // MergeWalletConfig merges a given wallet config with the default wallet config recursively. Any non zero value fields will override the default config.
    shared_ptr<WalletCfg_t> WalletCfg::MergeWalletConfig(shared_ptr<const WalletCfg_t> cfg) {
        shared_ptr<WalletCfg_t> ret(new WalletCfg_t(DefaultWalletConfig));
        if (cfg) {
            if(cfg->IV)                              ret->IV = cfg->IV;
            if(cfg->MasterKey)                       ret->MasterKey = cfg->MasterKey;
            if(cfg->Password.length() > 0)           ret->Password = cfg->Password;
            if(cfg->ScryptConfig.Salt)               ret->ScryptConfig = cfg->ScryptConfig;   // copy N,R,P together if Salt not empty
            if(cfg->SeedRPCServerAddr.size() > 0)    ret->SeedRPCServerAddr = cfg->SeedRPCServerAddr;
        }
        return ret;
    }

};  // namespace Wallet
};  // namespace NKN

// WalletCfg_t json Parser
template <typename T>
T& operator&(T& jsonCodec, NKN::Wallet::WalletCfg_t &w) {
    jsonCodec.StartObject();
    jsonCodec.Member("IV") & w.IV;
    jsonCodec.Member("MasterKey") & w.MasterKey;
    // jsonCodec.Member("Password") & w.Password;
    jsonCodec.Member("ScryptConfig") & w.ScryptConfig;
    jsonCodec.Member("SeedRPCServerAddr");
    size_t lstLen = w.SeedRPCServerAddr.size();
    jsonCodec.StartArray(&lstLen);
    if (jsonCodec.IsReader)
        w.SeedRPCServerAddr.resize(lstLen);
    for (size_t i = 0; i < lstLen; i++)
        jsonCodec & w.SeedRPCServerAddr[i];
    jsonCodec.EndArray();
    return jsonCodec.EndObject();
}

/* Implement insertion/extration template specialized for Object
 * Otherwise it will match default insertion & extration from json/NKNCodec.h
*/
// template < >
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::WalletCfg_t& w) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::Wallet::WalletCfg_t&>(w);
    return s << out.GetString();
};

// template < >
std::istream& operator>>(std::istream &s, NKN::Wallet::WalletCfg_t& w) {
    string json(istreambuf_iterator<char>(s), *(new istreambuf_iterator<char>()));
    NKN::JSON::Decoder dec(json);
    dec & w;
    return s;
}

namespace NKN{
namespace Wallet{
    typedef struct Wallet Wallet_t;
    typedef struct Wallet {
        shared_ptr<WalletCfg_t> config;
        shared_ptr<Account_t>   account;
        shared_ptr<WalletData_t> walletData;
        string address;

        Wallet(shared_ptr<WalletCfg_t> cfg=NULL,
                shared_ptr<Account_t> acc=NULL, shared_ptr<WalletData_t> data=NULL)
            : config(cfg), account(acc), walletData(data), address( data ? data->Address : "") {}

        inline ED25519::PubKey_t      PubKey()      { return account ? account->PublicKey   : ED25519::PubKey_t(0); }
        inline ED25519::PrivKey_t     Seed()        { return account ? account->PrivateKey  : ED25519::PrivKey_t(0); }
        inline ED25519::ProgramHash_t ProgramHash() { return account ? account->ProgramHash : ED25519::ProgramHash_t(0); }
        inline string Address() { return address; }
    } Wallet_t;

    shared_ptr<Wallet_t> NewWallet(shared_ptr<Account_t> acc, shared_ptr<WalletCfg_t> walletcfg) {
        assert(acc != NULL);
        shared_ptr<WalletData_t> wd(NULL);
        auto cfg = WalletCfg::MergeWalletConfig(walletcfg);

        if(0 != cfg->Password.length() || 0 != cfg->MasterKey) {
            wd = WalletData::NewWalletData(acc, cfg->Password, cfg->MasterKey, cfg->IV,
                    cfg->ScryptConfig.Salt, cfg->ScryptConfig.N, cfg->ScryptConfig.R, cfg->ScryptConfig.P);
        }

        return make_shared<Wallet_t>(cfg, acc, wd);
    }

    shared_ptr<Wallet_t> WalletFromJSON(string jsonStr, shared_ptr<WalletCfg_t> cfg) {
        auto Mergedcfg = WalletCfg::MergeWalletConfig(cfg);
        auto wd = shared_ptr<WalletData>(new WalletData());
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
        return make_shared<Wallet_t>(Mergedcfg, acc, wd);
    }
};  // namespace Wallet
};  // namespace NKN

// WalletData_t json Parser
template <typename T>
T& operator&(T& jsonCodec, NKN::Wallet::Wallet& w) {
    jsonCodec.StartObject();
    jsonCodec.Member("config") & *w.config;
    jsonCodec.Member("account") & *w.account;
    auto p = w.walletData ? w.walletData: NULL;
    if (w.walletData)
        jsonCodec.Member("walletData") & *w.walletData;
    jsonCodec.Member("address") & w.address;
    return jsonCodec.EndObject();
}

std::ostream& operator<<(std::ostream &s, const NKN::Wallet::Wallet& w) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::Wallet::Wallet&>(w);
    return s << out.GetString();
};
#endif  // __NKN_WALLET_H__
