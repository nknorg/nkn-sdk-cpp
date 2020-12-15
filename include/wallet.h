#ifndef __NKN_WALLET_H__
#define __NKN_WALLET_H__

#include <memory>
#include <cassert>

#include "include/crypto/crypto.h"
#include "include/crypto/ed25519.h"
#include "include/account.h"
#include "include/walletData.h"

#include "json/NKNCodec.h"

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
        const string GetRandomSeedRPCServerAddr();

        // MergeWalletConfig merges a given wallet config with the default wallet config recursively. Any non zero value fields will override the default config.
        static shared_ptr<WalletCfg_t> MergeWalletConfig(const shared_ptr<const WalletCfg_t> cfg) {
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

        const WalletCfg_t& operator=(const WalletCfg_t& cfg);
        WalletCfg_t& operator&&(const WalletCfg_t& cfg);        // TODO Merge & Update myself with given cfg
        WalletCfg_t& operator&&(const WalletCfg_t& cfg) const;  // TODO Merge cfg with myself and return a new one
        bool isContainedServAddr(const string& s);  // TODO
    } WalletCfg_t;
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

/*** WalletCfg I/O stream operation ***/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::WalletCfg_t& w);
std::istream& operator>>(std::istream &s, NKN::Wallet::WalletCfg_t& w);

namespace NKN{
namespace Wallet{
    typedef struct Wallet Wallet_t;
    typedef struct Wallet {
        shared_ptr<WalletCfg_t> config;
        shared_ptr<const Account_t>   account;
        shared_ptr<WalletData_t> walletData;
        string address;

        Wallet(shared_ptr<WalletCfg_t> cfg=NULL,
                shared_ptr<const Account_t> acc=NULL, shared_ptr<WalletData_t> data=NULL)
            : config(cfg), account(acc), walletData(data), address( data ? data->Address : "") {}

        inline const Uint512          PrivKey()     { return account ? account->GetPrivateKeyFromSeed() : Uint512(0); }
        inline ED25519::PubKey_t      PubKey()      { return account ? account->PublicKey   : ED25519::PubKey_t(0); }
        inline ED25519::PrivKey_t     Seed()        { return account ? account->PrivateKey  : ED25519::PrivKey_t(0); }
        inline ED25519::ProgramHash_t ProgramHash() { return account ? account->ProgramHash : ED25519::ProgramHash_t(0); }
        inline string Address() { return address; }
    } Wallet_t;

    shared_ptr<Wallet_t> NewWallet(shared_ptr<const Account_t> acc, shared_ptr<WalletCfg_t> walletcfg);

    shared_ptr<Wallet_t> WalletFromJSON(string jsonStr, shared_ptr<WalletCfg_t> cfg);
};  // namespace Wallet
};  // namespace NKN

// Wallet_t json Parser
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

/*** Wallet I/O stream operation ***/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::Wallet& w);
// Disable iStream operation of Wallet_t, instead with NKN::Wallet::WalletFromJSON(from vault keyStore)
// std::istream& operator>>(std::istream &s, NKN::Wallet::Wallet& w);

#endif  // __NKN_WALLET_H__
