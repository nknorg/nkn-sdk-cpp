#ifndef __NKN_WALLET_H__
#define __NKN_WALLET_H__

#include <json/NKNCodec.h>
#include <memory>

#include "include/crypto/crypto.h"
#include "include/crypto/ed25519.h"

using namespace std;

namespace NKN {

const vector<string> DefaultSeedRPCServerAddr = {"http://seed.nkn.org:30003"};

namespace Wallet {
    typedef struct ScryptCfg ScryptData_t;
    typedef struct ScryptCfg ScryptCfg_t;
    struct ScryptCfg {
        Uint64 Salt;
        int N;
        int R;
        int P;

        ScryptCfg() : Salt(), N(), R(), P() {}
        ScryptCfg(const ScryptCfg_t& s) : Salt(s.Salt), N(s.N), R(s.R), P(s.P) {}
        ScryptCfg(const Uint64& salt, int N=32768, int R=8, int P=1) : Salt(salt), N(N), R(R), P(P) {}
        ~ScryptCfg() {}

        const ScryptCfg_t& operator=(const ScryptCfg_t& cfg) {
            Salt = cfg.Salt;
            N = cfg.N;
            R = cfg.R;
            P = cfg.P;
            return *this;
        }

        bool isValidCfg();  // TODO Check N/R/P

        // ScryptCfg::Random will generated a ScryptCfg with a random salt
        static shared_ptr<ScryptCfg_t> Random(int N=32768, int R=8, int P=1) {
            auto u64_ptr = Uint64::Random<shared_ptr<Uint64>>();
            return shared_ptr<ScryptCfg_t>(new ScryptCfg(*u64_ptr, N, R, P));
        }
    };
    const ScryptCfg_t DefaultScryptConfig(0);

    inline static const Uint256 PasswordToAesKeyScrypt(const string& pswd, const ScryptData_t& data) {
        return SCRYPT<Uint256>::KeyDerive(pswd, data.Salt, data.N, data.R, data.P);
    }

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

    typedef struct Account Account_t;
    struct Account {
        // const Account member since PubKey & ProgramHash should be determined by PrivKey.
        // They should not be modified anymore after constructed.
        const ED25519::PrivKey_t     PrivateKey;
        const ED25519::PubKey_t      PublicKey;
        const ED25519::ProgramHash_t ProgramHash;

        Account(const Account_t* acc) = delete; // explicit forbidden copy account for security consideration
        Account(const Account_t& acc) = delete; // explicit forbidden copy account for security consideration
        Account() :
            PrivateKey(),   // generated PrivKey from random
            PublicKey(PrivateKey.PublicKey()),
            ProgramHash(PublicKey.toProgramHash()) {}
        Account(const ED25519::PrivKey_t& seed) :
            PrivateKey(seed),   // generated PrivKey from given seed
            PublicKey(PrivateKey.PublicKey()),
            ProgramHash(PublicKey.toProgramHash()) {}

        // For compatible with sdk-go API
        inline static shared_ptr<const Account_t> const NewAccount() { return shared_ptr<const Account_t>(new Account()); }
        inline static shared_ptr<const Account_t> const NewAccount(ED25519::PrivKey_t seed) { return make_shared<const Account_t>(seed); }
        inline const string WalletAddress() { return ProgramHash.toAddress(); }
    };

    typedef struct WalletData WalletData_t;
    struct WalletData {
        /* enum WalletVer {
            V1 = 1,
            V2 = 2,
        };
        WalletVer Version; */
        static constexpr uint32_t V1 = 1;
        static constexpr uint32_t V2 = 2;
        uint32_t  Version;
        AES_IV_t  IV;
        AES_Key_t MasterKey;
        Uint256   SeedEncrypted;
        string    Address;
        shared_ptr<ScryptCfg_t>      ScryptData;

        // WalletData() : Version(V2) {}
        WalletData(shared_ptr<ScryptCfg_t> cfg=NULL) : Version(V2), ScryptData(cfg) {
            if (ScryptData == NULL)
                ScryptData = make_shared<ScryptCfg_t>();
        }
        WalletData(shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t& mstKey = Uint256::Random<Uint256>(),
                const AES_IV_t&  iv     = Uint128::Random<Uint128>(),
                const Salt_t&    salt   = Uint64::Random<Uint64>(),
                int N=32768, int R=8, int P=1)
            : WalletData(acc, pswd, mstKey, iv, make_shared<ScryptCfg_t>(salt,N,R,P)) {}
        /* WalletData(shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t&& mstKey = *Uint256::Random<shared_ptr<Uint256>>(),
                const AES_IV_t&&  iv     = *Uint128::Random<shared_ptr<Uint128>>(),
                const Salt_t&&    salt   = *Uint64::Random<shared_ptr<Uint64>>(),
                int N=32768, int R=8, int P=1);  //TODO */
        WalletData(shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t& mstKey = *Uint256::Random<shared_ptr<Uint256>>(),
                const AES_IV_t&  iv     = *Uint128::Random<shared_ptr<Uint128>>(),
                shared_ptr<ScryptCfg_t> cfg=ScryptCfg::Random())
            : Version(V2), IV(iv), ScryptData(cfg)
        {
            if (!ScryptData->N) ScryptData->N=32768;
            if (!ScryptData->R) ScryptData->R=8;
            if (!ScryptData->P) ScryptData->P=1;
            if (!ScryptData->Salt) ScryptData->Salt = Uint64::Random<Uint64>();
            if (!IV) IV = Uint128::Random<Uint128>();

            auto key = mstKey ? mstKey : Uint256::Random<Uint256>();

            if ( ! isSupportedVer() ) { /* TODO: log unsupport error and throw */ }

            Uint256 pswdKey = PasswordToAesKeyScrypt(pswd, *ScryptData);
            AES<Uint256> aesMstKey(pswdKey, IV);
            MasterKey = aesMstKey.Enc(key);

            AES<Uint256> aesSeed(key, IV);
            SeedEncrypted = aesSeed.Enc(acc->PrivateKey);

            Address = acc->PrivateKey.PublicKey().toProgramHash().toAddress();
        }

        // For compatible with sdk-go API
        inline static shared_ptr<WalletData_t> NewWalletData(
                shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t& mstKey = *Uint256::Random<shared_ptr<Uint256>>(),
                const AES_IV_t&  iv     = *Uint128::Random<shared_ptr<Uint128>>(),
                const Salt_t&    salt   = *Uint64::Random<shared_ptr<Uint64>>(),
                int N=32768, int R=8, int P=1) {
            return shared_ptr<WalletData_t>(new WalletData(acc, pswd, mstKey, iv, salt, N, R, P));
        }

        inline bool isSupportedVer() {
            switch (Version) {
                case V2:
                    return true;
                case V1:   // TODO support obsole V1 wallet in cpp sdk
                default:   // TODO log unsupport error
                    fprintf(stdout, "%s:%d Unsupport wallet version %d\n", __PRETTY_FUNCTION__, __LINE__, Version);
            }
            return false;
        }

        shared_ptr<AES_Key_t> DecryptMasterKey(const string& pswd) {
            if ( ! isSupportedVer() )
                return NULL;   // TODO log unsupport error

            Uint256 pswdKey = PasswordToAesKeyScrypt(pswd, *ScryptData);
            AES<shared_ptr<AES_Key_t>> aes(pswdKey, IV/*, "aes-256-cbc"*/);
            return aes.Dec(MasterKey);
        }

        shared_ptr<Account_t> DecryptAccount(const string& pswd) {
            auto plainMstKey = DecryptMasterKey(pswd);
            auto seed = AES<Uint256>(*plainMstKey, IV).Dec(SeedEncrypted);
            return make_shared<Account_t>(seed);
        }
    };
};  // namespace Wallet
};  // namespace NKN

// Account_t json Parser
template <typename T>
T& operator&(T& jsonCodec, const NKN::Wallet::Account_t &acc) {
    jsonCodec.StartObject();
    jsonCodec.Member("PrivateKey") & acc.PrivateKey;
    jsonCodec.Member("PublicKey") & acc.PublicKey;
    jsonCodec.Member("ProgramHash") & acc.ProgramHash;
    return jsonCodec.EndObject();
}

std::ostream& operator<<(std::ostream &s, const NKN::Wallet::Account_t &acc) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::Wallet::Account_t&>(acc);
    return s << out.GetString();
}
/* Unnecessary restore Account_t from plain text json
std::istream& operator>>(std::istream &s, NKN::Wallet::Account_t &acc) {
    string json(istreambuf_iterator<char>(s), *(new istreambuf_iterator<char>()));
    NKN::JSON::Decoder dec(json);
    dec & acc;
    return s;
} */

// Scrypt_t json Parser
template <typename T>
T& operator&(T &jsonCodec, NKN::Wallet::ScryptCfg_t &s) {
    jsonCodec.StartObject();
    jsonCodec.Member("Salt") & s.Salt;
    jsonCodec.Member("N") & s.N;
    jsonCodec.Member("R") & s.R;
    jsonCodec.Member("P") & s.P;
    return jsonCodec.EndObject();
}

/* Implement insertion/extration template specialized for Object
 * Otherwise it will match default insertion & extration from json/NKNCodec.h
 */
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::ScryptCfg_t &n) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::Wallet::ScryptCfg_t&>(n);
    return s << out.GetString();
}

std::istream& operator>>(std::istream &s, NKN::Wallet::ScryptCfg_t &n) {
    string json(istreambuf_iterator<char>(s), *(new istreambuf_iterator<char>()));
    NKN::JSON::Decoder dec(json);
    dec & n;
    return s;
}

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

// WalletData_t json Parser
template <typename T>
T& operator&(T& jsonCodec, NKN::Wallet::WalletData_t &wd) {
    jsonCodec.StartObject();
    jsonCodec.Member("Version") & wd.Version;
    jsonCodec.Member("IV") & wd.IV;
    jsonCodec.Member("MasterKey") & wd.MasterKey;
    jsonCodec.Member("SeedEncrypted") & wd.SeedEncrypted;
    jsonCodec.Member("Address") & wd.Address;
    jsonCodec.Member("Scrypt") & *wd.ScryptData;
    return jsonCodec.EndObject();
}

/* Implement insertion/extration template specialized for WalletData_t
 * Otherwise it will match default insertion & extration from json/NKNCodec.h
*/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::WalletData_t& wd) {
    NKN::JSON::Encoder out;
    out & const_cast<NKN::Wallet::WalletData_t&>(wd);
    return s << out.GetString();
};

std::istream& operator>>(std::istream &s, NKN::Wallet::WalletData_t& wd) {
    string json(istreambuf_iterator<char>(s), *(new istreambuf_iterator<char>()));
    NKN::JSON::Decoder dec(json);
    dec & wd;
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

    static shared_ptr<Wallet_t> NewWallet(shared_ptr<Account_t> acc, shared_ptr<WalletCfg_t> walletcfg) {
        assert(acc != NULL);
        shared_ptr<WalletData_t> wd(NULL);
        auto cfg = WalletCfg::MergeWalletConfig(walletcfg);

        if(0 != cfg->Password.length() || 0 != cfg->MasterKey) {
            wd = WalletData::NewWalletData(acc, cfg->Password, cfg->MasterKey, cfg->IV,
                    cfg->ScryptConfig.Salt, cfg->ScryptConfig.N, cfg->ScryptConfig.R, cfg->ScryptConfig.P);
        }

        return make_shared<Wallet_t>(cfg, acc, wd);
    }

    static shared_ptr<Wallet_t> WalletFromJSON(string jsonStr, shared_ptr<WalletCfg_t> cfg) {
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
