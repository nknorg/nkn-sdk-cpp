#ifndef __NKN_WALLET_DATA_H__
#define __NKN_WALLET_DATA_H__

#include <memory>

#include "include/crypto/crypto.h"
#include "include/account.h"

#include "json/NKNCodec.h"

using namespace std;

/*****************
 * Scrypt Config *
 *****************/

namespace NKN {
namespace Wallet {
    typedef struct ScryptCfg ScryptData_t;
    typedef struct ScryptCfg ScryptCfg_t;
    struct ScryptCfg {
        Uint64 Salt;
        int N;
        int R;
        int P;

        ScryptCfg() = default;
        ScryptCfg(const ScryptCfg_t& s) = default;
        ScryptCfg(const Uint64& salt, int N=32768, int R=8, int P=1): Salt(salt), N(N), R(R), P(P) {}
        ~ScryptCfg() = default;

        ScryptCfg_t& operator=(const ScryptCfg_t& cfg) = default;

        bool isValidCfg();  // TODO Check N/R/P

        // ScryptCfg::Random will generated a ScryptCfg with a random salt
        static shared_ptr<ScryptCfg_t> Random(int N=32768, int R=8, int P=1) {
            auto u64_ptr = Uint64::Random<shared_ptr<Uint64>>();
            return shared_ptr<ScryptCfg_t>(new ScryptCfg(*u64_ptr, N, R, P));
        }
    };
    extern const ScryptCfg_t DefaultScryptConfig;

    inline static const Uint256 PasswordToAesKeyScrypt(const string& pswd, const ScryptData_t& data) {
        return SCRYPT<Uint256>::KeyDerive(pswd, data.Salt, data.N, data.R, data.P);
    }
};  // namespace Wallet
};  // namespace NKN

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

/*** ScryptCfg I/O stream operation ***/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::ScryptCfg_t &n);
std::istream& operator>>(std::istream &s, NKN::Wallet::ScryptCfg_t &n);


/***************
 * Wallet Data *
 ***************/

namespace NKN {
namespace Wallet {
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
        WalletData(shared_ptr<ScryptCfg_t> cfg=NULL);
        WalletData(shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t& mstKey = Uint256::Random<Uint256>(),
                const AES_IV_t&  iv     = Uint128::Random<Uint128>(),
                const Salt_t&    salt   = Uint64::Random<Uint64>(),
                int N=32768, int R=8, int P=1);
        /* WalletData(shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t&& mstKey = *Uint256::Random<shared_ptr<Uint256>>(),
                const AES_IV_t&&  iv     = *Uint128::Random<shared_ptr<Uint128>>(),
                const Salt_t&&    salt   = *Uint64::Random<shared_ptr<Uint64>>(),
                int N=32768, int R=8, int P=1);  //TODO */
        WalletData(shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t& mstKey = *Uint256::Random<shared_ptr<Uint256>>(),
                const AES_IV_t&  iv     = *Uint128::Random<shared_ptr<Uint128>>(),
                shared_ptr<ScryptCfg_t> cfg=ScryptCfg::Random());

        // For compatible with sdk-go API
        inline static shared_ptr<WalletData_t> NewWalletData(
                shared_ptr<const Account_t> acc, const string& pswd,
                const AES_Key_t& mstKey = *Uint256::Random<shared_ptr<Uint256>>(),
                const AES_IV_t&  iv     = *Uint128::Random<shared_ptr<Uint128>>(),
                const Salt_t&    salt   = *Uint64::Random<shared_ptr<Uint64>>(),
                int N=32768, int R=8, int P=1) {
            return make_shared<WalletData_t>(acc, pswd, mstKey, iv, salt, N, R, P);
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

        inline bool VerifyPassword(const string& pswd) {
            return 0 == DecryptAccount(pswd)->ProgramHash.toAddress().compare(Address);
        }

        shared_ptr<AES_Key_t> DecryptMasterKey(const string& pswd);
        shared_ptr<Account_t> DecryptAccount(const string& pswd);
    };
};  // namespace Wallet
};  // namespace NKN

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

/*** WalletData I/O stream operation ***/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::WalletData_t& wd);
std::istream& operator>>(std::istream &s, NKN::Wallet::WalletData_t& wd);

#endif // __NKN_WALLET_DATA_H__
