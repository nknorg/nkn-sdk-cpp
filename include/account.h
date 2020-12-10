#ifndef __NKN_ACCOUNT_H__
#define __NKN_ACCOUNT_H__

#include "include/crypto/ed25519.h"

#include "json/NKNCodec.h"

using namespace std;

namespace NKN {
namespace Wallet {
    typedef struct Account Account_t;
    struct Account {
        // const Account member since PubKey & ProgramHash should be determined by PrivKey.
        // They should not be modified anymore after constructed.
        const ED25519::PrivKey_t     PrivateKey;
        const ED25519::PubKey_t      PublicKey;
        const ED25519::ProgramHash_t ProgramHash;

        Account();
        Account(const ED25519::PrivKey_t& seed);
        Account(const Account_t* acc) = delete; // explicit forbidden copy account for security consideration
        Account(const Account_t& acc) = delete; // explicit forbidden copy account for security consideration

        // For compatible with sdk-go API
        inline static shared_ptr<const Account_t> const NewAccount() { return shared_ptr<const Account_t>(new Account()); }
        inline static shared_ptr<const Account_t> const NewAccount(ED25519::PrivKey_t seed) { return make_shared<const Account_t>(seed); }
        inline const string WalletAddress() { return ProgramHash.toAddress(); }
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

/*** Stream Operation ***/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::Account_t &acc);
// Unnecessary restore Account_t from plain text json
// std::istream& operator>>(std::istream &s, NKN::Wallet::Account_t &acc);

#endif  // __NKN_ACCOUNT_H__
