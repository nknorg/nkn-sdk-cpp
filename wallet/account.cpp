#include <iostream>

#include "include/account.h"

using namespace std;

namespace NKN {
namespace Wallet {
    Account::Account()   // generated PrivKey from random
        : PrivateKey(), PublicKey(PrivateKey.PublicKey()), ProgramHash(PublicKey.toProgramHash()) {}
    Account::Account(const ED25519::PrivKey_t& seed)   // generated PrivKey from given seed
        : PrivateKey(seed), PublicKey(PrivateKey.PublicKey()), ProgramHash(PublicKey.toProgramHash()) {}
};  // namespace Wallet
};  // namespace NKN

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
