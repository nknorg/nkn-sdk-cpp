#include <iostream>

#include "include/walletData.h"

using namespace std;

/*****************
 * Scrypt Config *
 *****************/

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

/***************
 * Wallet Data *
 ***************/

namespace NKN {
namespace Wallet {
    const ScryptCfg_t DefaultScryptConfig(0);

    WalletData::WalletData(shared_ptr<ScryptCfg_t> cfg) : Version(V2), ScryptData(cfg) {
        if (ScryptData == NULL)
            ScryptData = make_shared<ScryptCfg_t>();
    }
    WalletData::WalletData(shared_ptr<const Account_t> acc, const string& pswd,
            const AES_Key_t& mstKey, const AES_IV_t& iv, const Salt_t&    salt,
            int N, int R, int P)
        : WalletData(acc, pswd, mstKey, iv, make_shared<ScryptCfg_t>(salt,N,R,P)) {}
    /* WalletData::WalletData(shared_ptr<const Account_t> acc, const string& pswd,
            const AES_Key_t&& mstKey = *Uint256::Random<shared_ptr<Uint256>>(),
            const AES_IV_t&&  iv     = *Uint128::Random<shared_ptr<Uint128>>(),
            const Salt_t&&    salt   = *Uint64::Random<shared_ptr<Uint64>>(),
            int N=32768, int R=8, int P=1);  //TODO */
    WalletData::WalletData(shared_ptr<const Account_t> acc, const string& pswd,
            const AES_Key_t& mstKey, const AES_IV_t&  iv, shared_ptr<ScryptCfg_t> cfg)
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

    shared_ptr<AES_Key_t> WalletData::DecryptMasterKey(const string& pswd) {
        if ( ! isSupportedVer() )
            return NULL;   // TODO log unsupport error

        Uint256 pswdKey = PasswordToAesKeyScrypt(pswd, *ScryptData);
        AES<shared_ptr<AES_Key_t>> aes(pswdKey, IV/*, "aes-256-cbc"*/);
        return aes.Dec(MasterKey);
    }

    shared_ptr<Account_t> WalletData::DecryptAccount(const string& pswd) {
        auto plainMstKey = DecryptMasterKey(pswd);
        auto seed = AES<Uint256>(*plainMstKey, IV).Dec(SeedEncrypted);
        return make_shared<Account_t>(seed);
    }
};  // namespace Wallet
};  // namespace NKN

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
