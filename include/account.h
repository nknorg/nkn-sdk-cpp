#ifndef __NKN_ACCOUNT_H__
#define __NKN_ACCOUNT_H__

#include "include/crypto/ed25519.h"
#include "include/crypto/hex.h"

#include "json/NKNCodec.h"

using namespace std;

namespace NKN {
namespace Wallet {
    typedef ED25519::PubKey_t   PubKey_t;
    typedef ED25519::PrivKey_t  PrivKey_t;
    typedef struct ProgramContext ProgramContext_t;
    struct ProgramContext {
        typedef ED25519::ProgramHash_t::ParameterType ParameterType;

        // const vector<char>    Code;
        const byteSlice       Code;
        vector<ParameterType> Parameters;
        const ED25519::ProgramHash_t   ProgramHash;
        const Uint160         OwnerPubkeyHash;

        ProgramContext(const ProgramContext_t& from)
            : Code(from.Code), Parameters(from.Parameters), ProgramHash(from.ProgramHash), OwnerPubkeyHash(from.OwnerPubkeyHash) {}
        ProgramContext(const byteSlice& code,
                const vector<ParameterType>& params,
                const ED25519::ProgramHash_t& pgmHash,
                const Uint160& pkHash) : Code(code), Parameters(params), ProgramHash(pgmHash), OwnerPubkeyHash(pkHash) {}

        static constexpr const char* ParameterTypeToName(NKN::Wallet::ProgramContext_t::ParameterType typ) {
            typedef NKN::Wallet::ProgramContext_t::ParameterType _enumType;
            return _enumType::Signature == typ ? "Signature" : _enumType::CHECKSIG == typ ? "CHECKSIG" : "UnknowType";
        }
    };

    typedef struct Account Account_t;
    struct Account {
        typedef ED25519::PubKey_t   PubKey_t;
        typedef ED25519::PrivKey_t  PrivKey_t;
        // const Account member since PubKey & ProgramHash should be determined by PrivKey.
        // They should not be modified anymore after constructed.
        const ED25519::PrivKey_t     PrivateKey;
        const ED25519::PubKey_t      PublicKey;
        const ED25519::ProgramHash_t ProgramHash;
        const shared_ptr<const ProgramContext_t> Contract;

        Account();
        Account(const ED25519::PrivKey_t& seed);
        Account(const Account_t* acc) = delete; // explicit forbidden copy account for security consideration
        Account(const Account_t& acc) = delete; // explicit forbidden copy account for security consideration

        // For compatible with sdk-go API
        inline static shared_ptr<const Account_t> const NewAccount() { return shared_ptr<const Account_t>(new Account()); }
        inline static shared_ptr<const Account_t> const NewAccount(ED25519::PrivKey_t seed) { return make_shared<const Account_t>(seed); }
        inline const string WalletAddress() const { return ProgramHash.toAddress(); }
        inline const Uint512 GetPrivateKeyFromSeed() const { return Uint512(PrivateKey.toHexString() + PublicKey.toHexString()); }

        inline const byteSlice Sign(const vector<uint8_t>& msg) const { return Sign(msg.data(), msg.size()); }
        inline const byteSlice Sign(const vector<char>& msg)    const { return Sign((uint8_t*)msg.data(), msg.size()); }
        inline const byteSlice Sign(const string& msg)          const { return Sign((uint8_t*)msg.data(), msg.size()); }
        inline const byteSlice Sign(const char* msg, size_t n)  const { return Sign((uint8_t*)msg, n); }
        const byteSlice Sign(const uint8_t* msg, size_t n) const {
            string sk = PrivateKey.toBytes() + PublicKey.toBytes();
            string signature(crypto_sign_BYTES, 0);
            crypto_sign_detached((uint8_t*)signature.data(), NULL, msg, n, (uint8_t*)sk.data());
            return signature;
        }

        inline bool Verify(const vector<uint8_t>& msg,const byteSlice& sig) const { return Verify(msg.data(), msg.size(), sig); }
        inline bool Verify(const vector<char>& msg,   const byteSlice& sig) const { return Verify((uint8_t*)msg.data(), msg.size(), sig); }
        inline bool Verify(const string& msg,         const byteSlice& sig) const { return Verify((uint8_t*)msg.data(), msg.size(), sig); }
        inline bool Verify(const char* msg, size_t n, const byteSlice& sig) const { return Verify((uint8_t*)msg, n, sig); }
        inline bool Verify(const uint8_t* msg, size_t n, const byteSlice& sig) const { return PublicKey.Verify(msg, n, sig); }

        inline shared_ptr<const ProgramContext_t> CreateSignatureProgramContext() {
            auto code = PublicKey.CreateSignatureProgramCode<basic_string,char>();
            return make_shared<const ProgramContext_t>(
                    code,
                    // vector<ProgramContext_t::ParameterType>{ProgramContext_t::ParameterType::Signature},
                    vector<ED25519::ProgramHash::ParameterType>{ED25519::ProgramHash::Signature},
                    PublicKey.ToCodeHash(code),
                    PublicKey.ToCodeHash(PublicKey.toBytes())
                );
        }

        inline const Uint256 GetCurvePrivKey() const {
            return PrivateKey.toCurvePrivKey<Uint256>();
            /* const string signPriv = GetPrivateKeyFromSeed().toBytes();
            vector<uint8_t> curvePriv(crypto_scalarmult_curve25519_BYTES, 0);
            crypto_sign_ed25519_sk_to_curve25519(curvePriv.data(), (uint8_t*)signPriv.data());
            return Uint256(curvePriv); */
        }

        inline const Uint256 GetCurvePubKey() const {
            return PublicKey.toCurvePubKey<Uint256>();
        }
    };
};  // namespace Wallet
};  // namespace NKN

// ProgramContext_t json Parser
template <typename T>
T& operator&(T& jsonCodec, const NKN::Wallet::ProgramContext_t &pgm) {
    jsonCodec.StartObject();
    jsonCodec.Member("Code") & NKN::HEX::EncodeToString(pgm.Code);

    jsonCodec.Member("Parameters");
    size_t cnt = pgm.Parameters.size();
    jsonCodec.StartArray(&cnt);
    for (auto& e: pgm.Parameters)
        jsonCodec & string(NKN::Wallet::ProgramContext_t::ParameterTypeToName(e));
    jsonCodec.EndArray();

    jsonCodec.Member("ProgramHash") & pgm.ProgramHash;
    jsonCodec.Member("OwnerPubkeyHash") & pgm.OwnerPubkeyHash;
    return jsonCodec.EndObject();
}

// Account_t json Parser
template <typename T>
T& operator&(T& jsonCodec, const NKN::Wallet::Account_t &acc) {
    jsonCodec.StartObject();
    jsonCodec.Member("PrivateKey") & acc.PrivateKey;
    jsonCodec.Member("PublicKey") & acc.PublicKey;
    jsonCodec.Member("ProgramHash") & acc.ProgramHash;
    jsonCodec.Member("Contract") & *acc.Contract;
    return jsonCodec.EndObject();
}

/*** Stream Operation ***/
std::ostream& operator<<(std::ostream &s, const NKN::Wallet::Account_t &acc);
// Unnecessary restore Account_t from plain text json
// std::istream& operator>>(std::istream &s, NKN::Wallet::Account_t &acc);

#endif  // __NKN_ACCOUNT_H__
