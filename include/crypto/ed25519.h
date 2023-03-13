#ifndef __NKN_ED25519_H__
#define __NKN_ED25519_H__

#include <sodium.h>

#include "uBigInt.h"
#include "byteslice.h"
#include "crypto/hash.h"
#include "crypto/base58.h"

using namespace std;

namespace NKN {
namespace ED25519 {
    // FOOLPROOFPREFIX used for fool-proof prefix
    // base58.BitcoinEncoding[21] = 'N', base58.BitcoinEncoding[18] = 'K'
    // 33 = len(base58.Encode( (2**192).Bytes() )),  192 = 8bit * (UINT160SIZE + SHA256CHKSUM)
    // (('N' * 58**35) + ('K' * 58**34) + ('N' * 58**33)) >> 192 = 0x02b824
    constexpr const char    FOOLPROOFPREFIX[] = {0x02, (char)0xb8, 0x25};

    constexpr size_t ProgramHash_SIZE = 160/8;
    constexpr size_t ADDR_STR_LEN     = 36; // len of (2**192).Bytes() = 33, +3 'NKN' prefix

    constexpr size_t PREFIXLEN        = sizeof(FOOLPROOFPREFIX);
    constexpr size_t SHA256CHKSUM     = 32/8; // 32bit checksum
    constexpr size_t HEXADDRLEN       = PREFIXLEN + ProgramHash_SIZE + SHA256CHKSUM;

    constexpr size_t SignatureSize    = crypto_sign_ed25519_BYTES;

    typedef struct ProgramHash : public Uint160 {
        typedef enum ProgramContextParameterType : uint8_t {
            Signature = 0,
            CHECKSIG  = 0xAC,
        } ParameterType;

        ProgramHash() : Uint160() {}

        template<typename _T>
            ProgramHash(_T t) : Uint160(t) {}	// constructor inherit from parent class

        template<typename _Container>
        static bool isValidCode(_Container code) {
            if (code.size() == HEXADDRLEN &&
                    string(code.begin(), code.begin()+PREFIXLEN)
                        .compare(0, PREFIXLEN, FOOLPROOFPREFIX) == 0)
            {
                HASH sha256_once("sha256"), sha256_twice("sha256");
                sha256_once.write(code.data(), PREFIXLEN+ProgramHash_SIZE);
                string sum_once = sha256_once.read<basic_string,char>();

                sha256_twice.write(sum_once.data(), sum_once.size());
                string sum_twice = sha256_twice.read<basic_string,char>();

                const string checksum(code.end()-SHA256CHKSUM, code.end());
                return sum_twice.substr(0, SHA256CHKSUM).compare(checksum) == 0;
            }
            return false;
        }

        const string toAddress() const {
            string bSlice = toBytes();
            string v(FOOLPROOFPREFIX, PREFIXLEN);
            v.append(bSlice.begin(), bSlice.end());

            HASH sha256_once("sha256"), sha256_twice("sha256");
            sha256_once.write(v.data(), v.size());
            string sum_once = sha256_once.read<basic_string,char>();

            sha256_twice.write(sum_once.data(), sum_once.size());
            string sum_twice = sha256_twice.read<basic_string,char>();
            v.append(sum_twice.begin(), sum_twice.begin()+SHA256CHKSUM); // Just used the first 4 MSB bytes as checksum

            return Base58<string>::Enc(v);
        }

        static const ProgramHash fromAddress(const string& addr) {
            auto code = Base58<shared_ptr<string>>::Dec(addr);

            if (! isValidCode(*code)) {
                fprintf(stderr, "%s is not a valid NKN wallet address\n", addr.c_str());
                return ProgramHash(0);
            }

            const vector<char> data(code->begin()+PREFIXLEN, code->begin()+PREFIXLEN+ProgramHash_SIZE);   // code[3:23]
            return ProgramHash(data);
        }
    } ProgramHash_t;

    typedef struct PubKey : public Uint256 {
        static constexpr size_t HexStrLen = 2*256/8;
        static constexpr size_t Size = 256/8;

        PubKey() : Uint256() {}
        PubKey(const PubKey& pk) : Uint256(pk) {}
        template<typename _T>
            PubKey(_T t) : Uint256(t) {}

        inline ProgramHash_t toProgramHash() const {
            return ToCodeHash(CreateSignatureProgramCode<basic_string,char>());
        }

        inline bool Verify(const vector<uint8_t>& msg,const byteSlice& sig) const { return Verify(msg.data(), msg.size(), sig); }
        inline bool Verify(const vector<char>& msg,   const byteSlice& sig) const { return Verify((uint8_t*)msg.data(), msg.size(), sig); }
        inline bool Verify(const string& msg,         const byteSlice& sig) const { return Verify((uint8_t*)msg.data(), msg.size(), sig); }
        inline bool Verify(const char* msg, size_t n, const byteSlice& sig) const { return Verify((uint8_t*)msg, n, sig); }
        bool Verify(const uint8_t* msg, size_t n, const byteSlice& signature) const {
            string pk = toBytes();
            return (crypto_sign_BYTES == signature.size()) &&
                (0 == crypto_sign_verify_detached((uint8_t*)signature.data(), msg, n, (uint8_t*)pk.data()));
        }

        inline const ProgramHash_t ToCodeHash(const void* code, size_t n) const;    // TODO if necessary
        template<template<typename...>class C=basic_string, typename... Args>
        inline const ProgramHash_t ToCodeHash(const C<Args...>& code) const {
            HASH sha256("sha256");
            sha256.write<C,Args...>(code);
            vector<char> sum256 = sha256.read<vector,char>();

            HASH ripemd160("ripemd160");
            ripemd160.write(sum256);
            return ProgramHash_t(ripemd160.read<vector,uint8_t>());
        }

        template<template<typename...>class C=basic_string, typename... Args>
        inline const C<Args...> CreateSignatureProgramCode() const {
            typedef typename C<Args...>::value_type _CharT;

            C<Args...> ret;
            const byteSlice pk = toBytes();

            ret.push_back((_CharT)pk.size());
            ret.insert(ret.end(), make_move_iterator(pk.begin()), make_move_iterator(pk.end()));
            ret.push_back((_CharT)ProgramHash_t::ParameterType::CHECKSIG);
            return ret;
        }

        template<typename T> const T toCurvePubKey() const;
        template<> const shared_ptr<vector<uint8_t>> toCurvePubKey<shared_ptr<vector<uint8_t>>>() const {
            const string signPk = toBytes();
            auto curvePub = make_shared<vector<uint8_t>>(crypto_scalarmult_curve25519_BYTES, 0);
            int err = crypto_sign_ed25519_pk_to_curve25519(curvePub->data(), (const uint8_t*)signPk.data());
            if (err) {
                cerr << "crypto_sign_ed25519_pk_to_curve25519 met err: " << err << endl;
            }
            return err ? nullptr : curvePub;
        }
        template<> inline const Uint256 toCurvePubKey<Uint256>() const {
            return Uint256(*toCurvePubKey<shared_ptr<vector<uint8_t>>>());
        }
        template<> inline const shared_ptr<Uint256> toCurvePubKey<shared_ptr<Uint256>>() const {
            return make_shared<Uint256>(*toCurvePubKey<shared_ptr<vector<uint8_t>>>());
        }
    } PubKey_t;

    typedef struct PrivKey : public Uint256 {
        static constexpr size_t HexStrLen = 2*256/8;
        static constexpr size_t Size = 256/8;

        PrivKey() : PrivKey(*Uint256::Random<shared_ptr<Uint256>>()) {} // generated PrivKey from random
        PrivKey(const PrivKey& k) : Uint256(k) {}
        template<typename _T>
            PrivKey(_T t) : Uint256(t) {}

        ~PrivKey() { FromHexString(string(2*256/8, 0)); }    // Clean private key in memory

        const PubKey_t PublicKey() const {
            basic_string<uint8_t> pk(crypto_sign_PUBLICKEYBYTES, 0);
            basic_string<uint8_t> sk(crypto_sign_SECRETKEYBYTES, 0);
            auto seed = toBytes();

            int not_ok = crypto_sign_seed_keypair((uint8_t*)pk.data(), (uint8_t*)sk.data(), (const uint8_t*)seed.data());
            if (not_ok) {
                printf("crypto_sign_seed_keypair failed %d\n", not_ok);
                // TODO throw
            }

            mpz_class n;
            mpz_import(n.get_mpz_t(), pk.size(), 1/*MSB*/, sizeof(uint8_t), 0/*endian*/, 0, pk.data());
            return PubKey_t(n);
        }

        inline const byteSlice Sign(const vector<uint8_t>& msg) const { return Sign(msg.data(), msg.size()); }
        inline const byteSlice Sign(const vector<char>& msg)    const { return Sign((uint8_t*)msg.data(), msg.size()); }
        inline const byteSlice Sign(const string& msg)          const { return Sign((uint8_t*)msg.data(), msg.size()); }
        inline const byteSlice Sign(const char* msg, size_t n)  const { return Sign((uint8_t*)msg, n); }
        const byteSlice Sign(const uint8_t* msg, size_t n) const {
            // Calc secretKey from seed
            const string seed = toBytes();
            basic_string<uint8_t> sk(crypto_sign_SECRETKEYBYTES, 0);
            basic_string<uint8_t> pk(crypto_sign_PUBLICKEYBYTES, 0);
            int ok = crypto_sign_seed_keypair((uint8_t*)pk.data(), (uint8_t*)sk.data(), (uint8_t*)seed.data());
            assert(0 == ok);

            string signature(crypto_sign_BYTES, 0);
            crypto_sign_detached((uint8_t*)signature.data(), NULL, msg, n, (uint8_t*)sk.data());
            return signature;
        }

        template<typename T> const T toCurvePrivKey() const;
        template<> const shared_ptr<vector<uint8_t>> toCurvePrivKey<shared_ptr<vector<uint8_t>>>() const {
            const string seed = toBytes();
            vector<uint8_t> signPk(crypto_sign_PUBLICKEYBYTES, 0);
            vector<uint8_t> signSk(crypto_sign_SECRETKEYBYTES, 0);
            auto curvePriv = make_shared<vector<uint8_t>>(crypto_scalarmult_curve25519_BYTES, 0);

            int err = crypto_sign_seed_keypair(signPk.data(), signSk.data(), (uint8_t*)seed.data());
            err = crypto_sign_ed25519_sk_to_curve25519(curvePriv->data(), signSk.data());
            if (err) {
                cerr << "toCurvePrivKey met err: " << err << endl;
            }
            return err ? nullptr : curvePriv;
        }
        template<> inline const Uint256 toCurvePrivKey<Uint256>() const {
            return Uint256(*toCurvePrivKey<shared_ptr<vector<uint8_t>>>());
        }
        template<> inline const shared_ptr<Uint256> toCurvePrivKey<shared_ptr<Uint256>>() const {
            return make_shared<Uint256>(*toCurvePrivKey<shared_ptr<vector<uint8_t>>>());
        }
    } PrivKey_t;
}; // namespace ED25519
};   // namespace NKN

#endif // __NKN_ED25519_H__
