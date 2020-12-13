#ifndef __NKN_ED25519_H__
#define __NKN_ED25519_H__

#include <sodium.h>

#include "include/uBigInt.h"
#include "include/crypto/hash.h"
#include "include/crypto/base58.h"

using namespace std;

namespace NKN {
namespace ED25519 {
    // FOOLPROOFPREFIX used for fool-proof prefix
    // base58.BitcoinEncoding[21] = 'N', base58.BitcoinEncoding[18] = 'K'
    // 33 = len(base58.Encode( (2**192).Bytes() )),  192 = 8bit * (UINT160SIZE + SHA256CHKSUM)
    // (('N' * 58**35) + ('K' * 58**34) + ('N' * 58**33)) >> 192 = 0x02b824
    constexpr char    FOOLPROOFPREFIX[] = {0x02, (char)0xb8, 0x25};
    constexpr uint8_t CHECKSIG = 0xAC;

    constexpr size_t ProgramHash_SIZE = 160/8;
    constexpr size_t ADDR_STR_LEN     = 36; // len of (2**192).Bytes() = 33, +3 'NKN' prefix

    constexpr size_t PREFIXLEN        = sizeof(FOOLPROOFPREFIX);
    constexpr size_t SHA256CHKSUM     = 4;
    constexpr size_t HEXADDRLEN       = PREFIXLEN + ProgramHash_SIZE + SHA256CHKSUM;

    typedef struct ProgramHash : public Uint160 {
        ProgramHash() : Uint160() {}
        // construct from MSB fixed len char array
        ProgramHash(char    data[ProgramHash_SIZE])       : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), ProgramHash_SIZE); }
        ProgramHash(uint8_t data[ProgramHash_SIZE])       : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), ProgramHash_SIZE); }
        ProgramHash(const char    data[ProgramHash_SIZE]) : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), ProgramHash_SIZE); }
        ProgramHash(const uint8_t data[ProgramHash_SIZE]) : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), ProgramHash_SIZE); }

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
            string v(FOOLPROOFPREFIX);
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
        PubKey() : Uint256() {}
        PubKey(const PubKey& pk) : Uint256(pk) {}
        template<typename _T>
            PubKey(_T t) : Uint256(t) {}

        ProgramHash_t toProgramHash() const {
            HASH sha256("sha256");
            sha256.write(256/8);
            sha256.write(toBytes().c_str(), 256/8);
            sha256.write(CHECKSIG);
            std::vector<char> sum256 = sha256.read<vector,char>();

            HASH ripemd160("ripemd160");
            ripemd160.write(sum256.data(), sum256.size());
            std::vector<uint8_t> sum160 = ripemd160.read<vector,uint8_t>();

            return ProgramHash_t(sum160);
        }
    } PubKey_t;

    typedef struct PrivKey : public Uint256 {
        PrivKey() : PrivKey(*Uint256::Random<std::shared_ptr<Uint256>>()) {} // generated PrivKey from random
        PrivKey(const PrivKey& k) : Uint256(k) {}
        template<typename _T>
            PrivKey(_T t) : Uint256(t) {}

        ~PrivKey() { FromHexString(std::string(2*256/8, 0)); }    // Clean private key in memory

        const PubKey_t PublicKey() const {
            std::basic_string<uint8_t> pk(crypto_sign_PUBLICKEYBYTES, 0);
            std::basic_string<uint8_t> sk(crypto_sign_SECRETKEYBYTES, 0);

            int not_ok = crypto_sign_seed_keypair(const_cast<uint8_t*>(pk.c_str()), const_cast<uint8_t*>(sk.c_str()),
                    reinterpret_cast<const uint8_t*>(toBytes().c_str()));
            if (not_ok) {
                printf("crypto_sign_seed_keypair failed %d\n", not_ok);
                // TODO throw
            }

            mpz_class n;
            mpz_import(n.get_mpz_t(), pk.size(), 1/*MSB*/, sizeof(uint8_t), 0/*endian*/, 0, pk.data());
            return PubKey_t(n);
        }
    } PrivKey_t;
}; // namespace ED25519
};   // namespace NKN

#endif // __NKN_ED25519_H__
