#ifndef __DATA_TYPE_H__
#define __DATA_TYPE_H__

#include <cassert>
#include <sstream>
#include <vector>
extern "C" {
#include <openssl/evp.h>
}

#include <dtype/uBigInt.h>
#include <sodium.h>

namespace NKN{
    typedef uBigInt<64>  Uint64;
    typedef uBigInt<128> Uint128;
    typedef uBigInt<160> Uint160;
    typedef uBigInt<256> Uint256;
    typedef uBigInt<512> Uint512;

    // wrap openssl/evp for c++
    struct HASH {
        const char* alg;
        EVP_MD_CTX* ctx;
        bool ended;

        HASH(const char* name) : alg(name), ctx(EVP_MD_CTX_new()), ended(false) {
            if (const EVP_MD* md = EVP_get_digestbyname(name))
                EVP_DigestInit_ex(ctx, md, NULL);
            else {
                ended = true;
                std::cerr << "EVP_get_digestbyname NOT found such alg: " << std::string(name) << std::endl;
                // TODO throw
            }
        }
        ~HASH() {EVP_MD_CTX_free(ctx);}

        // TODO read/write method
        bool write(const uint8_t c) {
            if (ended) {/* TODO throw */}
            return EVP_DigestUpdate(ctx, &c, sizeof(uint8_t)) == 1;
        }
        bool write(const char* msg, size_t n) {
            if (ended) {/* TODO throw */}
            return EVP_DigestUpdate(ctx, msg, n) == 1;
        }
        bool write(std::string msg) {
            if (ended) {/* TODO throw */}
            return EVP_DigestUpdate(ctx, msg.c_str(), msg.size()) == 1;
        }

        std::vector<char> read() {
            char buf[EVP_MAX_MD_SIZE];
            uint32_t md_len = 0;

            ended = true;
            if (EVP_DigestFinal_ex(ctx, reinterpret_cast<uint8_t*>(buf), &md_len) != 1 ) {
                // TODO throw
            }
            return std::vector<char>(buf, buf+md_len);
        }

        // TODO I/O stream
        // EVP_DigestUpdate / EVP_DigestFinal_ex
    };

    namespace AES {
        typedef Uint128 IV_t;
        typedef Uint256 MasterKey_t;
        typedef Uint256 Encrypted_t;
    };

    namespace SCRYPT {
        typedef Uint64 Salt_t;
    };

    namespace BASE58 {
        const char alphabet[59] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        // Encode
        const std::string b58enc(const mpz_class& n) {
            assert(n>=0);    // NOT support negative number
            std::vector<char> buf;  // TODO Pre-Allocate enough buff size
            mpz_class q(n); // quotient of math division

            do {
                unsigned long int r = mpz_fdiv_q_ui(q.get_mpz_t(), q.get_mpz_t(), 58L);
                buf.push_back(alphabet[r]);
            } while (q>0);

            return std::string(buf.rbegin(), buf.rend());   // inversed
        }
        // TODO parameters check
        const std::string b58enc(const uint8_t* p, size_t len) {
            mpz_class n;
            mpz_import(n.get_mpz_t(), len, uBigInt<256>::MSB, sizeof(uint8_t), 0/*endian*/, 0, p);
            return b58enc(n);
        }
        inline const std::string b58enc(const std::string& s) { return b58enc(reinterpret_cast<const uint8_t*>(s.c_str()), s.size()); }
        inline const std::string b58enc(const std::vector<char>& v) { return b58enc(reinterpret_cast<const uint8_t*>(v.data()), v.size()); }
        template <size_t N>
        inline const std::string b58enc(uBigInt<N>& n) { return b58enc(n.val); }

        // Decode
        const std::vector<char> b58dec(std::string& s) {
            // TODO
            return std::vector<char>();
        }
    };

    namespace ED25519 {
        typedef struct ProgramHash : public Uint160 {
            ProgramHash() : Uint160() {}
	    // construct from MSB fixed len char array
            ProgramHash(char    data[160/8])       : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), 20); }
            ProgramHash(uint8_t data[160/8])       : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), 20); }
            ProgramHash(const char    data[160/8]) : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), 20); }
            ProgramHash(const uint8_t data[160/8]) : Uint160() { FromBytes(reinterpret_cast<const uint8_t*>(data), 20); }

            template<typename _T>
                ProgramHash(_T t) : Uint160(t) {}	// constructor inherit from parent class

            std::string toAddress() {
                std::string bSlice = toBytes();
                std::vector<char> v = {0x02, (char)0xb8, 0x25}; // TODO: const 0x02b825
                v.insert(v.end(), bSlice.begin(), bSlice.end());

                HASH sha256_once("sha256"), sha256_twice("sha256");
                sha256_once.write(v.data(), v.size());
                std::vector<char> sum_once = sha256_once.read();

                sha256_twice.write(sum_once.data(), sum_once.size());
                std::vector<char> sum_twice = sha256_twice.read();
                // TODO: const +4 as CHECKSUM_LEN
                v.insert(v.end(), sum_twice.begin(), sum_twice.begin()+4); // Just used the first 4 MSB bytes as checksum

                //TODO base58 encode
                return BASE58::b58enc(v);
            }
        } ProgramHash_t;

        typedef struct PubKey : public Uint256 {
            PubKey() : Uint256() {}
            template<typename _T>
                PubKey(_T t) : Uint256(t) {}

            ProgramHash_t toProgramHash() {
                HASH sha256("sha256");
                sha256.write(256/8);
                sha256.write(toBytes().c_str(), 256/8);
                sha256.write(0xAC);
                std::vector<char> sum256 = sha256.read();

                HASH ripemd160("ripemd160");
                ripemd160.write(sum256.data(), sum256.size());
                std::vector<char> sum160 = ripemd160.read();

                return ProgramHash_t(sum160.data());
            }
        } PubKey_t;

        typedef struct PrivKey : public Uint256 {
            PrivKey() : Uint256() {}
            template<typename _T>
                PrivKey(_T t) : Uint256(t) {}

            PubKey_t PublicKey() {
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
    };
};  // namespace NKN

#endif //__DATA_TYPE_H__
