#include <iostream>
#include <string>

#include "uBigInt.h"
#include "crypto/hex.h"
#include "crypto/xchacha20-poly1305.h"

using namespace std;
using namespace NKN;

int main(int argc, char* argv[]) {
    string msg(argv[1]);
    Uint256 key  (argc>=3 ? argv[2] : "0");   // from argv or 0(means random)
    Uint192 nonce(argc>=4 ? argv[3] : "0");   // from argv or 0(means random)

    AEAD::xchacha20_poly1305<basic_string<char>> aead(key, nonce);
    cout << "Cipher from (" << aead.Key << ", " << aead.Nonce << ")" << endl;

    // DetachedMode, Encrypted to return value
    string hmac;
    string cipher = aead.Encrypt(msg, &hmac);
    cout << "Encrypted byteSlice: " << HEX::EncodeToString(cipher) << " with hmac: " << HEX::EncodeToString(hmac) << endl;

    string dest;
    string combinedStr = cipher+hmac;
    // CombinedMode, Decrypted to dest
    int err = aead.DecryptTo(combinedStr, &dest);
    if (err != 0) {
        fprintf(stderr, "Decrypted ciphertext fail. err=%d\n", err);
        return err;
    }
    cout << "Decrypted success. Your inputed msg: " << dest << endl;
}
