#include <iostream>
#include <memory>

#include "include/crypto/aes.h"
// #include "dtype/wallet.h"

using namespace std;
using namespace NKN;

int main(int argc, char* argv[]) {
    AES_Key_t    key(argv[1]);
    AES_IV_t     iv(argv[2]);
    AES<Uint256> aes(key, iv);

    cout << aes.Dec(Uint256(argv[3])) << endl;
    cout << aes.Enc(Uint256(argv[4])) << endl;
}
