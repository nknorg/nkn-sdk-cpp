#include <iostream>

#include "crypto/scrypt.h"

using namespace std;
using namespace NKN;

int main(int argc, char* argv[]) {
    string pswd(argv[1]);
    Uint64 salt(argv[2]);

    cout << SCRYPT<Uint256>::KeyDerive(pswd, salt, 32768, 8, 1) << endl;
}
