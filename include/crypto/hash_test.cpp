#include <iostream>
#include <memory>

#include "include/crypto/hash.h"

using namespace std;
using namespace NKN;

int main(int , char* argv[]) {
    string name(argv[1]);

    HASH h(name);
    h.write(string("Hello World"));

    cout << h.read<basic_string, char>() << endl;
    cout << h.read<uBigInt,256>() << endl;
    // h.read<vector, char>();

    // cout << Uint128::MAX << endl << sizeof(Uint256::MAX) << endl;

    HASH h2(name);
    h2.write(string("Hello World"));
    cout << *h2.read<shared_ptr, uBigInt, 256>() << endl;
    // cout << h.read<shared_ptr<uBigInt<256>>>() << endl;
}
