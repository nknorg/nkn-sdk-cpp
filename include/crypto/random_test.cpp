#include <iostream>

#include "include/crypto/random.h"

using namespace std;
using namespace NKN;

int main() {
    cout << Random<Uint160>::read() << endl;
    cout << Random<Uint160>::read(5) << endl;

    cout << *Random<shared_ptr<Uint256>>::read() << endl;
    cout << *Random<shared_ptr<Uint256>>::read(6) << endl;

    cout << Random<string>::read(8) << endl;
}
