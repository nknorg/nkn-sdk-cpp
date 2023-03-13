#include <iostream>
#include <memory>

#include "crypto/ed25519.h"

using namespace std;
using namespace NKN;

// example CMD: ./a.out 0 255 -1 -3 0x8f630f
int main(int argc, char* argv[]) {
    ED25519::PrivKey_t sk;

    cout << "Random PrivKey: " << sk << endl;
    cout << "PublicKey: " << sk.PublicKey() << endl;
    cout << "ProgramHash: " << sk.PublicKey().toProgramHash() << endl;
    cout << "Address: " << sk.PublicKey().toProgramHash().toAddress() << endl << endl;

    for (int i=1; i<argc; i++) {
        ED25519::PrivKey_t restore(argv[i]);
        cout << "PrivKey inputted: " << restore << endl;
        cout << "It's PublicKey: " << restore.PublicKey() << endl;
        cout << "It's ProgramHash: " << restore.PublicKey().toProgramHash() << endl;
        cout << "It's Address: " << restore.PublicKey().toProgramHash().toAddress() << endl << endl;
    }

    return 0;
}
