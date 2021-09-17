#include <iostream>
#include <memory>

#include "crypto/ed25519.h"

using namespace std;
using namespace NKN;

int main(int argc, char* argv[]) {
    ED25519::PrivKey_t sk;

    cout << "Random PrivKey: " << sk << endl;
    cout << "PublicKey: " << sk.PublicKey() << endl;
    cout << "ProgramHash: " << sk.PublicKey().toProgramHash() << endl;
    cout << "Address: " << sk.PublicKey().toProgramHash().toAddress() << endl;

    for (int i=1; i<argc; i++){
        ED25519::PrivKey_t restore(argv[i]);
        cout << "Random PrivKey: " << restore << endl;
        cout << "PublicKey: " << restore.PublicKey() << endl;
        cout << "ProgramHash: " << restore.PublicKey().toProgramHash() << endl;
        cout << "Address: " << restore.PublicKey().toProgramHash().toAddress() << endl;
    }
}
