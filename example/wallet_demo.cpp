#include <iostream>
#include <system_error>

#include "include/wallet.h"
#include "include/crypto/hex.h"

using namespace std;
using namespace NKN;

// example CMD: ./a.out wallet.json wallet_2.json wallet_3.json...
int main(int argc, char* argv[]) {
    // Create random wallet
    auto acc = Wallet::Account::NewAccount();                       // new Random account
    auto w = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(NULL)); // create wallet with accout and default cfg
    cout << "Random wallet: " << endl << *w << endl << endl;

    // Create wallet with accout and random cfg
    w = Wallet::NewWallet(Wallet::Account::NewAccount(-1),       // new account with seed
                            make_shared<Wallet::WalletCfg_t>(
                                AES_IV_t::Random<AES_IV_t>(),
                                AES_Key_t::Random<AES_Key_t>(),
                                "password")
                        );
    cout << "Configured wallet: " << endl << *w << endl << endl;

    // Create wallet from keyStore json specified by argv
    for (auto i=1; i<argc; i++) {
        string passwd;
        ifstream wFile(argv[i]);
        string jStr(istreambuf_iterator<char>{wFile}, {});

        cout << "Input password for wallet " << argv[i] << ":" << endl;
        getline(cin, passwd);

        auto w = WalletFromJSON(jStr, make_shared<Wallet::WalletCfg>(0, 0, passwd));    // wallet from argv[1] keyStore file
        if (w)
            cout << "wallet " << argv[i] << ": " << endl << *w << endl << endl;
        else
            cout << "Open wallet " << argv[i] << " failed" << endl << endl;
    }

    return 0;
}
