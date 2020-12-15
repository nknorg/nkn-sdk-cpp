#include <iostream>

#include "include/rpc.h"
#include "include/wallet.h"
#include "include/crypto/hex.h"

using namespace NKN;

int main(int, char* argv[]) {
    auto rpc = make_shared<JsonRPC>(GetRandomSeedRPCServerAddr());  // new RPC client
    auto acc = Wallet::Account::NewAccount();                       // new Random account
    auto w = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(NULL));    // create wallet with accout and default cfg
    auto np = Wallet::NanoPay::NewNanoPay(rpc, w, argv[1], 10, 200);    // New Wallet::NanoPay
    cout << "Wallet nanoPay: " << np << " Amount: " << np->amount << " Exprie: " << np->expiration <<  endl;

    auto npTxn = np->IncrementAmount("100");    // NanoPay Increase, return a transaction
    cout << npTxn << " Fee: " << npTxn->unsigned_tx().fee();
    cout << " Payload: " << HEX::EncodeToString(npTxn->unsigned_tx().payload().data()) << endl; // dump txn.Payload

    npTxn = np->IncrementAmount("100");     // Increase again
    cout << npTxn << " Fee: " << npTxn->unsigned_tx().fee();
    cout << " Payload: " << HEX::EncodeToString(npTxn->unsigned_tx().payload().data()) << endl; // dump txn.Payload again

    cout << HEX::EncodeToString( npTxn->SerializeAsString() ) << endl;  // txn serialize
}
