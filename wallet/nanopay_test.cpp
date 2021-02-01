#include <iostream>
#include <system_error>

#include "include/rpc.h"
#include "include/wallet.h"
#include "include/transaction.h"
#include "include/crypto/hex.h"

using namespace NKN;

int main(int, char* argv[]) {
    auto rpc = make_shared<JsonRPC>(GetRandomSeedRPCServerAddr());  // new RPC client

    // auto acc = Wallet::Account::NewAccount();                       // new Random account
    // auto w = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(NULL));    // create wallet with accout and default cfg
    ifstream wFile(argv[1]);
    string jStr(istreambuf_iterator<char>{wFile}, {});
    auto w = WalletFromJSON(jStr, make_shared<Wallet::WalletCfg>(0, 0, argv[3]));    // wallet from argv[1] keyStore file

    auto np = Wallet::NanoPay::NewNanoPay(rpc, w, argv[2], 0, 255);    // New Wallet::NanoPay
    cout << "Wallet nanoPay: " << np << " Amount: " << np->amount << " Exprie: " << np->expiration <<  endl;

    std::error_code err;
    np->id = Uint64("0x0807060504030201");
    auto npTxn = np->IncrementAmount("100.2", err);    // NanoPay Increase, return a transaction
    if (err) {
        cerr << "NanoPay IncrementAmount met err: " << err << endl;
        exit(err.value());
    }
    npTxn->mutable_unsigned_tx()->set_nonce(0);
    npTxn->mutable_unsigned_tx()->set_attributes(Uint256(0).toBytes());

    cout << npTxn << " Fee: " << npTxn->unsigned_tx().fee();
    cout << npTxn << " Nonce: " << npTxn->unsigned_tx().nonce() << endl;
    cout << "\nPayload: " << HEX::EncodeToString(npTxn->unsigned_tx().payload().data()) << endl; // dump txn.Payload
    // cout << " GetHashData: " << HEX::EncodeToString(TXN::Serialize<pb::Transaction>(npTxn)) << endl;

    // npTxn = np->IncrementAmount("100");     // Increase again
    // cout << npTxn << " Fee: " << npTxn->unsigned_tx().fee();
    // cout << " Payload: " << HEX::EncodeToString(npTxn->unsigned_tx().payload().data()) << endl; // dump txn.Payload again

    TXN::SignTransaction(npTxn, w->account);
    cout << "\nRaw Txn: " << HEX::EncodeToString( npTxn->SerializeAsString() ) << endl;  // txn serialize
}
