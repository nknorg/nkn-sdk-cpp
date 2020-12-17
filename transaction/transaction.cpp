#include <vector>

#include "include/crypto/ed25519.h"
#include "pb/transaction.pb.h"
#include "include/transaction.h"
#include "include/account.h"

using namespace std;

namespace NKN {
namespace TXN {
pb::UnsignedTx* NewPBUnsignedTxn(pb::Payload* pld, const Uint64& nonce, const Uint64& fee, const string& attr) {
    auto unsignedTx = new pb::UnsignedTx();
    unsignedTx->set_allocated_payload(pld);
    unsignedTx->set_nonce(nonce.Value().get_ui());
    unsignedTx->set_fee(fee.Value().get_si());
    unsignedTx->set_attributes(attr);
    return unsignedTx;
}

shared_ptr<pb::Transaction> NewPBTransaction(pb::UnsignedTx* unsignedTx,
        const vector<shared_ptr<pb::Program>>& programs) {
    auto txn = shared_ptr<pb::Transaction>(new pb::Transaction());
    txn->set_allocated_unsigned_tx(unsignedTx);
    // TODO set_programs
    return txn;
}

pb::Payload* PackPayload(const pb::PayloadType typ, ::google::protobuf::Message* msg) {
    auto pld = new pb::Payload();
    pld->set_type(typ);
    pld->set_data(msg->SerializeAsString());
    return pld;
}

template<>
const string Serialize<pb::Payload>(const pb::Payload& pld) {
    auto data = pld.data();

    string buf = SerializeToLE<uint32_t>((uint32_t)pld.type());
    buf.append(SerializeVarUint((uint64_t)data.size()));
    buf.append(data);
    return buf;
}

template<>
const string Serialize<pb::Transaction>(const pb::Transaction& txn) {
    const pb::UnsignedTx& utxn = txn.unsigned_tx();
    auto buf = Serialize<pb::Payload>(utxn.payload());

    buf.append( SerializeToLE<uint64_t>(utxn.nonce()) );
    buf.append( SerializeToLE<uint64_t>((uint64_t)utxn.fee()) );

    const string& attr = utxn.attributes();
    buf.append(SerializeVarUint((uint64_t)attr.size()));
    buf.append(attr);
    return buf;
}

bool SignTransaction(shared_ptr<pb::Transaction> txn, const shared_ptr<const Wallet::Account> acc) {
    const byteSlice sign = SignByAccount(txn, acc);
    pb::Program* pgm = txn->add_programs();
    pgm->set_code(acc->Contract->Code);

    uint8_t sign_len = (uint8_t)sign.size();
    pgm->set_parameter(string(1, (char)sign_len) + sign);
    return false;
}

}; // namespace TXN
}; // namespace NKN
