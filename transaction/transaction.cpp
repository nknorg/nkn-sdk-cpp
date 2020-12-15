#include <vector>

#include "include/crypto/ed25519.h"
#include "pb/transaction.pb.h"
#include "include/transaction.h"

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
}; // namespace TXN
}; // namespace NKN
