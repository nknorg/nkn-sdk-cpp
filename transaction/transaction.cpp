#include <vector>

#include "include/byteslice.h"
#include "include/crypto/ed25519.h"
#include "transaction/sigchain.h"
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

bool SignTransaction(shared_ptr<pb::Transaction> txn, const shared_ptr<const Wallet::Account> acc) {
    const byteSlice sign = SignByAccount(txn, acc);
    pb::Program* pgm = txn->add_programs();
    pgm->set_code(acc->Contract->Code);

    uint8_t sign_len = (uint8_t)sign.size();
    pgm->set_parameter(string(1, (char)sign_len) + sign);
    return false;
}

shared_ptr<pb::SigChain> InitSigChain(const Uint256& srcID, const Wallet::PubKey_t& srcPubKey,
        const Uint256& destID, const Wallet::PubKey_t& destPubKey, shared_ptr<Uint256> blockHash,
        uint32_t dataSize, uint32_t nonce=0) {
    auto sc = make_shared<pb::SigChain>();
    nonce ? sc->set_nonce(nonce) : sc->set_nonce(Random<uint32_t>()());
    sc->set_src_id(srcID.toBytes());
    sc->set_src_pubkey(srcPubKey.toBytes());
    sc->set_dest_id(destID.toBytes());
    sc->set_dest_pubkey(destPubKey.toBytes());
    sc->set_block_hash(blockHash->toBytes());
    sc->set_data_size(dataSize);

    auto elem = sc->add_elems();
    elem->set_sig_algo(pb::SigAlgo::SIGNATURE);
    elem->set_mining(false);

    return sc;
}

shared_ptr<pb::SigChainElem> NewSigChainElem(shared_ptr<Uint256> id, const Wallet::PubKey_t& nextPubkey,
        const string& signature="", const string& vrf="", const string& proof="", bool mining=false, const pb::SigAlgo& sigAlgo=pb::SigAlgo::SIGNATURE) {
    auto ptr = make_shared<pb::SigChainElem>();

    ptr->set_sig_algo(sigAlgo);
    ptr->set_mining(mining);
    ptr->set_next_pubkey(nextPubkey.toBytes());  // TODO. Check LSB/MSB
    if (id)                 ptr->set_id(id->toBytes());  // TODO. Check LSB/MSB
    if (vrf.length())       ptr->set_vrf(vrf);
    if (proof.length())     ptr->set_proof(proof);
    if (signature.length()) ptr->set_signature(signature);

    return ptr;
}
}; // namespace TXN

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

template<>
const string Serialize<pb::SigChainElem>(const pb::SigChainElem& elem) {
    ostringstream oss;

    if (elem.id().length())     oss << Serialize(elem.id());
    oss << Serialize(elem.next_pubkey());
    oss << Serialize(elem.mining());
    if (elem.vrf().length())    oss << Serialize(elem.vrf());

    return oss.str();
}

template<>
const string Serialize<pb::SigChain>(const pb::SigChain& sc) {
    ostringstream oss;

    oss << SerializeToLE<uint32_t>(sc.nonce());
    oss << SerializeToLE<uint32_t>(sc.data_size());
    oss << Serialize(sc.block_hash());
    oss << Serialize(sc.src_id());
    oss << Serialize(sc.src_pubkey());
    oss << Serialize(sc.dest_id());
    oss << Serialize(sc.dest_pubkey());
/* Disable recursive serialize elems for compatible with nknorg/nkn/v2@v2.0.6/pb/sigchain.go:#SerializationMetadata
    for (auto& it: sc.elems()) {
        oss << Serialize(it);
    }
 */
    return oss.str();
}
}; // namespace NKN
