
#include "include/crypto/ed25519.h"
#include "pb/transaction.pb.h"
#include "include/transaction.h"

using namespace std;

namespace NKN {
namespace TXN {

/************
 * Coinbase *
 ************/
// Never be used from NKN app

/***************
 * SigChainTxn *
 ***************/
// TODO No requirement from NKN app at current

/*****************
 * TransferAsset *
 *****************/
shared_ptr<pb::TransferAsset> NewTransferAsset(
        const ED25519::ProgramHash& send, const ED25519::ProgramHash& recv, const Uint64& amount) {
    auto trans = shared_ptr<pb::TransferAsset>(new pb::TransferAsset());
    trans->set_sender(send.toBytes());
    trans->set_recipient(recv.toBytes());
    trans->set_amount(amount.Value().get_si());
    return trans;
}
shared_ptr<pb::Transaction> NewTransferAssetTransaction(
        const ED25519::ProgramHash& send,
        const ED25519::ProgramHash& recv,
        const Uint64& nonce, const Uint64& value, const Uint64& fee) {
    auto trans = NewTransferAsset(send, recv, value);
    auto pld = PackPayload(pb::TRANSFER_ASSET_TYPE, reinterpret_cast<::google::protobuf::Message*>(trans.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, nonce, fee);
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/**************
 * GenerateID *
 **************/
shared_ptr<pb::GenerateID> NewGenerateID(const ED25519::PubKey& pubKey, const Uint64& regFee) {
    auto gen = shared_ptr<pb::GenerateID>(new pb::GenerateID());
    gen->set_public_key(pubKey.toBytes());
    gen->set_registration_fee(regFee.Value().get_si());
    return gen;
}
shared_ptr<pb::Transaction> NewGenerateIDTransaction(
        const ED25519::PubKey& pubKey, const Uint64& regFee,
        const Uint64& nonce, const Uint64& fee, const string& attr) {
    auto gen = NewGenerateID(pubKey, regFee);
    auto pld = PackPayload(pb::GENERATE_ID_TYPE, reinterpret_cast<::google::protobuf::Message*>(gen.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, nonce, fee, attr);
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/*************
 * Subscribe *
 *************/
shared_ptr<pb::Subscribe> NewSubscribe(
        const string& subscriber, const string& id, const string& topic,
        uint32_t duration, const string& meta) {
    auto sub = shared_ptr<pb::Subscribe>(new pb::Subscribe());
    sub->set_subscriber(subscriber);
    sub->set_identifier(id);
    sub->set_topic(topic);
    sub->set_duration(duration);
    sub->set_meta(meta);
    return sub;
}
shared_ptr<pb::Transaction> NewSubscribeTransaction(
        const string& subscriber, const string& id, const string& topic,
        uint32_t duration, const string& meta, const Uint64& nonce, const Uint64& fee) {
    auto sub = NewSubscribe(subscriber, id, topic, duration, meta);
    auto pld = PackPayload(pb::SUBSCRIBE_TYPE, reinterpret_cast<::google::protobuf::Message*>(sub.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, nonce, fee);
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/***************
 * Unsubscribe *
 ***************/
shared_ptr<pb::Unsubscribe> NewUnsubscribe(const string& subscriber, const string& id, const string& topic) {
    auto unsub = shared_ptr<pb::Unsubscribe>(new pb::Unsubscribe());
    unsub->set_subscriber(subscriber);
    unsub->set_identifier(id);
    unsub->set_topic(topic);
    return unsub;
}
shared_ptr<pb::Transaction> NewUnsubscribeTransaction(
        const string& subscriber, const string& id, const string& topic, const Uint64& nonce, const Uint64& fee) {
    auto unsub = NewUnsubscribe(subscriber, id, topic);
    auto pld = PackPayload(pb::UNSUBSCRIBE_TYPE, reinterpret_cast<::google::protobuf::Message*>(unsub.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, nonce, fee);
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/***********
 * NanoPay *
 ***********/
shared_ptr<pb::NanoPay> NewNanoPay(
        const ED25519::ProgramHash& send, const ED25519::ProgramHash& recv,
        const Uint64& id, const Uint64& amount, uint32_t txnExpired, uint32_t nPayExpired) {
    auto np = shared_ptr<pb::NanoPay>(new pb::NanoPay());
    np->set_sender(send.toBytes());
    np->set_recipient(recv.toBytes());
    np->set_id(id.Value().get_ui());
    np->set_amount(amount.Value().get_si());
    np->set_txn_expiration(txnExpired);
    np->set_nano_pay_expiration(nPayExpired);
    return np;
}
shared_ptr<pb::Transaction> NewNanoPayTransaction(
        const ED25519::ProgramHash& send, const ED25519::ProgramHash& recv,
        const Uint64& id, const Uint64& amount, uint32_t txnExpired, uint32_t nPayExpired) {
    auto np = NewNanoPay(send, recv, id, amount, txnExpired, nPayExpired);
    auto pld = PackPayload(pb::NANO_PAY_TYPE, reinterpret_cast<::google::protobuf::Message*>(np.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, 0, 0, Uint256::Random<Uint256>().toBytes());
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/****************
 * RegisterName *
 ****************/
shared_ptr<pb::RegisterName> NewRegisterName(const string& registrant, const string& name, const Uint64& regFee) {
    auto reg = shared_ptr<pb::RegisterName>(new pb::RegisterName());
    reg->set_registrant(registrant);
    reg->set_name(name);
    reg->set_registration_fee(regFee.Value().get_si());
    return reg;
}
shared_ptr<pb::Transaction> NewRegisterNameTransaction(
        const string& registrant, const string& name, const Uint64& nonce, const Uint64& regFee, const Uint64& fee) {
    auto reg = NewRegisterName(registrant, name, regFee);
    auto pld = PackPayload(pb::REGISTER_NAME_TYPE, reinterpret_cast<::google::protobuf::Message*>(reg.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, nonce, fee);
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/**************
 * DeleteName *
 **************/
shared_ptr<pb::DeleteName> NewDeleteName(const string& registrant, const string& name) {
    auto del = shared_ptr<pb::DeleteName>(new pb::DeleteName());
    del->set_registrant(registrant);
    del->set_name(name);
    return del;
}
shared_ptr<pb::Transaction> NewDeleteNameTransaction(
        const string& registrant, const string& name, const Uint64& nonce, const Uint64& fee) {
    auto del = NewDeleteName(registrant, name);
    auto pld = PackPayload(pb::DELETE_NAME_TYPE, reinterpret_cast<::google::protobuf::Message*>(del.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, nonce, fee);
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/****************
 * TransferName *
 ****************/
shared_ptr<pb::TransferName> NewTransferName(const string& registrant, const string& to, const string& name) {
    auto trans = shared_ptr<pb::TransferName>(new pb::TransferName());
    trans->set_registrant(registrant);
    trans->set_recipient(to);
    trans->set_name(name);
    return trans;
}
shared_ptr<pb::Transaction> NewTransferNameTransaction(
        const string& registrant, const string& to, const string& name, const Uint64& nonce, const Uint64& fee) {
    auto trans = NewTransferName(registrant, to, name);
    auto pld = PackPayload(pb::TRANSFER_NAME_TYPE, reinterpret_cast<::google::protobuf::Message*>(trans.get()));
    auto unsignedTx = NewPBUnsignedTxn(pld, nonce, fee);
    return NewPBTransaction(unsignedTx, vector<shared_ptr<pb::Program>>{});
}

/**************
 * IssueAsset *
 **************/
// TODO No requirement from NKN app at current

}; // namespace TXN
}; // namespace NKN
