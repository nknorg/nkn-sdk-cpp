#ifndef __TRANSACTION_H__
#define __TRANSACTION_H__

#include "pb/transaction.pb.h"

#include "include/crypto/ed25519.h"

using namespace std;

namespace NKN {
namespace TXN {
shared_ptr<pb::Transaction> NewPBTransaction(pb::UnsignedTx* unsignedTx,
        const vector<shared_ptr<pb::Program>>& programs = vector<shared_ptr<pb::Program>>{});

pb::UnsignedTx* NewPBUnsignedTxn(pb::Payload* pld, const Uint64& nonce, const Uint64& fee, const string& attr);
inline pb::UnsignedTx* NewPBUnsignedTxn(pb::Payload* pld, const Uint64& nonce, const Uint64& fee,
        const Uint256& attr = Uint256::Random<Uint256>()) { return NewPBUnsignedTxn(pld, nonce, fee, attr.toBytes()); }

pb::Payload* PackPayload(const pb::PayloadType typ, ::google::protobuf::Message* msg);

shared_ptr<pb::TransferAsset> NewTransferAsset(
        const ED25519::ProgramHash& send, const ED25519::ProgramHash& recv, const Uint64& amount);
shared_ptr<pb::Transaction> NewTransferAssetTransaction(
        const ED25519::ProgramHash& send, const ED25519::ProgramHash& recv,
        const Uint64& nonce, const Uint64& value, const Uint64& fee);

shared_ptr<pb::GenerateID> NewGenerateID(const ED25519::PubKey& pubKey, const Uint64& regFee);
shared_ptr<pb::Transaction> NewGenerateIDTransaction(const ED25519::PubKey& pubKey,
        const Uint64& regFee, const Uint64& nonce, const Uint64& fee, const string& attr);

shared_ptr<pb::Subscribe> NewSubscribe(
        const string& subscriber, const string& id, const string& topic,
        uint32_t duration, const string& meta);
shared_ptr<pb::Transaction> NewSubscribeTransaction(
        const string& subscriber, const string& id, const string& topic,
        uint32_t duration, const string& meta, const Uint64& nonce, const Uint64& fee);

shared_ptr<pb::Unsubscribe> NewUnsubscribe(const string& subscriber, const string& id, const string& topic);
shared_ptr<pb::Transaction> NewUnsubscribeTransaction(
        const string& subscriber, const string& id, const string& topic, const Uint64& nonce, const Uint64& fee);

shared_ptr<pb::NanoPay> NewNanoPay(
        const ED25519::ProgramHash& send, const ED25519::ProgramHash& recv,
        const Uint64& id, const Uint64& amount, uint32_t txnExpired, uint32_t nPayExpired);
shared_ptr<pb::Transaction> NewNanoPayTransaction(
        const ED25519::ProgramHash& send, const ED25519::ProgramHash& recv,
        const Uint64& id, const Uint64& amount, uint32_t txnExpired, uint32_t nPayExpired);

shared_ptr<pb::RegisterName> NewRegisterName(const string& registrant, const string& name, const Uint64& regFee);
shared_ptr<pb::Transaction> NewRegisterNameTransaction(
        const string& registrant, const string& name, const Uint64& nonce, const Uint64& regFee, const Uint64& fee);

shared_ptr<pb::DeleteName> NewDeleteName(const string& registrant, const string& name);
shared_ptr<pb::Transaction> NewDeleteNameTransaction(
        const string& registrant, const string& name, const Uint64& nonce, const Uint64& fee);

shared_ptr<pb::TransferName> NewTransferName(const string& registrant, const string& to, const string& name);
shared_ptr<pb::Transaction> NewTransferNameTransaction(
        const string& registrant, const string& to, const string& name, const Uint64& nonce, const Uint64& fee);

}; // namespace TXN
}; // namespace NKN

#endif /* __TRANSACTION_H__ */
