#ifndef __NKN_CLIENT_MSG_H__
#define __NKN_CLIENT_MSG_H__

#include <functional>
#include <iostream>

#include "include/crypto/hex.h"
#include "include/crypto/random.h"
#include "include/serialize.h"
#include "include/channel.h"
#include "payloads/payloads.pb.h"
#include "pb/sigchain.pb.h"
#include "pb/clientmessage.pb.h"

#include "client/address.h"
#include "json/NKNCodec.h"

namespace NKN {
namespace Client {

using namespace std;

template <typename T>
shared_ptr<payloads::Payload> newBinaryPayload(const T& data,
        shared_ptr<Uint64> messageID, shared_ptr<Uint64> replyToID, bool noReply) {
    if (messageID == nullptr && replyToID == nullptr) {
        messageID = Random<shared_ptr<Uint64>>()();
    }

    auto pld = make_shared<payloads::Payload>();
    pld->set_type(payloads::PayloadType::BINARY);
    pld->set_data(data.data(), data.size());
    pld->set_no_reply(noReply);
    if (messageID)
        pld->set_message_id(messageID->toBytes());
    if (replyToID)
        pld->set_reply_to_id(replyToID->toBytes());

    return pld;
}

shared_ptr<payloads::Payload> newTextPayload(const string& data, shared_ptr<Uint64> messageID=nullptr,
        shared_ptr<Uint64> replyToID=nullptr, bool noReply=true);

shared_ptr<payloads::Payload> newAckPayload(const shared_ptr<Uint256> replyToID);

shared_ptr<pb::ClientMessage> newClientMessage(shared_ptr<pb::OutboundMessage> obMsgPtr);

template <typename T>
inline shared_ptr<payloads::Payload> newMessagePayload(const T& data, shared_ptr<Uint64> messageID=nullptr, bool noReply=true) {
    return newBinaryPayload(data, messageID, nullptr, noReply);
}
template <> // Explicit template specialization for string type data
inline shared_ptr<payloads::Payload> newMessagePayload<string>(const string& data, shared_ptr<Uint64> messageID, bool noReply) {
    return newTextPayload(data, messageID, nullptr, noReply);
}

template <typename T>
inline shared_ptr<payloads::Payload> newReplyPayload(const T& data, shared_ptr<Uint64> replyToID) {
    return newBinaryPayload(data, nullptr, replyToID, false);
}
template <>
inline shared_ptr<payloads::Payload> newReplyPayload<string>(const string& data, shared_ptr<Uint64> replyToID) {
    return newTextPayload(data, nullptr, replyToID, false);
}

typedef struct Message {
    shared_ptr<Address> Src;
    shared_ptr<Uint64> MessageID;
    payloads::PayloadType Type;
    byteSlice   Data;
    bool        Encrypted;
    bool        NoReply;
    std::function<bool(const byteSlice&)> reply;

    Message(shared_ptr<Address> src, payloads::PayloadType type, const byteSlice& data,
            bool encrypted, bool noReply, shared_ptr<Uint64> msgID=nullptr);

    inline static unique_ptr<Message> NewMessage(shared_ptr<Address> src, payloads::PayloadType type,
            const byteSlice& data, bool encrypted, bool noReply, shared_ptr<Uint64> msgID=nullptr) {
        return unique_ptr<Message>(new Message(src, type, data, encrypted, noReply, msgID));
    }
} Message_t;

typedef Channel<Message_t>    OnMessage_t;
typedef shared_ptr<OnMessage_t> OnMessagePtr_t;

}; // namespace Client
}; // namespace NKN

// Message_t json Parser
template <typename T>
T& operator&(T& jsonCodec, const NKN::Client::Message_t& m);

std::ostream& operator<<(std::ostream &s, const NKN::Client::Message_t& m);

#endif  // __NKN_CLIENT_MSG_H__
