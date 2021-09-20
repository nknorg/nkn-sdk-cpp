
#include "client/message.h"

namespace NKN {
namespace Client {

using namespace std;

shared_ptr<payloads::Payload> newTextPayload(const string& data,
        shared_ptr<Uint64> messageID, shared_ptr<Uint64> replyToID, bool noReply){
    if (messageID == nullptr && replyToID == nullptr) {
        messageID = Random<shared_ptr<Uint64>>()();
    }

    payloads::TextData txt;
    txt.set_text(data);

    auto pld = make_shared<payloads::Payload>();
    pld->set_type(payloads::PayloadType::TEXT);
    pld->set_data(txt.SerializeAsString());
    pld->set_no_reply(noReply);
    if (messageID)
        pld->set_message_id(messageID->toBytes());
    if (replyToID)
        pld->set_reply_to_id(replyToID->toBytes());

    return pld;
}

shared_ptr<payloads::Payload> newAckPayload(const shared_ptr<Uint256> replyToID) {
    auto pld = make_shared<payloads::Payload>();
    pld->set_type(payloads::PayloadType::ACK);
    pld->set_reply_to_id(replyToID->toBytes());
    return pld;
}

shared_ptr<pb::ClientMessage> newClientMessage(shared_ptr<pb::OutboundMessage> obMsgPtr) {
    auto cliMsgPtr = make_shared<pb::ClientMessage>();
    cliMsgPtr->set_message_type(pb::ClientMessageType::OUTBOUND_MESSAGE);

    if (obMsgPtr->payloads_size() > 1) {
        cliMsgPtr->set_compression_type(pb::CompressionType::COMPRESSION_ZLIB);
        cliMsgPtr->set_message(nullptr); // crash pointer. TODO zip
    } else {
        cliMsgPtr->set_compression_type(pb::CompressionType::COMPRESSION_NONE);
        cliMsgPtr->set_message(obMsgPtr->SerializeAsString());
    }

    return cliMsgPtr;
}

Message::Message(shared_ptr<Address> src, payloads::PayloadType type,
        const byteSlice& data, bool encrypted, bool noReply, shared_ptr<Uint64> msgID)
    : Src(src), MessageID(msgID), Type(type), Data(data), Encrypted(encrypted), NoReply(noReply) {
    if (MessageID == nullptr) {
        MessageID = Uint64::Random<shared_ptr<Uint64>>();
    }
}

}; // namespace Client
}; // namespace NKN

// Message_t json Parser
template <typename T>
T& operator&(T& jsonCodec, const NKN::Client::Message_t& m) {
    jsonCodec.StartObject();
    jsonCodec.Member("Src") & m.Src->v;
    jsonCodec.Member("MessageID") & *m.MessageID;
    jsonCodec.Member("Type") & m.Type;
    jsonCodec.Member("Data") & m.Data;
    jsonCodec.Member("Encrypted") & m.Encrypted;
    jsonCodec.Member("NoReply") & m.NoReply;
    // TODO jsonCodec.Member("reply") function pointer
    return jsonCodec.EndObject();
}

std::ostream& operator<<(std::ostream &s, const NKN::Client::Message_t& m) {
    NKN::JSON::Encoder out;
    out & m;
    return s << out.GetString();
}
