#ifndef __NKN_NEW_CLIENT_H__
#define __NKN_NEW_CLIENT_H__

#include <memory>
#include <future>

#include <cpprest/ws_client.h>
#include <safe_ptr.h>

#include "include/unique_ptr_backporting.h"
#include "include/crypto/secretbox.h"
#include "include/wallet.h"
#include "message.h"
#include "transaction/sigchain.h"
#include "include/serialize.h"
#include "client/config.h"

namespace NKN {
namespace Client {

using namespace std;
using namespace web::websockets::client;

typedef class Client Client_t;
class Client: public enable_shared_from_this<Client> {
    friend class MultiClient;
public:
    // typedef websocket_callback_client           super;
    typedef shared_ptr<Client_t>                ClientPtr_t;
    typedef shared_ptr<const Wallet::Account_t> AccountPtr_t;
    typedef shared_ptr<Wallet::Wallet_t>        WalletPtr_t;
    typedef std::function<bool(unique_ptr<Message_t>)> msg_callback_fn;
    typedef shared_ptr<websocket_callback_client> wsCliPtr_t;
    template<typename K_t, typename V_t>
    using safe_map = sf::contfree_safe_ptr<unordered_map<K_t, V_t>>;

    Client(): wsCli(make_shared<websocket_callback_client>())
              , config(ClientConfig::MergeClientConfig(nullptr))
              , account(make_shared<const Wallet::Account_t>())
              , publicKey(account->PublicKey)
              , curveSecretKey(account->GetCurvePrivKey())
              , address(Address(account->PublicKey))
              , wallet(Wallet::NewWallet(account,
                          make_shared<Wallet::WalletCfg_t>(0,0,"",0,0,nullptr,config->SeedRPCServerAddr)))
              , reconnectChan(1)
              , OnMessage(config->MsgChanLen)
              , node(nullptr)
              , sigChainBlockHash(nullptr)
              , state(CREATED)
    {
        reconnThrd = std::async(launch::async, &Client::handleReconnect, this, 0);
        pingThrd   = std::async(launch::async, &Client::pingRoutine, this, this->pingInterval);

        reconnectChan.push(make_unique<bool>(true), true);  // genarated a reconnect event
    }

    Client(const AccountPtr_t acc, const string& identifier, shared_ptr<ClientConfig_t> cfg=nullptr)
        : wsCli(make_shared<websocket_callback_client>())
          , config(ClientConfig::MergeClientConfig(cfg))
          , account(acc ? acc : make_shared<const Wallet::Account_t>())
          , publicKey(account->PublicKey), curveSecretKey(account->GetCurvePrivKey())
          , address(Address(account->PublicKey, identifier))
          , wallet(Wallet::NewWallet(account,
                      make_shared<Wallet::WalletCfg_t>(0,0,"",0,0,nullptr,config->SeedRPCServerAddr)))
          , reconnectChan(1)
          , OnMessage(config->MsgChanLen)
          , node(nullptr)
          , sigChainBlockHash(nullptr)
          , state(CREATED)
    {
        reconnThrd = std::async(launch::async, &Client::handleReconnect, this, 0);
        pingThrd   = std::async(launch::async, &Client::pingRoutine, this, this->pingInterval);

        reconnectChan.push(make_unique<bool>(true), true);  // genarated a reconnect event
    }

    ~Client() {
        fprintf(stderr, "%s:%d %s[%p] destructor.\n", __PRETTY_FUNCTION__, __LINE__, address.v.data(), this);
    }

    static ClientPtr_t NewClient(AccountPtr_t acc, string identifier, shared_ptr<ClientConfig_t> cfg=nullptr) {
        return make_shared<Client>(acc, identifier, cfg);
    }

    int handleReconnect(int maxRetries) {
        int failed_cnt = 0;
        int32_t interval = config->MinReconnectInterval;

        while (this->state != CLOSED || failed_cnt < maxRetries) {
            // block at read from Channel until timeout
            unique_ptr<bool> reconn = reconnectChan.pop(false, millisecond(3*config->MinReconnectInterval));

            if (!reconn)    continue;   // timeout, leave point for check this->state
            // if (*reconn == false) {} // Channel<false> should not happen. Just to be extension in future

            try {
                cerr << "try to connect the " << failed_cnt+1 << " times via seed Server: "
                    << (config->SeedRPCServerAddr ? *(config->SeedRPCServerAddr) : vector<string>()) << endl;

                auto node = this->connect(1);
                if (node) {
                    interval = config->MinReconnectInterval;    // reset interval
                    failed_cnt = 0;
                    this->node = node;
                    continue;   // connect success
                }
            } catch (const websocket_exception& ex) {
                fprintf(stderr, "Catch an exception during webSocket connect: %s\n", ex.what());
            }

            // connect failed or throw exception
            failed_cnt++;
            interval = min(interval*2, config->MaxReconnectInterval);   // adjust retry interval
            this_thread::sleep_for(chrono::milliseconds(interval));
            reconnectChan.push(make_unique<bool>(true), true);  // genarated a reconnect event
        }

        bool unreach_max_retries = failed_cnt < maxRetries;
        if (!unreach_max_retries) {
            // client closed by other thread
            unique_lock<decltype(stateMutex)> lock(stateMutex);
            this->state = CLOSED;
            stateCond.notify_all();
        }

        return unreach_max_retries;
    }

    shared_ptr<Node> connect(int maxRetries) {
        auto node = GetWSAddress<shared_ptr<Node>>(address.v, *(config->SeedRPCServerAddr));
        if (node) {
            cerr << "Client::connect connect Node [" << node->ID << ":" << node->Addr << "]" << endl;
            if (!connectToNode(node)) {
                cerr << "Client::connect failed to connect Node [" << node->ID << ":" << node->Addr << "]" << endl;
                node = nullptr;
            }
        }

        return node;
    }

    bool connectToNode(const shared_ptr<Node> node) {
        auto uri = uri_builder().set_scheme("ws").set_host(node->Addr).to_uri();
        auto newWsCli = make_shared<websocket_callback_client>();
        newWsCli->set_message_handler(std::bind(&Client::handleMessage, this, placeholders::_1));
        newWsCli->set_close_handler(std::bind(&Client::close_handler, this, placeholders::_1, placeholders::_2, placeholders::_3));

        {
            unique_lock<decltype(stateMutex)> lock(stateMutex);
            state = DIALING;
            stateCond.notify_all();
        }

        try {
            newWsCli->connect(uri).get();    // TODO set Handshake timeout

            // swap newWsCli & prevCli after connect success
            auto prevCli = wsCli;
            wsCli = newWsCli;

            prevCli->close().then([prevCli](){
                fprintf(stderr, "ws_client[%p] was closed\n", prevCli.get());
            });
        } catch (const std::exception& ex) {
            fprintf(stderr, "%s:%d occurred exception [%s]\n", __PRETTY_FUNCTION__, __LINE__, ex.what());
            // TODO backtrace
            unique_lock<decltype(stateMutex)> lock(stateMutex);
            state = DISCONNECTED;
            stateCond.notify_all();
            return false;
        }

        // TODO check node->RPCAddr and update to config.SeedRPCServerAddr

        // NKN setClient action
        sendWsJson({
            kvPair_t("Action", "setClient"),
            kvPair_t("Addr", this->address.v),
        });     // setClient via async

        return true;
    }

    pplx::task<void> sendWsJson(const initializer_list<kvPair_t>& kv) {
        json::value js = json::value::object();
        for (auto& it: kv)
            js[U(it.first)] = json::value(it.second);
        return sendWsJson(js);
    }
    pplx::task<void> sendWsJson(const web::json::value& js) {
        websocket_outgoing_message msg;
        msg.set_utf8_message(js.serialize());
        return wsCli->send(msg);
    }

    void pingRoutine(int32_t interval) {
        auto self(shared_from_this());
        while (true) {
            {   // Lock
                unique_lock<decltype(stateMutex)> lock(stateMutex);
                if (stateCond.wait_for(lock, chrono::milliseconds(interval),
                        [self](){ return self->state == CLOSED; }   // wake up if state == CLOSED
                    )) {
                    break;  // break & exit pingRoutine thread
                }

                // wake up by timeout
                if (state != CONNECTED)
                    continue;   // only ping during connected
            }   // UnLock

            websocket_outgoing_message ping;
            ping.set_ping_message();
            try {
                wsCli->send(ping).then([](){ // TODO set write deadline
                    auto t = std::time(nullptr);
                    cerr << "interval ping msg at " << std::ctime(&t);
                });
            } catch (const websocket_exception& ex) {
                fprintf(stderr, "%s:%d occurred exception [%s]\n", __PRETTY_FUNCTION__, __LINE__, ex.what());
            }
        }
    }

    void handleMessage(const websocket_incoming_message& msg) {
        // TODO update pongTimeout
        switch (auto typ = msg.message_type()) {
            case websocket_message_type::text_message:
                msg.extract_string().then(std::bind(&Client::TextMsgHandler, this, placeholders::_1));  //.get();
                break;
            case websocket_message_type::binary_message: {
                concurrency::streams::container_buffer<std::vector<uint8_t>> buff;
                auto cnt = msg.body().read_to_end(buff).get();
                this->PbMsgHandler(buff.collection(), cnt);
                break;
            }
            case websocket_message_type::ping:
            {
                // responsePong
                websocket_outgoing_message pong;
                pong.set_pong_message();
                wsCli->send(pong).then([](){ cerr << "response pong msg success" << endl; });
                break;
            }
            case websocket_message_type::pong:
                // cerr << "Recv a pong_message" << endl;
                // TODO update keepalive timeout
                break;
            default:
                cerr << "Recv a unknown msg type: " << static_cast<int>(msg.message_type()) << endl;
        }
    }

    void TextMsgHandler(const string& msg){
        std::error_code err;
        auto js = json::value::parse(msg, err);
        if (err) {
            cerr << "TextMsgHandler: invalid json string[" << msg << "] with code:"
                << err.value() << ", reason:" << err.message() << endl;
            return;
        }

        auto act = js[U("Action")];
        auto desc = js[U("Desc")];
        auto error = js[U("Error")];
        auto result = js[U("Result")];

        if (act.is_null() || error.is_null() || result.is_null()) {
            cerr << "TextMsgHandler: invalid json msg without action/error/reult field" << endl;
            return;
        }

        if (error.as_number().to_int64() != 0) {
            cerr << act << ": action met error:" << error << ", Desc:" << desc << endl;
            // TODO handle errcode.WRONG_NODE
            // TODO error handle, reconnect node
            // this->close().then();
            return;
        }

        if (act.as_string().compare("setClient") == 0) {
            auto sigHash = result[U("sigChainBlockHash")];
            this->sigChainBlockHash = make_shared<Uint256>(sigHash.as_string());
            Node node(result[U("node")]);

            if (this->node && this->node->Equal(node)) {
                unique_lock<decltype(stateMutex)> lock(stateMutex);
                state = CONNECTED;
                stateCond.notify_all();
                OnConnect.push(make_unique<bool>(true), true);
            } else {
                unique_lock<decltype(stateMutex)> lock(stateMutex);
                state = DISCONNECTED;
                stateCond.notify_all();
                reconnectChan.push(make_unique<bool>(true), true);
            }
        } else if (act.as_string().compare("updateSigChainBlockHash") == 0) {
            this->sigChainBlockHash = make_shared<Uint256>(result.as_string());
        } else {
            cerr << "Unsupported webSocket action: " << act << endl;
        }
    }

    void PbMsgHandler(const vector<uint8_t>& msg, size_t len) {
        assert(len == msg.size());

        // Unmarshal pb::ClientMessage
        auto cliMsgPtr = make_shared<pb::ClientMessage>();
        cliMsgPtr->ParseFromArray(msg.data(), msg.size());
        if (cliMsgPtr->message_type() != pb::ClientMessageType::INBOUND_MESSAGE) {
            cerr << "PbMsgHandler(): received a non-inbound msg which type: " << cliMsgPtr->message_type() << ". ignore it." << endl;
            return;
        }

        // Unmarshal pb::InboundMessage
        auto inMsg = make_shared<pb::InboundMessage>();
        inMsg->ParseFromString(cliMsgPtr->message());

        auto remoteAddr = make_shared<Address>(inMsg->src());
        const string& prevHash = inMsg->prev_hash();
        if (prevHash.length() > 0) {
            // TODO sendReceipt(prevHash)
        }

        // Unmarshal inbound.payload
        auto pldMsg = make_shared<payloads::Message>();
        pldMsg->ParseFromString(inMsg->payload());

        // Decrypt/Unmarshal inbound.payload.payload
        shared_ptr<payloads::Payload> pld = nullptr;
        if (pldMsg->encrypted()) {
            pld = DecryptInboundMsg(pldMsg, remoteAddr);
        } else {
            pld = make_shared<payloads::Payload>();
            pld->ParseFromString(pldMsg->payload());
        }

        auto idStr = pld->message_id();
        auto msgID = make_shared<Uint64>(idStr.data(), idStr.length(), Uint64::FORMAT::BINARY);
        auto msgType = pld->type();
        auto data = pld->data();

        switch (msgType) {
            case payloads::TEXT: {
                auto textData = make_shared<payloads::TextData>();
                textData->ParseFromString(data);
                data = textData->text();
                break;
            }
            case payloads::ACK:
                // cout << "Received an ACK msg for msgID: " << HEX::EncodeToString(msgID);
                // cout << " ReplyToID: " << HEX::EncodeToString(pld->reply_to_id()) << endl;
                data = string();
                break;
            default:
                cout << "Unknown msg type: " << msgType << endl;
        }

        auto usrMsg = Message::NewMessage(remoteAddr, msgType, data, pldMsg->encrypted(), pld->no_reply(), msgID);

        // TODO is a reply msg
        auto msgIDbinStr = pld->reply_to_id();
        if (msgIDbinStr.length() > 0) {
            assert(msgIDbinStr.length() == 8);

            // uint64_t mID = Uint64(msgIDbinStr.data(), 64/8, Uint64::BINARY).Value().get_ui();
            if (responseChannels->count(msgIDbinStr) > 0) { // key existed
                auto ch = std::move(responseChannels->operator[](msgIDbinStr));
                responseChannels->erase(msgIDbinStr);
                if (!ch->push(std::move(usrMsg), true)) {
                    cerr << "********* Recv a reply msg but channel full. drop it" << endl;
                }
                /* if (cb) {
                    cb(std::move(usrMsg));
                } // TODO else { // log invalid callback } */
            }
            return;
        }

        auto self(shared_from_this());
        if (!pld->no_reply()) { // required reply by remote
            usrMsg->reply = [remoteAddr, pldMsg, msgID, self](const byteSlice& data){
                auto msg = newReplyPayload(data, msgID);
                return self->_send(vector<shared_ptr<Address>>{remoteAddr}, msg, pldMsg->encrypted(), 0);
            };
        }

        OnMessage.push(std::move(usrMsg), true);
    }

    void close_handler(websocket_close_status status, const utility::string_t& reason, const std::error_code& err) {
        // TODO log status & reason & err
        unique_lock<decltype(stateMutex)> lock(stateMutex);
        if (state == CLOSED)    // do nothing if CLOSED
            return;

        state = DISCONNECTED;
        reconnectChan.push(make_unique<bool>(true), true);
        stateCond.notify_all();
    }

    vector<shared_ptr<string>> EncryptMultiMsg(const string& data, vector<shared_ptr<Address>> dests) {
        auto msgNonce = Uint192::Random<shared_ptr<Uint192>>();
        auto msgKey   = Uint256::Random<shared_ptr<Uint256>>();
        auto cipher   = SecretBox::Encrypt(data, msgKey, msgNonce);

        vector<shared_ptr<string>> ret;
        // const Uint256 x25519SK = account->GetCurvePrivKey();
        for (auto& it: dests) {
            // TODO cache shareKey
            auto keyNonce = Uint192::Random<shared_ptr<Uint192>>();
            auto shareKey = SecretBox::Precompute<shared_ptr<Uint256>>(it->pubKey->toCurvePubKey<Uint256>(), this->curveSecretKey);
            auto encryptedKey = SecretBox::Encrypt(msgKey->toBytes(), shareKey, keyNonce);

            auto msg = make_shared<payloads::Message>();
            msg->set_payload(*cipher);
            msg->set_encrypted(true);
            msg->set_nonce(keyNonce->toBytes() + msgNonce->toBytes());
            msg->set_encrypted_key(*encryptedKey);

            auto encMsg = make_shared<string>(msg->ByteSizeLong(), 0);
            msg->SerializeToArray((uint8_t*)encMsg->data(), msg->ByteSizeLong());
            ret.push_back(encMsg);
        }
        return ret;
    }

    vector<shared_ptr<string>> EncryptSingelMsg(const string& data, shared_ptr<Address> dest) {
        auto nonce = Uint192::Random<shared_ptr<Uint192>>();
        // auto nonce = make_shared<Uint192>("383736353433323138373635343332313837363534333231");   // Debug
        // TODO cache shareKey
        auto shareKey = SecretBox::Precompute<shared_ptr<Uint256>>(dest->pubKey->toCurvePubKey<Uint256>(), this->curveSecretKey);
        shared_ptr<string> cipher = SecretBox::Encrypt(data, shareKey, nonce);

        auto msg = make_shared<payloads::Message>();
        msg->set_payload(*cipher);
        msg->set_encrypted(true);
        msg->set_nonce(nonce->toBytes());
        // nullptr encrypted_key

        auto encMsg = make_shared<string>(msg->ByteSizeLong(), 0);
        msg->SerializeToArray((uint8_t*)encMsg->data(), msg->ByteSizeLong());
        return vector<shared_ptr<string>>(1, encMsg);
    }

    shared_ptr<payloads::Payload> DecryptInboundMsg(shared_ptr<payloads::Message> encMsg, shared_ptr<Address> peer) {
        auto encryptedKey = encMsg->encrypted_key();
        auto nonce = encMsg->nonce();

        auto pld = make_shared<payloads::Payload>();
        if (encryptedKey.length() > 0) {    // encrypted msg with common key for multi-receiver
            pld->ParseFromString(*DecryptMultiMsg(encMsg->payload(), peer, encryptedKey, nonce));
        } else {    // encrypted msg with peer shareKey
            auto noncePtr = make_shared<Uint192>(nonce.data(), nonce.length(), Uint192::FORMAT::BINARY);
            auto plainPtr = DecryptSingelMsg(encMsg->payload(), peer, noncePtr);
            pld->ParseFromString(*plainPtr);
        }
        return pld;
    }

    shared_ptr<string> DecryptMultiMsg(const string& cipher, shared_ptr<Address> peer, const string& encryptedKey, const string& nonce) {
        // TODO shareKey cache
        auto noncePtr = nonce.data();
        auto shareKey = SecretBox::Precompute<shared_ptr<Uint256>>(peer->pubKey->toCurvePubKey<Uint256>(), this->curveSecretKey);

        auto keyNoncePtr = make_shared<Uint192>(noncePtr, 192/8, Uint192::FORMAT::BINARY);
        auto msgNoncePtr = make_shared<Uint192>(noncePtr+192/8, 192/8, Uint192::FORMAT::BINARY);
        auto plainKey = SecretBox::Decrypt(encryptedKey, shareKey, keyNoncePtr);

        return SecretBox::Decrypt(cipher,
                        make_shared<Uint256>(plainKey->data(), plainKey->length(), Uint256::FORMAT::BINARY),
                        keyNoncePtr);
    }

    inline shared_ptr<string> DecryptSingelMsg(const string& cipher, shared_ptr<Address> peer, shared_ptr<Uint192> nonce) {
        // TODO shareKey cache
        auto shareKey = SecretBox::Precompute<shared_ptr<Uint256>>(peer->pubKey->toCurvePubKey<Uint256>(), this->curveSecretKey);
        return SecretBox::Decrypt(cipher, shareKey, nonce);
    }

    template<typename T>
    inline OnMessagePtr_t SendText(const vector<string>& dests, const T& data, shared_ptr<MessageConfig_t> cfg=nullptr) {
        return Send(dests, data, cfg);
    }
    template<typename T>
    inline OnMessagePtr_t SendBinary(const vector<string>& dests, const T& data, shared_ptr<MessageConfig_t> cfg=nullptr) {
        return Send(dests, data, cfg);
    }

    /*** Send<string>: send msg as TextPayload   ***
     *** Send<T>:      sned msg as BinaryPayload ***/
    template<typename T>
    OnMessagePtr_t Send(const vector<shared_ptr<Address_t>>& dests, const T& data, shared_ptr<MessageConfig_t> cfg=nullptr) {
        auto& msgCfg = this->config->MessageConfig;
        msgCfg->MergeConfig(cfg);

        auto dest_cnt = dests.size();
        if (0 == dest_cnt) {
            // TODO empty destination error
            fprintf(stderr, "%s:%d empty dests.\n", __PRETTY_FUNCTION__, __LINE__);
            return nullptr;
        }

        shared_ptr<payloads::Payload> pld = newMessagePayload(data, msgCfg->MessageID, msgCfg->NoReply);
        if (!pld) {
            fprintf(stderr, "%s:%d new Msg payload failed.\n", __PRETTY_FUNCTION__, __LINE__);
            return nullptr;
        }

        if (!_send(dests, pld, !msgCfg->Unencrypted, msgCfg->MaxHoldingSeconds)) {   // send failed
            fprintf(stderr, "%s:%d ********** send msg failed.\n", __PRETTY_FUNCTION__, __LINE__);
            return nullptr;
        }

        auto ret = make_shared<OnMessage_t>(1);
        if (!msgCfg->NoReply) {
            (*responseChannels)[pld->message_id()] = ret;
        }
        return ret;
    }

    /*** Send<string>: send msg as TextPayload   ***
     *** Send<T>:      sned msg as BinaryPayload ***/
    template<typename T>
    OnMessagePtr_t Send(const vector<string>& dests, const T& data, shared_ptr<MessageConfig_t> cfg=nullptr) {
        // resolved dests addrs
        vector<shared_ptr<Address_t>> resolveds;
        for (auto& it: dests) {
            auto ptr = make_shared<Address>(it);
            if (! ptr->ResolveNS()) {
                continue;
            }
            resolveds.push_back(ptr);
        }

        return Send(resolveds, data, cfg);
    }

    shared_ptr<pb::OutboundMessage> newOutboundMessage(const vector<shared_ptr<Address>>& dests,
            const vector<shared_ptr<string>>& plds, bool encrypted, int32_t maxHoldingSeconds) {

        uint32_t nonce = Random<uint32_t>()();
        // uint32_t nonce = (uint32_t)-1;   // Debug

        // new SigChain
        auto sc = make_shared<pb::SigChain>();
        sc->set_nonce(nonce);
        sc->set_src_id(this->address.addressID->toBytes()); // TODO NameResolve if address.addressID empty
        sc->set_src_pubkey(this->publicKey.toBytes());
        if (this->sigChainBlockHash)
            sc->set_block_hash(sigChainBlockHash->toBytes());

        // append SigChainElem
        auto scElem = sc->add_elems();
        scElem->set_next_pubkey(this->node->PubKey.toHexString());
        const string elem_serial = Serialize(*scElem);

        // New&Set OutboundMessage Ptr
        auto obMsg = make_shared<pb::OutboundMessage>();
        obMsg->set_max_holding_seconds(maxHoldingSeconds);
        obMsg->set_nonce(nonce);
        if (this->sigChainBlockHash)
            obMsg->set_block_hash(sigChainBlockHash->toBytes());

        // modify SigChain and serialize it for each destID
        auto pldBegin=plds.cbegin(), pldIter=plds.cbegin();
        for (auto dest=dests.cbegin(); dest != dests.cend(); dest++) {
            obMsg->add_dests((*dest)->v);

            // cover plds.size() < dests.size() case
            if (pldIter != plds.cend()) {
                obMsg->add_payloads(*(*pldIter));
                sc->set_data_size((*pldIter)->length());
                pldIter++;
            } else {
                sc->set_data_size((*pldBegin)->length());
            }

            // modify SigChain for each pair<dest, payload> and serialize it
            sc->set_dest_id((*dest)->addressID->toBytes());
            sc->set_dest_pubkey((*dest)->pubKey->toBytes());

            HASH h256("sha256");
            h256.write(Serialize(*sc));
            h256.write(elem_serial);
            obMsg->add_signatures(account->Sign(h256.read<basic_string,char>()));
        }

        return obMsg;
    }

    pplx::task<void> Close() {
        unique_lock<decltype(stateMutex)> lock(stateMutex);
        state = CLOSED;
        stateCond.notify_all();
        return wsCli->close();
    }

private:
    bool _send(const vector<string>& dests, shared_ptr<payloads::Payload> pld, bool encrypted, int32_t maxHoldingSeconds) {
        // typedef remove_reference<decltype(dests)>::type::const_iterator dests_iter_t;

        vector<shared_ptr<Address_t>> resolveds;
        for_each(dests.cbegin(), dests.cend(), [&resolveds](const string& it) {
            auto addr = make_shared<Address>(it);
            if (! addr->ResolveNS()) {
                return;
            }
            resolveds.emplace_back(addr);
        });

        return _send(resolveds, pld, encrypted, maxHoldingSeconds);
    }

    bool _send(const vector<shared_ptr<Address_t>>& dests,
            shared_ptr<payloads::Payload> pld, bool encrypted, int32_t maxHoldingSeconds) {
        auto dest_cnt = dests.size();
        maxHoldingSeconds = std::max(maxHoldingSeconds, 0);
        const string rawPld = pld->SerializeAsString();

        // initialize msgList directly with ternary operator for avoid copy assignment msgList
        auto msgList = !encrypted
                            ? vector<shared_ptr<string>>()  // unencrypt, init with empty msgList
                            : (dest_cnt > 1)                // encrypt, init with nonempty msgList had encrypted already
                                ? EncryptMultiMsg(rawPld, dests)
                                : EncryptSingelMsg(rawPld, dests[0]);

        auto obMsgList = make_shared<vector<shared_ptr<pb::OutboundMessage>>>();
        if (!encrypted) {   // Unencrypt mode
            auto msg = make_shared<payloads::Message>();
            msg->set_payload(rawPld);
            msg->set_encrypted(false);

            auto pbPld = make_shared<string>(msg->ByteSizeLong(), 0);
            msg->SerializeToArray((uint8_t*)pbPld->data(), msg->ByteSizeLong());
            msgList.emplace_back(pbPld); // only one serialized pb::payloads::Message in unencrypt mode

            size_t totalSize = pbPld->length();
            for (auto& it: dests) {
                // TODO split multiple outbound msg when totalSize reach maxClientMessageSize
                totalSize += it->v.length() + ED25519::SignatureSize;
            }
            if (totalSize > maxClientMessageSize) {
                return false;
            }

            auto outboundMsg = newOutboundMessage(dests, msgList, false, maxHoldingSeconds);
            obMsgList->push_back(outboundMsg);
        } else {    // Encrypt mode
            size_t totalSize = 0;
            vector<shared_ptr<Address_t>>::const_iterator destPos, destIter = dests.begin();
            vector<shared_ptr<string>>::const_iterator    dataPos, dataIter = msgList.begin();
            for (destPos=destIter, dataPos=dataIter; destIter != dests.end(); destIter++, dataIter++) {
                auto Len = (*dataIter)->length() + (*destIter)->v.length() + ED25519::SignatureSize;
                if (Len > maxClientMessageSize) {
                    cerr << "encoded message is greater than " << maxClientMessageSize << " bytes" << endl;
                    return false;
                }
                if (totalSize+Len > maxClientMessageSize) {
                    auto outboundMsg = newOutboundMessage(
                            vector<shared_ptr<Address_t>>(destPos, destIter),
                            vector<shared_ptr<string>>(dataPos, dataIter),
                            true, maxHoldingSeconds
                         );
                    obMsgList->push_back(outboundMsg);
                    totalSize = 0;  // reset totalSize counter
                    destPos = destIter;
                    dataPos = dataIter;
                }
                totalSize += Len;
            }

            auto outboundMsg = newOutboundMessage(
                    vector<shared_ptr<Address_t>>(destPos, dests.end()),
                    vector<shared_ptr<string>>(dataPos, msgList.end()),
                    true, maxHoldingSeconds
                    );
            obMsgList->push_back(outboundMsg);
        }

        // TODO set msgCfg->WsWriteTimeout

        for (auto& it: *obMsgList) {
            auto wsMsgPtr = make_shared<websocket_outgoing_message>();
            wsMsgPtr->set_binary_message(
                concurrency::streams::container_buffer<std::string>(newClientMessage(it)->SerializeAsString())
            );
            wsCli->send(*wsMsgPtr).then([wsMsgPtr](){
                auto t = std::time(nullptr);
            });
        }

        return true;
    }

private:
    wsCliPtr_t wsCli;
    mutex stateMutex; // lock

public:
    static constexpr size_t MessageIDSize = 64/8;     // 64bit msgID
    static constexpr size_t maxClientMessageSize = 4*1000*1000;
    static constexpr int32_t pingInterval = 8*1000;

    shared_ptr<ClientConfig_t> config;
    const AccountPtr_t account;
    const ED25519::PubKey_t& publicKey;
    const Uint256 curveSecretKey;
    const Address address;
    WalletPtr_t wallet;

    Channel<bool> reconnectChan;
    Channel<bool> OnConnect;
    OnMessage_t OnMessage;
    safe_map<string, OnMessagePtr_t> responseChannels;

    shared_ptr<Node> node;  // NKN node which client connecting
    shared_ptr<Uint256> sigChainBlockHash;

    std::future<void> pingThrd;
    std::future<int> reconnThrd;

    typedef enum {
        CREATED,
        DISCONNECTED,
        DIALING,
        CONNECTED,
        CLOSED,
    } state_t;
    std::atomic<state_t> state;
    condition_variable stateCond;
};  // class Client
constexpr size_t Client::MessageIDSize;// = 64/8;     // 64bit msgID
constexpr size_t Client::maxClientMessageSize;// = 4*1000*1000;
constexpr int32_t Client::pingInterval;// = 8*1000;

};  // namespace Client
};  // namespace NKN
#endif  // __NKN_NEW_CLIENT_H__
