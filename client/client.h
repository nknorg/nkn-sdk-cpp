#ifndef __NKN_CLIENT_H__
#define __NKN_CLIENT_H__

#include <memory>
#include <future>

#include <safe_ptr.h>

#include "unique_ptr_backporting.h"
#include "crypto/secretbox.h"
#include "message.h"
#include "wallet.h"
#include "transaction/sigchain.h"
#include "serialize.h"
#include "client/config.h"

#include <cpprest/ws_client.h>

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

    Client();
    Client(const AccountPtr_t acc, const string& identifier, shared_ptr<ClientConfig_t> cfg=nullptr);

    /* Client(): wsCli(make_shared<websocket_callback_client>())
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
    } */

    inline ~Client() {
        fprintf(stderr, "%s:%d %s[%p] destructor.\n", __PRETTY_FUNCTION__, __LINE__, address.v.data(), this);
    }

    static ClientPtr_t NewClient(AccountPtr_t acc, string identifier, shared_ptr<ClientConfig_t> cfg=nullptr);

    int handleReconnect(int maxRetries);

    shared_ptr<Node> connect(int maxRetries);

    bool connectToNode(const shared_ptr<Node> node);

    pplx::task<void> sendWsJson(const initializer_list<kvPair_t>& kv);
    pplx::task<void> sendWsJson(const web::json::value& js);

    void pingRoutine(int32_t interval);

    void handleMessage(const websocket_incoming_message& msg);

    void TextMsgHandler(const string& msg);

    void PbMsgHandler(const vector<uint8_t>& msg, size_t len);

    void close_handler(websocket_close_status status, const utility::string_t& reason, const std::error_code& err);

    vector<shared_ptr<string>> EncryptMultiMsg(const string& data, vector<shared_ptr<Address>> dests);

    vector<shared_ptr<string>> EncryptSingelMsg(const string& data, shared_ptr<Address> dest);

    shared_ptr<payloads::Payload> DecryptInboundMsg(shared_ptr<payloads::Message> encMsg, shared_ptr<Address> peer);

    shared_ptr<string> DecryptMultiMsg(const string& cipher, shared_ptr<Address> peer, const string& encryptedKey, const string& nonce);

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
            const vector<shared_ptr<string>>& plds, bool encrypted, int32_t maxHoldingSeconds);

    pplx::task<void> Close();

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
                // auto t = std::time(nullptr);
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

};  // namespace Client
};  // namespace NKN
#endif  // __NKN_CLIENT_H__
