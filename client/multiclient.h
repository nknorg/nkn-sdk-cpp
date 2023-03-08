#ifndef __NKN_MULTI_CLIENT_H__
#define __NKN_MULTI_CLIENT_H__

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <vector>
#include <functional>
#include <unordered_map>
#include <thread>
#include <memory>
#include <future>
#include <algorithm>
#include <condition_variable>

#include <safe_ptr.h>
#include "include/channel.h"
#include <cpprest/ws_client.h>

#include "include/wallet.h"
#include "include/account.h"
#include "client/config.h"
#include "client/client.h"
#include "ncp/session.h"
#include "payloads/payloads.pb.h"

namespace NKN {
namespace Client {
using namespace std;

typedef class MultiClient MultiClient_t;
class MultiClient: public enable_shared_from_this<MultiClient> {
public:
    typedef shared_ptr<Client_t>        Client_ptr;
    typedef shared_ptr<ClientConfig_t>  ClientConfig_ptr;
    typedef shared_ptr<NCP::Session_t>  Session_ptr;
    typedef shared_ptr<const Wallet::Account_t> Account_ptr;
    template<typename K_t, typename V_t>
    using safe_map = sf::contfree_safe_ptr<unordered_map<K_t, V_t>>;

    ClientConfig_ptr config;
    int offset;
    // const string addr;
    const shared_ptr<const Address> addr;
    Session_ptr acceptSession;

    // TODO onClose
    safe_map<string, chrono::time_point<chrono::steady_clock>> msgCache;

    Channel<bool>      OnConnect;
    Channel<Message_t> OnMessage;

    Client_ptr defaultClient;
    safe_map<int, Client_ptr> clients;

    // TODO acceptAddrs  regex

    std::atomic<bool> isClosed;
    std::atomic<bool> createDone;
    safe_map<string, Session_ptr> sessions;

    MultiClient() = delete;
    MultiClient(const MultiClient_t&) = delete;
    MultiClient& operator=(const MultiClient_t&) = delete;

    MultiClient(Account_ptr acc, const string& baseIdentifier, int cliCnt, bool originalClient, ClientConfig_ptr cfg=nullptr);

    inline ~MultiClient() {
        fprintf(stderr, "%s:%d %s[%p] destructor.\n", __PRETTY_FUNCTION__, __LINE__, addr->v.data(), this);
    }

    inline static shared_ptr<MultiClient_t> NewMultiClient(Account_ptr acc, const string& baseIdentifier,
            int numSubClients, bool originalClient, ClientConfig_ptr config=nullptr) {
        return make_shared<MultiClient_t>(acc, baseIdentifier, numSubClients, originalClient, config);
    }

    inline safe_map<int, Client_ptr> GetClients() {
        return createDone ? clients : safe_map<int, Client_ptr>(clients->cbegin(), clients->cend());
    }

    inline const shared_ptr<const Address> Addr() { return addr; }

    template<typename T>
    OnMessagePtr_t Send(const vector<string>& dests, const T& data, shared_ptr<MessageConfig_t> cfg=nullptr) {
        auto msgCfg = make_shared<MessageConfig_t>(*(config->MessageConfig));
        msgCfg->MergeConfig(cfg);

        if (0 == dests.size()) {
            // TODO empty destination error
            return nullptr;
        }

        shared_ptr<payloads::Payload> pld = newMessagePayload(data, msgCfg->MessageID, msgCfg->NoReply);
        if (!pld) {
            fprintf(stderr, "%s:%d new Msg payload failed.\n", __PRETTY_FUNCTION__, __LINE__);
            return nullptr;
        }

        return _send(dests, pld, !msgCfg->Unencrypted, msgCfg->MaxHoldingSeconds);
    }

    bool Close();

private:
    vector<std::future<void>> cli_thrd_grp;

    void subClient_handler(int idx, Account_ptr acc, const string& baseIdentifier) {
        while (!isClosed) {
            fprintf(stdout, "Creating subClient for idx: %d\n", idx);
            auto cli = Client::NewClient(acc, addIdentifier(baseIdentifier, idx), config);

            fprintf(stdout, "WsHandshakeTimeout: %d\n", config->WsHandshakeTimeout);
            unique_ptr<bool> succ = cli->OnConnect.pop(false, chrono::milliseconds(config->WsHandshakeTimeout));
            if (succ==nullptr || (*succ)==false) {
                // cli->close()
                this_thread::sleep_for(chrono::milliseconds(config->MinReconnectInterval));
                continue;
            }

            (*clients)[idx] = cli;
            // TODO Update this->defaultClient

            this->OnConnect.push(std::move(succ), true);

            while (cli->state != Client::state_t::CLOSED) {
                unique_ptr<NKN::Client::Message> msg = cli->OnMessage.pop(false, chrono::milliseconds(1000));
                if (!msg)    continue;

                if (msg->Type == payloads::PayloadType::SESSION) {
                    // TODO
                } else {
                    shared_ptr<Uint64> msgID = msg->MessageID;
                    auto key = msgID->toHexString();
                    auto ts  = steady_clock::now();

                    if (this->msgCache->count(key)) { // has key already
                        // TODO compare value with ts, update to the earlier timestamp
                        continue;
                    }
                    (*(this->msgCache))[key] = ts;

                    auto tuple = removeIdentifier(msg->Src);
                    if (!msg->NoReply) {
                        bool encrypted = msg->Encrypted;
                        msg->reply = [this, msgID, encrypted, tuple](const byteSlice& data)->bool{
                            auto msg = newReplyPayload(data, msgID);
                            return this->_send(vector<string>{tuple->first}, msg, encrypted, 0) != nullptr;
                        };
                    }

                    this->OnMessage.push(std::move(msg), true);
                }
            }
            if (cli) {
                fprintf(stderr, "subClient %p close due to state:%d\n", cli.get(), int(cli->state));
            }
            clients->erase(idx);
            cli->Close();   //.get();
            fprintf(stderr, "close subClient %p done\n", cli.get());
        }
        fprintf(stderr, "MultiClient %p state was %d\n", this, isClosed.load());
    }

    bool sendWithClient(const int clientID, const vector<string>& dests,
            shared_ptr<payloads::Payload> pld, bool encrypted, int32_t maxHoldingSeconds) {
        auto cli_lst    = this->GetClients();

        if (cli_lst->count(clientID) == 0) {    // key not existed
            fprintf(stderr, "No avaliable subClient[%d] to send\n", clientID);
            return false;   // TODO error code
        }

        auto cli = (*cli_lst)[clientID];
        if (cli == nullptr) {
            fprintf(stderr, "subClient[%d] is nullptr\n", clientID);
            return false;
        }

        return cli->_send(*addMultiClientPrefix(dests, clientID), pld, encrypted, maxHoldingSeconds);
    }

    OnMessagePtr_t _send(const vector<string>& dests, shared_ptr<payloads::Payload> pld, bool encrypted, int32_t maxHoldingSeconds) {
        auto cli_lst    = this->GetClients();
        auto succ_ch    = make_shared<Channel<bool>>(cli_lst->size());
        auto onRawReply = make_shared<OnMessage_t>(1);
        auto onReply    = make_shared<OnMessage_t>(1);

        auto self(shared_from_this());
        for (auto kv=cli_lst->cbegin(); kv!=cli_lst->cend(); kv++) {
            std::thread(
                // [self,succ_ch,onRawReply,onReply](decltype(cli_lst)::obj_t::const_iterator kv, const vector<string>& dests,
                [self,succ_ch,onRawReply,onReply](int cli_ID, Client_ptr subCli, const vector<string>& dests,
                        shared_ptr<payloads::Payload> pld, bool encrypted, int32_t maxHoldingSeconds){
                    auto resp_map = subCli->responseChannels;

                    if (!pld->no_reply()) {
                        (*resp_map)[pld->message_id()] = onRawReply;
                    }

                    auto succ = self->sendWithClient(cli_ID, dests, pld, encrypted, maxHoldingSeconds);
                    if (!succ) {
                        // ?? need to resp_map->erase(key)?
                        return;
                    }

                    if (!pld->no_reply()) {
                        // wait response and push to onReply channel
                        auto msg = onRawReply->pop(false, chrono::milliseconds(self->config->WsWriteTimeout));
                        if (msg) {
                            // get rid of clientID prefix
                            auto tuple = self->removeIdentifier(msg->Src);
                            msg->Src = make_shared<Address>(tuple->first);

                            onReply->push(std::move(msg), true);
                        }
                    }
                    succ_ch->push(make_unique<bool>(true), true);
                },
                kv->first, kv->second, dests, pld, encrypted, maxHoldingSeconds
            ).detach();;
        }

        // wait any of sub-clients succ until timeout
        /* auto succ = succ_ch->pop(false, chrono::milliseconds(this->config->WsWriteTimeout));
        fprintf(stderr, "%s:%d *************** Sent msg with timeo %d, got %d\n",
                __PRETTY_FUNCTION__, __LINE__, this->config->WsWriteTimeout, succ ? *succ : false);
        cerr << "return " << onReply << ".get() ";
        fprintf(stderr, "%p\n", onReply.get());
        return (succ && *succ) ? onReply : nullptr; */
        return onReply;
    }

    shared_ptr<pair<string, string>> removeIdentifier(shared_ptr<Address> addr) {
        const string& s = addr->v;
        auto pos = s.find('.', 0);
        // TODO s.substr(0, pos) regex match "^__\\d+__$";
        return make_shared<pair<string, string>>(
                    s.substr(pos + sizeof('.')),
                    s.substr(0, pos)
                );
    }

    /* shared_ptr<vector<string>> splitStr(const string& str, const string& delimiter="") {
        size_t pos_start = 0, pos_end;

        auto token_lst = make_shared<vector<string>>();
        while ((pos_end = str.find(delimiter, pos_start)) != string::npos) {
            token_lst->emplace_back(str.substr(pos_start, pos_end - pos_start));
            pos_start = pos_end + delimiter.length();
        }
        token_lst->emplace_back(str.substr(pos_start));

        return token_lst;
    } */

    inline const string addIdentifier(const string& base, int idx) {
        return idx<0 ? base : addIdentifierPrefix(base, "__" + to_string(idx) + "__");
    }

    inline const string addIdentifierPrefix(const string& base, const string& prefix) {
        return base.length()==0 ? prefix
                                : prefix.length()==0 ? base
                                                     : prefix + '.' + base;
    }

    shared_ptr<vector<string>> addMultiClientPrefix(const vector<string>& dests, int clientID) {
        auto ret = make_shared<vector<string>>(dests.size());
        transform(dests.cbegin(), dests.cend(), ret->begin(), [this,&clientID](const string& addr){
            return addIdentifier(addr, clientID);
        });
        return ret;
    }
};  // class MultiClient
};  // namespace Client
};  // namespace NKN
#endif  // __NKN_MULTI_CLIENT_H__
