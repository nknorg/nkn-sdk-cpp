#ifndef __NKN_TUNA_SESS_H__
#define __NKN_TUNA_SESS_H__

#include <chrono>
#include <future>
#include <string>
#include <unordered_map>
#include <memory>
#include <thread>
#include <vector>
#include <cassert>
#include <initializer_list>

#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <safe_ptr.h>

#include "client/address.h"
#include "client/multiclient.h"
#include "include/account.h"
#include "include/wallet.h"
#include "include/crypto/secretbox.h"
#include "include/rpc.h"

#include "client/client.h"

#include "ncp/config.h"
#include "ncp/error.h"
#include "ncp/session.h"
#include "tuna/config.h"
#include "tuna/error.h"
#include "tuna/interface.h"
#include "tuna/tcpconn.h"
#include "tuna/message.h"
#include "tuna/pb/session.pb.h"

namespace NKN {
namespace TUNA {

using namespace std;

constexpr uint32_t maxSessionMsgOverhead = 1024;

typedef class TunaSessionClient TunaSessionClient_t;
class TunaSessionClient {
public:
    typedef shared_ptr<TunaSessionClient_t> TunaSessCliPtr_t;
    typedef shared_ptr<Config_t>            ConfigPtr_t;
    typedef shared_ptr<Client::MultiClient> MClientPtr_t;
    typedef shared_ptr<NCP::Session_t>      SessionPtr_t;
    typedef shared_ptr<Wallet::Account_t>   AccountPtr_t;
    typedef shared_ptr<Wallet::Wallet_t>    WalletPtr_t;
    typedef shared_ptr<Uint256>             Uint256Ptr_t;
    typedef shared_ptr<const Client::Address_t>   AddressPtr_t;
    typedef std::chrono::time_point<std::chrono::steady_clock>  ptime_t;

    template<typename K_t, typename V_t>
    using safe_map = sf::contfree_safe_ptr<unordered_map<K_t, V_t>>;

    TunaSessionClient() = default;
    TunaSessionClient(const TunaSessionClient_t&) = delete;
    TunaSessionClient& operator=(const TunaSessionClient_t&) = delete;

    atomic_bool isClosed;
    ConfigPtr_t   config;
    WalletPtr_t   wallet;
    AccountPtr_t  clientAccount;
    MClientPtr_t  multiClient;
    AddressPtr_t  addr;
    // net.Addr;
    // chan shared_ptr<NCP::Session_t>    acceptSession;
    Channel<bool> onClose;
    mutex RWMutex;
    vector<shared_ptr<Listener_t>> listeners;
    // TunaExit    tunaExits;
    // Regexp  acceptAddrs;
    safe_map<string, SessionPtr_t>                    sessions;
    safe_map<string, map<string, shared_ptr<TCPConn_t>>> sessionConns;
    safe_map<string, Uint256Ptr_t>                    sharedKeys;
    safe_map<string, int32_t>                         connCount;
    safe_map<string, ptime_t>                         closedSessionKey;  // TODO expired feature

    boost::asio::io_context async_io;   // to be obsoleted
    std::future<void> sessCleaner;
    // boost::thread*  AsyncThrd;

    TunaSessionClient(AccountPtr_t acc, MClientPtr_t cli, WalletPtr_t wal, ConfigPtr_t cfg)
        : isClosed(false)
          , config(Config::MergedConfig(cfg))
          , wallet(wal)
          , clientAccount(acc)
          , multiClient(cli)
          , addr(cli->addr)
          , sessions()
          , sessionConns()
          , sharedKeys()
          , connCount()
          , closedSessionKey()
          , async_io()
    {
        sessCleaner = std::async(launch::async, [this](uint32_t interval){
            while (!isClosed) {
                this_thread::sleep_for(std::chrono::milliseconds(interval));

                // TODO Lock
                for (auto it=this->sessions->cbegin(); it != this->sessions->cend(); ) {
                    const string& sessKey = it->first;
                    const shared_ptr<NCP::Session_t>& sess = it->second;

                    if (!sess->IsClosed()) {
                        it++;
                        continue;
                    }

                    for (auto& kv: this->sessionConns->at(sessKey)) {
                        kv.second->Close();
                    }
                    this->sessionConns->erase(sessKey);
                    this->connCount->erase(sessKey);
                    (*(this->closedSessionKey))[sessKey] = std::chrono::steady_clock::now();
                    it = this->sessions->erase(it);
                }   // UnLock
            }
        }, 1000);
    }

    inline static TunaSessCliPtr_t NewTunaSessionClient(AccountPtr_t acc, MClientPtr_t cli, WalletPtr_t wal, ConfigPtr_t cfg) {
        return make_shared<TunaSessionClient_t>(acc, cli, wal, cfg);
    }

    inline virtual ConnPtr_t Dial(const string& remoteAddr) final {
        return DialSession(remoteAddr);
    }

    inline virtual SessionPtr_t DialSession(const string& remoteAddr) final {
        return DialWithConfig(remoteAddr, nullptr);
    }

    SessionPtr_t DialWithConfig(const string& remoteAddr, shared_ptr<DialConfig_t> cfg=nullptr) {
        auto dialCfg = DialConfig::MergeDialConfig(config->SessionConfig, cfg);

        // TODO set timeout with dialCfg->DialTimeout
        auto jsStr = NewJson(initializer_list<kvPair_t>({
                                kvPair_t("action", "getPubAddr"),
                            }))->serialize();
        auto recv_ch = multiClient->Send(vector<string>{remoteAddr}, static_cast<byteSlice&>(jsStr));
        auto resp = recv_ch->pop(false, std::chrono::milliseconds(dialCfg->DialTimeout));
        if (!resp) {
            // TODO log error
            return nullptr;
        }

        auto addrs = PubAddrs::NewFromMsg(resp->Data);
        if (!addrs) {
            // TODO log error
            return nullptr;
        }

        auto sessionID = Uint64::Random<string>();
        auto meta = make_shared<pb::SessionMetadata>();
        meta->set_allocated_id(&sessionID);

        string sessKey = remoteAddr+sessionID;
        sessionConns->emplace(sessKey, map<string, shared_ptr<TCPConn_t>>());
        auto& conn_map = (*sessionConns)[sessKey];

        for (size_t idx=0; idx<addrs->size(); idx++) {
            auto addr = (*addrs)[idx];
            auto conn = make_shared<TCPConn_t>(addr->IP, (uint16_t)addr->Port);
            // TODO conn->set_msg_handler

            auto err = conn->Dial(5*1000)
                .then([conn,this,remoteAddr,meta](const boost::system::error_code& err){
                    if (err)    return err;

                    auto ec = conn->Write(this->addr->String()).get();
                    if (ec)    return ec;

                    // Send pb.SessionMetadata
                    auto nonce  = Uint192::Random<shared_ptr<Uint192>>();
                    auto cipher = this->encode(meta->SerializeAsString(), make_shared<Client::Address_t>(remoteAddr));

                    return conn->Write(*cipher).get();
                }).get();

            // if err, log err and close conn
            if (! err) {
                conn_map[to_string(idx)] = conn;
            }
        }

        if(conn_map.size() == 0) {
            // TODO all Dial failed
        }

        vector<string> conn_list;
        for (auto& kv: conn_map) {
            conn_list.emplace_back(kv.first);
        }

        auto sess = newSession(remoteAddr, sessionID, conn_list, config->SessionConfig);
        if (sess == nullptr) {
            return nullptr;
        }

        (*sessions)[sessKey] = sess;
        for (auto& it: conn_map) {
            if (it.second != nullptr) {
                int idx = std::stoi(it.first);
                shared_ptr<TCPConn_t> conn = it.second;
                std::thread([this,sessKey,idx,conn](){
                    this->handleConn(conn, sessKey, idx);
                    conn->Close();
                }).detach();
            }
        }

        auto err = sess->Dial(/*timeout*/);
        if (err) {
            return nullptr;
        }
        return sess;
    }

    shared_ptr<NCP::Session> newSession(const string& remoteAddr,
            const string& sessionID, const vector<string>& connIDs, shared_ptr<NCP::Config> cfg) {
        auto sessKey = remoteAddr + sessionID;
        return NCP::Session::NewSession(addr, remoteAddr, connIDs, {},
                    [this,sessKey,remoteAddr](const string& connID, const string&,
                        shared_ptr<string> buf, const std::chrono::milliseconds& ) -> boost::system::error_code {
                    shared_ptr<TCPConn_t> conn = (*this->sessionConns)[sessKey][connID];
                    if (conn == nullptr) {
                        return ErrCode::ErrNullConnection;
                    }

                    auto remote = make_shared<Client::Address_t>(remoteAddr);
                    auto cipher = this->encode(*buf, remote);
                    auto n = conn->Write(*cipher);
                    return n == cipher->size() ? ErrCode::Success : ErrCode::ErrOperationAborted;
            }, cfg);
    }

    void handleConn(shared_ptr<TCPConn_t> conn, const string& sessKey, int idx) {
        if (sessions->count(sessKey) == 0) {
            // log
            return;
        }

        SessionPtr_t sess = (*sessions)[sessKey];
        if (sess == nullptr) {
            // log
            return;
        }

        if (connCount->count(sessKey) == 0) {
            (*connCount)[sessKey] = 0;
        }
        (*connCount)[sessKey]++;

        while (!sess->IsClosed()) {
            auto err = handleMsg(conn, sess, idx);
            if (err) {
                if (err == NCP::ErrCode::ErrSessionClosed || err == boost::asio::error::eof) {
                    break;
                }
                auto c = onClose.pop(true);
                if (c && *c) {
                    break;
                }
                // log err
            }
        }

        auto conn_cnt = (*connCount)[sessKey];
        if (--conn_cnt == 0) {
            sessions->erase(sessKey);
            sessionConns->erase(sessKey);
            connCount->erase(sessKey);
            (*closedSessionKey)[sessKey] = std::chrono::steady_clock::now();
            sess->Close();
        }
    }

    boost::system::error_code handleMsg(shared_ptr<TCPConn_t> conn, SessionPtr_t sess, int idx) {
        auto data = readMessage(conn, config->SessionConfig->MTU + maxSessionMsgOverhead);
        if (data == nullptr) {
            // log
            return ErrCode::ErrOperationAborted;
        }

        auto plain = decode(*data, make_shared<Client::Address_t>(sess->RemoteAddr()));
        if (plain == nullptr) {
            // log
            return ErrCode::ErrInvalidPacket;
        }

        return sess->ReceiveWith(to_string(idx), to_string(idx), plain);
    }

    shared_ptr<string> encode(const byteSlice& msg, AddressPtr_t remote) {
        auto nonce  = Uint192::Random<shared_ptr<Uint192>>();
          // TODO cache shareKey
        auto shareKey = SecretBox::Precompute<shared_ptr<Uint256>>(
                                                remote->pubKey->toCurvePubKey<Uint256>(),
                                                clientAccount->GetCurvePrivKey());
        auto cipher = SecretBox::Encrypt(msg, shareKey, nonce);

        return make_shared<string>(nonce->toBytes() + *cipher);
    }

    shared_ptr<string> decode(uint8_t* cipher, size_t len, AddressPtr_t remote) {
        assert(len > NONCESIZE);

          // TODO cache shareKey
        auto shareKey = SecretBox::Precompute<shared_ptr<Uint256>>(
                                                remote->pubKey->toCurvePubKey<Uint256>(),
                                                clientAccount->GetCurvePrivKey());
        auto nonce = make_shared<Uint192>(cipher, NONCESIZE, Uint192::FORMAT::BINARY);
        return SecretBox::Decrypt<basic_string,char>(cipher+NONCESIZE, len-NONCESIZE, shareKey, nonce);
    }

    static constexpr size_t NONCESIZE = 192/8;
};  // class TunaSessionClient
constexpr size_t TunaSessionClient::NONCESIZE;

};  // namespace TUNA
};  // namespace NKN
#endif  // __NKN_TUNA_SESS_H__
