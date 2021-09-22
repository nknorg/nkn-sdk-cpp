#include <memory>

#include <pplx/pplxtasks.h>

#include "include/crypto/hex.h"
#include "ncp/error.h"
#include "tuna/client.h"
#include "ncp/session.h"

namespace NKN {
namespace TUNA {

constexpr size_t TunaSessionClient::NONCESIZE;

TunaSessionClient::TunaSessionClient(AccountPtr_t acc, MClientPtr_t cli, WalletPtr_t wal, ConfigPtr_t cfg)
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

                auto map = this->sessionConns->at(sessKey);
                for (auto it = map->cbegin(); it != map->cend(); it++) {
                    it->second->Close();
                }
                this->sessionConns->erase(sessKey);
                this->connCount->erase(sessKey);
                (*(this->closedSessionKey))[sessKey] = std::chrono::steady_clock::now();
                it = this->sessions->erase(it);
            }   // UnLock
        }
    }, 1000);
}

shared_ptr<NCP::Session> TunaSessionClient::newSession(const string& remoteAddr,
        const string& sessionID, const vector<string>& connIDs, shared_ptr<NCP::Config> cfg) {
    auto sessKey = remoteAddr + sessionID;
    return NCP::Session::NewSession(addr->v, remoteAddr, connIDs, {}, shared_from_this(),
                [](const TUNA::TunaCli_Ptr tuna, const string& connID, const string&, shared_ptr<string> buf, const std::chrono::milliseconds&) -> boost::system::error_code {
                    return ErrCode::Success;
                }, cfg);
                /* [this,sessKey,remoteAddr](const string& connID, const string&,
                    shared_ptr<string> buf, const std::chrono::milliseconds& ) -> boost::system::error_code {
                shared_ptr<TCPConn_t> conn = (*this->sessionConns)[sessKey][connID];
                if (conn == nullptr) {
                    return ErrCode::ErrNullConnection;
                }

                auto remote = make_shared<Client::Address_t>(remoteAddr);
                auto cipher = this->encode(*buf, remote);
                auto n = conn->Write(*cipher);
                return n == cipher->size() ? ErrCode::Success : ErrCode::ErrOperationAborted;
        }, cfg); */
}

shared_ptr<NCP::Session_t> TunaSessionClient::DialWithConfig(const string& remoteAddr, shared_ptr<DialConfig_t> cfg) {
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
    sessionConns->emplace(sessKey, safe_map<string, shared_ptr<TCPConn_t>>());
    auto& conn_map = (*sessionConns)[sessKey];

    atomic_size_t done_cnt(0);
    pplx::task_completion_event<size_t> wait_all;
    for (size_t idx=0; idx<addrs->size(); idx++) {
        auto addr = (*addrs)[idx];
        auto conn = make_shared<TCPConn_t>(addr->IP, (uint16_t)addr->Port);

        conn->Dial(5*1000)
            .then([idx,conn,this,meta,&remoteAddr,&conn_map](const boost_err& err){
                if (err) {
                    return err;
                }

                auto sent = conn->Write(this->addr->String());
                if (sent != this->addr->String().length()) {
                    return boost_err(ErrCode::ErrOperationAborted);
                }

                // Send pb.SessionMetadata
                auto nonce  = Uint192::Random<shared_ptr<Uint192>>();
                auto cipher = this->encode(meta->SerializeAsString(), make_shared<Client::Address_t>(remoteAddr));
                sent = conn->Write(*cipher);
                if (sent != cipher->size()) {
                    return boost_err(ErrCode::ErrOperationAborted);
                }

                (*conn_map)[to_string(idx)] = conn;
                return boost_err(ErrCode::Success);
            })
            .then([idx,&done_cnt,&wait_all,&addrs](const boost_err& err){
                cerr << "TCPConn[" << idx << "] Dial result: " << err << '\n';
                done_cnt++;
                if (done_cnt == addrs->size()) {
                    wait_all.set(done_cnt.load());
                }
            });
    }
    size_t cnt = pplx::create_task(wait_all).get();
    assert (cnt == addrs->size());

    if(conn_map->size() == 0) {
        // TODO all Dial failed
    }

    vector<string> conn_list;
    for (auto it = conn_map->cbegin(); it != conn_map->cend(); it++) {
        conn_list.emplace_back(it->first);
    }

    auto sess = newSession(remoteAddr, sessionID, conn_list, config->SessionConfig);
    if (sess == nullptr) {
        cerr << "newSession failed\n";
        return nullptr;
    }
    (*sessions)[sessKey] = sess;

    for (auto it = conn_map->cbegin(); it != conn_map->cend(); it++) {
        if (it->second != nullptr) {
            int idx = std::stoi(it->first);
            shared_ptr<TCPConn_t> conn = it->second;
            std::thread([this,sessKey,idx,conn](){
                this->handleConn(conn, sessKey, idx);
                conn->Close();
            }).detach();
        }
    }

    cout << "Try to Session Dial...\n";
    auto err = sess->Dial(/*timeout*/);
    if (err) {
        cerr << "Session.Dial() failed: " << err << '\n';
        return nullptr;
    }
    cout << "Session Dial success\n";
    return sess;
}

void TunaSessionClient::handleConn(shared_ptr<TCPConn_t> conn, const string& sessKey, int idx) {
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

boost::system::error_code TunaSessionClient::handleMsg(shared_ptr<TCPConn_t> conn, SessionPtr_t sess, int idx) {
    auto data = conn->readMessage(config->SessionConfig->MTU + maxSessionMsgOverhead);
    if (data == nullptr) {
        // log
        return ErrCode::ErrOperationAborted;
    }

    auto plain = decode((uint8_t*)data->data(), data->size(), make_shared<Client::Address_t>(sess->RemoteAddr()));
    if (plain == nullptr) {
        // log
        return ErrCode::ErrInvalidPacket;
    }

    return sess->ReceiveWith(to_string(idx), to_string(idx), plain);
}

};  // namespace TUNA
};  // namespace NKN
