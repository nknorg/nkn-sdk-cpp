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
class TunaSessionClient: public std::enable_shared_from_this<TunaSessionClient> {
public:
    typedef shared_ptr<TunaSessionClient_t> TunaSessCliPtr_t;
    typedef shared_ptr<Config_t>            ConfigPtr_t;
    typedef shared_ptr<Client::MultiClient> MClientPtr_t;
    typedef shared_ptr<NCP::Session_t>      SessionPtr_t;
    typedef shared_ptr<const Wallet::Account_t>   AccountPtr_t;
    typedef shared_ptr<Wallet::Wallet_t>    WalletPtr_t;
    typedef shared_ptr<Uint256>             Uint256Ptr_t;
    typedef shared_ptr<const Client::Address_t>   AddressPtr_t;
    typedef std::chrono::time_point<std::chrono::steady_clock>  ptime_t;
    typedef boost::system::error_code       boost_err;

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
    safe_map<string, safe_map<string, shared_ptr<TCPConn_t>>> sessionConns;
    safe_map<string, Uint256Ptr_t>                    sharedKeys;
    safe_map<string, int32_t>                         connCount;
    safe_map<string, ptime_t>                         closedSessionKey;  // TODO expired feature

    boost::asio::io_context async_io;   // to be obsoleted
    std::future<void> sessCleaner;
    // boost::thread*  AsyncThrd;

    TunaSessionClient(AccountPtr_t acc, MClientPtr_t cli, WalletPtr_t wal, ConfigPtr_t cfg);

    inline static TunaSessCliPtr_t NewTunaSessionClient(AccountPtr_t acc, MClientPtr_t cli, WalletPtr_t wal, ConfigPtr_t cfg) {
        return make_shared<TunaSessionClient_t>(acc, cli, wal, cfg);
    }

    inline virtual ConnPtr_t Dial(const string& remoteAddr) final {
        return dynamic_pointer_cast<Conn_t>(DialSession(remoteAddr));
    }

    inline virtual SessionPtr_t DialSession(const string& remoteAddr) final {
        return DialWithConfig(remoteAddr, nullptr);
    }

    SessionPtr_t DialWithConfig(const string& remoteAddr, shared_ptr<DialConfig_t> cfg=nullptr);

    shared_ptr<NCP::Session> newSession(const string& remoteAddr,
            const string& sessionID, const vector<string>& connIDs, shared_ptr<NCP::Config> cfg);

    void handleConn(shared_ptr<TCPConn_t> conn, const string& sessKey, int idx);

    boost::system::error_code handleMsg(shared_ptr<TCPConn_t> conn, SessionPtr_t sess, int idx);

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
        auto nonce = make_shared<Uint192>((char*)cipher, NONCESIZE, Uint192::FORMAT::BINARY);
        return SecretBox::Decrypt<basic_string,char>(cipher+NONCESIZE, len-NONCESIZE, shareKey, nonce);
    }

    static constexpr size_t NONCESIZE = 192/8;
};  // class TunaSessionClient

};  // namespace TUNA
};  // namespace NKN
#endif  // __NKN_TUNA_SESS_H__
