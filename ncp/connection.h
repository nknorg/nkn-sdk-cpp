#ifndef __NCP_CONNECTION_H__
#define __NCP_CONNECTION_H__

#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <queue>
#include <unordered_map>

#include <boost/system/error_code.hpp>

#include <safe_ptr.h>

#include "include/channel.h"
#include "tuna/interface.h"

using namespace std;

namespace NKN {
    namespace NCP {

        typedef class Session Session_t;
        typedef class Connection Connection_t;

        class Connection {
            typedef chrono::time_point<chrono::steady_clock> time_point;
            template<typename K_t, typename V_t>
            using safe_map = sf::contfree_safe_ptr<unordered_map<K_t, V_t>>;

            template<typename T, typename = typename std::enable_if<std::is_integral<T>::value>::type>
            using safe_heap = sf::contfree_safe_ptr<priority_queue<T, vector<T>, greater<T>>>;

            friend class Session;

            shared_ptr<Session_t> session;
            string localClientID;
            string remoteClientID;
            uint32_t windowSize{};

            Channel<bool> sendWindowUpdate;
            // TODO RWMutex;

            safe_map<uint32_t, time_point> timeSentSeq;
            safe_map<uint32_t, bool> resentSeq;
            safe_heap<uint32_t> sendAckQueue;

            chrono::milliseconds retransmissionTimeout{};

        public:
            Connection() = default;

            // Connection(const Connection_t& conn) = default;
            // Connection_t& operator=(const Connection_t& conn) = default;
            Connection(const shared_ptr<Session_t>& sess, string localCliID, string remoteCliID);

            static shared_ptr<Connection_t>
            NewConnection(const shared_ptr<Session_t>& sess, const string &localID, const string &remoteID) {
                return make_shared<Connection_t>(sess, localID, remoteID);
            }

            inline uint32_t SendWindowUsed() { return timeSentSeq->size(); }

            inline void SendAck(uint32_t sequenceID) { /* TODO Lock */ sendAckQueue->push(sequenceID); }

            inline int SendAckQueueLen() { /* TODO Lock */ return int(sendAckQueue->size()); }

            void ReceiveAck(uint32_t seq, bool isSentByMe);

            inline chrono::milliseconds &RetransmissionTimeout() { /* TODO Lock*/ return retransmissionTimeout; }

            boost::system::error_code waitForSendWindow(const chrono::milliseconds& timeo);

            void Start() {
                auto *thrdTx = new std::thread([this] { tx(); });
                auto *thrdSendAck = new std::thread([this] { sendAck(); });
                auto *thrdCheckTimeout = new std::thread([this] { checkTimeout(); });

                thrdTx->detach();
                thrdSendAck->detach();
                thrdCheckTimeout->detach();
            }

            boost::system::error_code tx();

            boost::system::error_code sendAck();

            boost::system::error_code checkTimeout();
        };  // class Connection
    }  // namespace NCP
}  // namespace NKN
#endif  // __NCP_CONNECTION_H__
