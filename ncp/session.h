#ifndef __NCP_SESSION_H__
#define __NCP_SESSION_H__

#include <chrono>
#include <memory>
#include <thread>
#include <string>
#include <vector>
#include <atomic>
#include <unordered_map>

#include <boost/system/error_code.hpp>

#include <safe_ptr.h>

#include "channel.h"
#include "byteslice.h"
#include "interface.h"
#include "client.h"
#include "config.h"
#include "pb/packet.pb.h"

namespace NKN {
    namespace TUNA {
        typedef class TunaSessionClient TunaCli_t;
        typedef shared_ptr<TunaCli_t> TunaCli_Ptr;
    };
    namespace NCP {
        using namespace std;

/****** Session ******/
        typedef class Connection Connection_t;
        typedef class Session Session_t;

        class Session : public std::enable_shared_from_this<Session>, public TUNA::Conn_t {
        public:
            friend class Connection;

            typedef chrono::time_point<chrono::steady_clock> time_point;

            typedef boost::system::error_code (*SendWithFunc)(const TUNA::TunaCli_Ptr tuna, const string &localID,
                                                              const string &remoteID,
                                                              shared_ptr<string> buf,
                                                              const chrono::milliseconds &writeTimeout);

            typedef shared_ptr<Connection_t> ConnectionPtr_t;
            template<typename K_t, typename V_t>
            using safe_map = sf::contfree_safe_ptr<unordered_map<K_t, V_t>>;

            Session() = default;

            Session(const Session_t &sess) = delete;

            Session_t &operator=(const Session_t &sess) = delete;

            Session(string localAddr, string remoteAddr,
                    const vector<string> &localCliIDs, const vector<string> &remoteCliIDs,
                    TUNA::TunaCli_Ptr tuna, SendWithFunc fn, shared_ptr<Config_t> cfg = nullptr);

            static inline shared_ptr<Session_t> NewSession(
                    const string &localAddr, const string &remoteAddr,
                    const vector<string> &localCliIDs, const vector<string> &remoteClientIDs,
                    TUNA::TunaCli_Ptr tuna, SendWithFunc fn, shared_ptr<Config_t> cfg = nullptr) {
                return make_shared<Session_t>(localAddr, remoteAddr, localCliIDs, remoteClientIDs, tuna, fn, cfg);
            }

            inline bool IsStream() { return !config->NonStream; }

            inline bool IsEstablished() { /* TODO Lock */ return isEstablished.load(); }

            inline bool IsClosed() { /* TODO Lock */ return isClosed.load(); }

            inline shared_ptr<string> GetDataToSend(uint32_t seq) { return (*sendWindowData)[seq]; }

            inline void updateBytesReadSentTime() { bytesReadSentTime.store(chrono::steady_clock::now()); }

            inline void SetLinger(uint32_t t) { config->Linger = t; }

            inline uint32_t GetConnWindowSize();

            inline uint64_t GetBytesRead() { /* TODO Lock */ return bytesRead.load(); }

            inline uint32_t RecvWindowUsed() { /* TODO Lock */ return recvWindowUsed.load(); }

            inline uint32_t SendWindowUsed() {
                /* TODO Lock */
                uint64_t wb = bytesWrite.load(), rb = remoteBytesRead.load();
                return wb > rb ? static_cast<uint32_t>(wb - rb) : 0;
            }

            inline uint32_t getResendSeq() {
                auto ret = resendChan->pop(true);
                return ret == nullptr ? 0 : *ret;
            }

            uint32_t getSendSeq() {
                while (!IsClosed()) {
                    auto resend = resendChan->pop(true);
                    if (resend)
                        return *resend;

                    auto send = sendChan.pop(true);
                    if (send)
                        return *send;

                    this_thread::sleep_for(chrono::milliseconds(10));
                }
                return 0;
            }

            /*** No corresponding API in C++ ***/
            // TODO SetDeadline();
            // TODO SetReadDeadline();
            // TODO SetWriteDeadline();
            /***********************************/

            boost::system::error_code
            ReceiveWith(const string &localID, const string &remoteID, const shared_ptr<string>& buf);

            uint32_t waitForSendWindow(uint32_t n);

            boost::system::error_code handleACKPkt(const shared_ptr<pb::Packet>& pkt);

            boost::system::error_code handleSeqPkt(const shared_ptr<pb::Packet>& pkt);

            boost::system::error_code handleClosePacket();

            boost::system::error_code handleHandshakePacket(const shared_ptr<pb::Packet>& pkt);

            boost::system::error_code sendClosePacket();

            boost::system::error_code sendHandshakePacket(chrono::milliseconds timeo);

            boost::system::error_code Dial(/*timeout*/);

            boost::system::error_code Accept();

            void start();

            void startFlush(uint32_t interval);

            boost::system::error_code flushSendBuffer();

            boost::system::error_code startCheckBytesRead();

            // NKN::Conn_t interface
            inline string LocalAddr() final { return localAddr; }

            inline string RemoteAddr() final { return remoteAddr; }

            size_t Read(byteSlice &, size_t) final;

            size_t Write(const byteSlice &) final;

            boost::system::error_code Close() final;

            shared_ptr<Config_t> config;

        private:
            size_t _recvAndUpdateSeq(uint32_t, string::iterator &);

            string localAddr;
            string remoteAddr;
            vector<string> localClientIDs;
            vector<string> remoteClientIDs;
            TUNA::TunaCli_Ptr tunaCli;
            SendWithFunc sendWith{};

            atomic<uint32_t> sendWindowSize{};
            atomic<uint32_t> recvWindowSize{};
            atomic<uint32_t> sendMtu{};
            atomic<uint32_t> recvMtu{};

            safe_map<string, ConnectionPtr_t> connections;
            Channel<bool> onAccept;
            Channel<uint32_t> sendChan;
            shared_ptr<Channel<uint32_t>> resendChan;
            Channel<bool> sendWindowUpdate;
            Channel<bool> recvDataUpdate;

            atomic_bool isAccepted{};
            atomic_bool isEstablished{};
            atomic_bool isClosed{};

            // TODO buff Lock
            shared_ptr<byteSlice> sendBuffer;
            atomic<uint32_t> sendWindowStartSeq{};
            atomic<uint32_t> sendWindowEndSeq{};
            atomic<uint32_t> recvWindowStartSeq{};
            atomic<uint32_t> recvWindowUsed{};
            safe_map<uint32_t, shared_ptr<string>> sendWindowData;
            safe_map<uint32_t, shared_ptr<string>> recvWindowData;

            atomic<uint64_t> bytesWrite{};
            atomic<uint64_t> bytesRead{};
            atomic<uint64_t> remoteBytesRead{};

            atomic<time_point> bytesReadSentTime{};
            atomic<time_point> bytesReadUpdateTime{};
        };  // class Session
    };  // namespace NCP
};  // namespace NKN

#endif  // __NCP_SESSION_H__
