#include <chrono>
#include <iostream>
#include <memory>
#include <cmath>

#include <boost/asio.hpp>
#include <thread>

#include <spdlog/spdlog.h>

#include "pb/packet.pb.h"
#include "error.h"
#include "util.h"
#include "session.h"
#include "connection.h"

using namespace std;

namespace NKN {
    namespace NCP {
        Connection::Connection(const shared_ptr<Session_t>& sess, string localCliID, string remoteCliID)
                : session(sess), localClientID(std::move(localCliID)), remoteClientID(std::move(remoteCliID)),
                  windowSize(sess->config->InitialConnectionWindowSize), sendWindowUpdate(1), timeSentSeq(),
                  resentSeq(), sendAckQueue(),
                  retransmissionTimeout(chrono::milliseconds(sess->config->InitialRetransmissionTimeout)) {}

        void Connection::ReceiveAck(uint32_t seq, bool isSentByMe) {
            // TODO Lock
            if (timeSentSeq->count(seq) == 0) {
                return;
            }

            // increase windowSize if success without resent
            if (resentSeq->count(seq) == 0) {
                windowSize = min(++windowSize, session->config->MaxConnectionWindowSize);
            }

            if (isSentByMe) {
                auto mil_sec = chrono::milliseconds(1).count();
                auto rtt = chrono::duration_cast<chrono::milliseconds>(
                        chrono::steady_clock::now() - (*timeSentSeq)[seq]);
                auto delta = tanh(double(3 * rtt.count() - retransmissionTimeout.count()) / mil_sec / 1000);

                retransmissionTimeout += chrono::milliseconds(long(100 * delta));
                if (retransmissionTimeout.count() > session->config->MaxRetransmissionTimeout)
                    retransmissionTimeout = chrono::milliseconds(session->config->MaxRetransmissionTimeout);
            }

            timeSentSeq->erase(seq);
            resentSeq->erase(seq);

            sendWindowUpdate.push(make_unique<bool>(true), true);
        }

        boost::system::error_code Connection::tx() {
            boost::system::error_code ec;
            uint32_t seq = 0;

            while (true) {
                if (seq == 0) {
                    seq = session->getResendSeq();
                    // spdlog::info("Connection[{}-{}]::tx():{} getResendSeq == {}", localClientID, remoteClientID, __LINE__, seq);
                }

                if (seq == 0) {
                    ec = waitForSendWindow(chrono::milliseconds(1000));
                    // spdlog::info("Connection[{}-{}]::tx():{} waitForSendWindow got err: {}:{}",
                            // localClientID, remoteClientID, __LINE__, ec.message(), ec.value());
                    if (ec == ErrCode::ErrMaxWait)
                        continue;
                    if (ec) {
                        return ec;
                    }
                    seq = session->getSendSeq();
                    spdlog::info("Connection[{}-{}]::tx():{} getSendSeq == {}", localClientID, remoteClientID, __LINE__, seq);
                }

                auto data = session->GetDataToSend(seq);
                if (data->size() == 0) {
                    // TODO Lock
                    timeSentSeq->erase(seq);
                    resentSeq->erase(seq);
                    spdlog::info("Connection[{}-{}]::tx():{} GetDataToSend got 0 data with seq:{}", localClientID, remoteClientID, __LINE__, seq);
                    continue;
                }

                ec = session->sendWith(localClientID, remoteClientID, data, retransmissionTimeout);
                if (ec) {
                    spdlog::info("Connection[{}-{}]::tx():{} sendWith got err {}:{}",
                            localClientID, remoteClientID, __LINE__, ec.message(), ec.value());
                    if (session->IsClosed())
                        return ErrCode::ErrSessionClosed;
                    if (ec == ErrCode::ErrConnClosed)
                        return ec;

                    // TODO log ec
                    session->resendChan->push(make_unique<uint32_t>(seq));
                    this_thread::sleep_for(chrono::seconds(1));
                    continue;
                }

                // sendWith success
                // TODO Lock
                if (timeSentSeq->count(seq) == 0)
                    (*timeSentSeq)[seq] = chrono::steady_clock::now();
                resentSeq->erase(seq);
                // TODO UnLock
                seq = 0;

                // spdlog::info("Connection[{}-{}]::tx():{} reached loop ending", localClientID, remoteClientID, __LINE__);
            }
        }

        boost::system::error_code Connection::sendAck() {
            boost::system::error_code ec;
            boost::asio::io_context io;

            boost::asio::deadline_timer t(io);
            auto interval = boost::posix_time::milliseconds(session->config->SendAckInterval);
            while (!session->IsClosed()) {
                t.expires_from_now(interval, ec);
                t.wait(ec);

                // spdlog::info("sendAck({}-{}):{} SendAckQueueLen:{}",
                        // localClientID, remoteClientID, __LINE__, SendAckQueueLen());
                if (SendAckQueueLen() == 0) {
                    interval = boost::posix_time::milliseconds(1000);
                    continue;
                }
                interval = boost::posix_time::milliseconds(session->config->SendAckInterval);

                vector<uint32_t> ackStartSeqList;
                vector<uint32_t> ackSeqCountList;

                // TODO Lock
                while (sendAckQueue->size() > 0 && (ackStartSeqList.size() < session->config->MaxAckSeqListSize)) {
                    uint32_t ackSeqCount, ackStartSeq;
                    ackStartSeq = sendAckQueue->top();
                    sendAckQueue->pop();
                    ackSeqCount = 1;
                    while (sendAckQueue->size() > 0 && sendAckQueue->top() == NextSeq(ackStartSeq, ackSeqCount)) {
                        sendAckQueue->pop();
                        ackSeqCount++;
                    }

                    ackStartSeqList.push_back(ackStartSeq);
                    ackSeqCountList.push_back(ackSeqCount);

                    spdlog::info("sendAck({}-{}):{} ackStartSeq:{} ackSeqCount:{}",
                            localClientID, remoteClientID, __LINE__, ackStartSeq, ackSeqCount);
                }
                // TODO UnLock

                if (all_of(ackSeqCountList.cbegin(), ackSeqCountList.cend(), [](uint32_t n) { return n == 1; })) {
                    ackSeqCountList.clear();
                }

                auto pktPtr = make_shared<pb::Packet>();
                for (auto it = ackStartSeqList.cbegin(); it < ackStartSeqList.cend(); it++) {
                    pktPtr->add_ack_start_seq(*it);
                }
                for (auto it = ackSeqCountList.cbegin(); it < ackSeqCountList.cend(); it++) {
                    pktPtr->add_ack_seq_count(*it);
                }
                pktPtr->set_bytes_read(session->GetBytesRead());
                auto raw = make_shared<string>(pktPtr->ByteSizeLong(), 0);
                pktPtr->SerializeToArray((void *) raw->data(), raw->length());

                auto err = session->sendWith(localClientID, remoteClientID, raw,
                                             retransmissionTimeout);
                spdlog::info("sendAck({}-{}):{} sendWith result {}:{}",
                        localClientID, remoteClientID, __LINE__, err.message(), err.value());
                if (err) {
                    if (err == ErrCode::ErrConnClosed) {
                        return err;
                    }
                    this_thread::sleep_for(chrono::seconds(1));
                    continue;
                }
                session->updateBytesReadSentTime();
            }
            spdlog::warn("sendAck({}-{}):{} thread terminal", localClientID, remoteClientID, __LINE__);
            return ErrCode::ErrConnClosed;
        }

        boost::system::error_code Connection::checkTimeout() {
            boost::system::error_code ec;
            boost::asio::io_context io;

            boost::asio::deadline_timer t(io);
            auto interval = boost::posix_time::milliseconds(session->config->CheckTimeoutInterval);
            while (true) {
                t.expires_from_now(interval, ec);
                t.wait(ec);

                if (session->IsClosed()) {
                    return ErrCode::ErrSessionClosed;
                }

                time_point threshold = chrono::steady_clock::now() - retransmissionTimeout;
                // TODO Lock
                for (auto it = timeSentSeq->begin(); it != timeSentSeq->end(); it++) {
                    if (resentSeq->count(it->first) > 0) {   // resent already
                        continue;
                    }
                    if (it->second < threshold) {   // expired already
                        session->resendChan->push(make_unique<uint32_t>(it->first));
                        windowSize = std::max(windowSize / 2, session->config->MinConnectionWindowSize);
                    }
                }
            }
            return ErrCode::Success;
        }

        boost::system::error_code Connection::waitForSendWindow(const chrono::milliseconds& timeo) {
            if (SendWindowUsed() >= this->windowSize) {
                auto ret = sendWindowUpdate.pop(false, timeo);
                if (ret == nullptr) {   // timeout
                    return ErrCode::ErrMaxWait;
                }

                if (this->session->IsClosed()) {
                    return ErrCode::ErrSessionClosed;
                }
                // this_thread::sleep_for(milliseconds(100));
            }
            return ErrCode::Success;
        }
    };  // namespace NCP
};  // namespace NKN
