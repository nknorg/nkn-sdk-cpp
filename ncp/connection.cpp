#include <iostream>
#include <memory>
#include <math.h>

#include <boost/asio.hpp>

#include "include/unique_ptr_backporting.h"

#include "pb/packet.pb.h"
#include "ncp/error.h"
#include "ncp/util.h"
#include "ncp/session.h"
#include "ncp/connection.h"

using namespace std;

namespace NKN {
namespace NCP {
Connection::Connection(const shared_ptr<Session_t> sess, const string& localCliID, const string& remoteCliID)
    : session(sess)
      , localClientID(localCliID)
      , remoteClientID(remoteCliID)
      , windowSize(sess->config->InitialConnectionWindowSize)
      , sendWindowUpdate(1)
      , timeSentSeq()
      , resentSeq()
      , sendAckQueue()
      , retransmissionTimeout(chrono::milliseconds(sess->config->InitialRetransmissionTimeout)) {}

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
        auto rtt = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - (*timeSentSeq)[seq]);
        auto delta = tanh(double(3*rtt.count() - retransmissionTimeout.count())/mil_sec/1000);

        retransmissionTimeout += chrono::milliseconds(long(100*delta));
        if (retransmissionTimeout.count() > session->config->MaxRetransmissionTimeout)
            retransmissionTimeout = chrono::milliseconds(session->config->MaxRetransmissionTimeout);
    }

    timeSentSeq->erase(seq);
    resentSeq->erase(seq);

    sendWindowUpdate.push(make_unique<bool>(true));
}

boost::system::error_code Connection::tx() {
    boost::system::error_code ec;
    uint32_t seq = 0;

    while (true) {
        if (seq == 0) {
            seq = session->getResendSeq();
        }

        if (seq == 0) {
            ec = waitForSendWindow(/*timeout*/);
            if (ec == ErrCode::ErrMaxWait)
                continue;
            if (ec)
                return ec;
            seq = session->getSendSeq();
        }

        auto data = session->GetDataToSend(seq);
        if (data->size() == 0) {
            // TODO Lock
            timeSentSeq->erase(seq);
            resentSeq->erase(seq);
            continue;
        }

        ec = session->sendWith(localClientID, remoteClientID, data, retransmissionTimeout);
        if (ec) {
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
    }
}

boost::system::error_code Connection::sendAck() {
    boost::system::error_code ec;
    boost::asio::io_context io;

    boost::asio::deadline_timer t(io);
    auto interval = boost::posix_time::milliseconds(session->config->SendAckInterval);
    while (true) {
        t.expires_from_now(interval, ec);
        t.wait(ec);

        if (SendAckQueueLen() == 0) {
            continue;
        }

        vector<uint32_t> ackStartSeqList;
        vector<uint32_t> ackSeqCountList;

        // TODO Lock
        while (sendAckQueue->size()>0 && (ackStartSeqList.size()<session->config->MaxAckSeqListSize)) {
            uint32_t ackSeqCount, ackStartSeq;
            ackStartSeq = sendAckQueue->top();
            sendAckQueue->pop();
            ackSeqCount = 1;
            while (sendAckQueue->size()>0 && sendAckQueue->top() == NextSeq(ackStartSeq, ackSeqCount)) {
                sendAckQueue->pop();
                ackSeqCount++;
            }

            ackStartSeqList.push_back(ackStartSeq);
            ackSeqCountList.push_back(ackSeqCount);
        }
        // TODO UnLock

        if (all_of(ackSeqCountList.cbegin(), ackSeqCountList.cend(), [](uint32_t n){return n==1;})) {
            ackSeqCountList.clear();
        }

        auto pktPtr = make_shared<pb::Packet>();
        for (auto it=ackStartSeqList.cbegin(); it<ackStartSeqList.cend(); it++) {
            pktPtr->add_ack_start_seq(*it);
        }
        for (auto it=ackSeqCountList.cbegin(); it<ackSeqCountList.cend(); it++) {
            pktPtr->add_ack_seq_count(*it);
        }
        pktPtr->set_bytes_read(session->GetBytesRead());
        auto raw = make_shared<string>(pktPtr->ByteSizeLong(), 0);
        pktPtr->SerializeToArray((void*)raw->data(), raw->length());

        auto err = session->sendWith(localClientID, remoteClientID, raw, retransmissionTimeout);
        if (err) {
            // TODO
            this_thread::sleep_for(chrono::seconds(1));
            continue;
        }
        session->updateBytesReadSentTime();
    }
}

boost::system::error_code Connection::checkTimeout() {
    boost::system::error_code ec;
    boost::asio::io_context io;

    boost::asio::deadline_timer t(io);
    auto interval = boost::posix_time::milliseconds(session->config->CheckTimeoutInterval);
    while (true) {
        t.expires_from_now(interval, ec);
        t.wait(ec);

        time_point threshold = chrono::steady_clock::now() - retransmissionTimeout;
        // TODO Lock
        for (auto it = timeSentSeq->begin(); it != timeSentSeq->end(); it++) {
            if (resentSeq->count(it->first) > 0) {   // resent already
                continue;
            }
            if (it->second < threshold) {   // expired already
                session->resendChan->push(make_unique<uint32_t>(it->first));
                windowSize = std::max(windowSize/2, session->config->MinConnectionWindowSize);
            }
        }
    }
    return ErrCode::Success;
}

boost::system::error_code Connection::waitForSendWindow(/*timeout*/) {
    auto ret = sendWindowUpdate.pop(true, chrono::milliseconds(1000));
    if (ret == nullptr) {   // timeout
        return ErrCode::ErrMaxWait;
    }
    return ErrCode::Success;
}
};  // namespace NCP
};  // namespace NKN
