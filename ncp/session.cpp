#include <chrono>
#include <memory>
#include <thread>

#include <spdlog/spdlog.h>
#include <boost/asio.hpp>
#include <utility>
#include <pplx/pplxtasks.h>
#include <byteslice.h>

#include "util.h"
#include "error.h"
#include "session.h"
#include "connection.h"

namespace NKN {
    namespace NCP {
        using namespace std;

        Session::Session(const string& localAddr, const string& remoteAddr,
                         const vector<string> &localCliIDs, const vector<string> &remoteCliIDs,
                         TUNA::TunaCli_Ptr tuna, SendWithFunc fn, shared_ptr<Config_t> cfg)
                : config(Config::MergeDefaultConfig(std::move(cfg))),
                  localAddr(std::move(localAddr)),
                  remoteAddr(std::move(remoteAddr)),
                  localClientIDs(localCliIDs),
                  remoteClientIDs(remoteCliIDs),
                  tunaCli(std::move(std::move(tuna))),
                  sendWith(fn),
                  sendWindowSize(config->SessionWindowSize),
                  recvWindowSize(config->SessionWindowSize),
                  sendMtu(config->MTU), recvMtu(config->MTU),
                  onAccept(1),
                  sendChan(1),
                  resendChan(nullptr), isAccepted(false),
                  isEstablished(false),
                  isClosed(false),
                  sendBuffer(nullptr),
                  sendWindowStartSeq(MinSequenceID),
                  sendWindowEndSeq(MinSequenceID),
                  recvWindowStartSeq(MinSequenceID),
                  recvWindowUsed(0),
                  bytesWrite(0),
                  bytesRead(0),
                  remoteBytesRead(0),
                  bytesReadSentTime(chrono::steady_clock::now()),
                  bytesReadUpdateTime(chrono::steady_clock::now()) {
            sendBuffer = make_shared<byteSlice>(sendMtu.load(), 0);
            sendBuffer->resize(0);
        }

        inline uint32_t Session::GetConnWindowSize() {
            uint32_t ret = 0;
            for (auto it = connections->cbegin(); it != connections->cend(); it++) {
                ret += it->second->windowSize;
            }
            return ret;
        }

        boost::system::error_code
        Session::ReceiveWith(const string &localID, const string &remoteID, const shared_ptr<string> &buf) {
            // spdlog::error("Session::ReceiveWith received buff from Conn[{}-{}]", localID, remoteID);
            // cerr << "Session::ReceiveWith received buff from Conn[" << localID << ":" << remoteID << "]\n";
            if (IsClosed()) {
                return ErrCode::ErrConnClosed;
            }

            auto pktPtr = make_shared<pb::Packet>();
            if (!pktPtr->ParseFromArray(buf->data(), buf->size())) {  // parse pb failed
                return ErrCode::ErrInvalidPacket;
            }

            if (pktPtr->close()) {
                return handleClosePacket();
            }

            bool isEst = IsEstablished();
            if (!isEst && pktPtr->handshake()) {
                return handleHandshakePacket(pktPtr);
            }

            auto ack_start_seq_len = pktPtr->ack_start_seq_size();
            auto ack_seq_count_len = pktPtr->ack_seq_count_size();

            // is ACK packet
            if (isEst && (ack_start_seq_len > 0 || ack_seq_count_len > 0)) {
                spdlog::info("Session::ReceiveWith received ACK[{}, {}] packet from Conn[{}-{}]",
                        ack_start_seq_len, ack_seq_count_len, localID, remoteID);
                auto err = handleACKPkt(localID, remoteID, pktPtr);
                if (err)
                    return err;
            }

            // is BytesRead packet
            if (isEst && pktPtr->bytes_read() > remoteBytesRead) {
                spdlog::info("Session::ReceiveWith received BytesRead[{}] packet from Conn[{}-{}]",
                        pktPtr->bytes_read(), localID, remoteID);
                remoteBytesRead = pktPtr->bytes_read();
                sendWindowUpdate.push(make_unique<bool>(true), true);
            }

            // is seq packet
            if (isEst && pktPtr->sequence_id() > 0) {
                spdlog::info("Session::ReceiveWith received Seq[{}] packet from Conn[{}-{}]",
                        pktPtr->sequence_id(), localID, remoteID);
                auto err = handleSeqPkt(localID, remoteID, pktPtr);
                if (err)
                    return err;
            }

            // spdlog::info("Session::ReceiveWith reached Ending");
            return ErrCode::Success;
        }

        boost::system::error_code Session::handleACKPkt(
                const string& localID, const string& remoteID, const shared_ptr<pb::Packet> &pkt) {
            auto ack_start_seq_len = pkt->ack_start_seq_size();
            auto ack_seq_count_len = pkt->ack_seq_count_size();

            if (ack_start_seq_len > 0 && ack_seq_count_len > 0 && ack_start_seq_len != ack_seq_count_len) {
                return ErrCode::ErrInvalidPacket;
            }

            /* uint32_t count = 0;
            if (ack_start_seq_len > 0)
                count = ack_start_seq_len;
            if (ack_seq_count_len > 0)
                count = ack_seq_count_len; */
            uint32_t count = ack_seq_count_len>0 ? ack_seq_count_len
                                                : ack_start_seq_len>0 ? ack_start_seq_len
                                                : 0;

            uint32_t ackStartSeq=0, ackEndSeq=0;
            for (uint32_t i=0; i<count; i++) {
                /* if (ack_start_seq_len > 0)
                    ackStartSeq = pkt->ack_start_seq(i);
                else
                    ackStartSeq = MinSequenceID;

                if (ack_seq_count_len > 0)
                    ackEndSeq = NextSeq(ackStartSeq, pkt->ack_seq_count(i));
                else
                    ackEndSeq = NextSeq(ackStartSeq, 1); */

                ackStartSeq = ack_start_seq_len>0 ? pkt->ack_start_seq(i) : MinSequenceID;
                ackEndSeq = NextSeq(ackStartSeq, ack_seq_count_len>0 ? pkt->ack_seq_count(i) : 1);

                if (SeqInBetween(sendWindowStartSeq, sendWindowEndSeq, NextSeq(ackEndSeq, -1))) {
                    if (!SeqInBetween(sendWindowStartSeq, sendWindowEndSeq, ackStartSeq)) {
                        ackStartSeq = sendWindowStartSeq;
                    }
                    for (uint32_t seq=ackStartSeq; SeqInBetween(ackStartSeq, ackEndSeq, seq); seq=NextSeq(seq, 1)) {
                        for (auto it=connections->cbegin(); it != connections->cend(); it++) {
                            it->second->ReceiveAck(seq, it->first == connKey(localID, remoteID));
                        }
                        sendWindowData->erase(seq);
                    }
                    if (ackStartSeq == sendWindowStartSeq) {
                        while (sendWindowStartSeq != sendWindowEndSeq) {
                            sendWindowStartSeq = NextSeq(sendWindowStartSeq, 1);
                            if (sendWindowData->count(sendWindowStartSeq)) {
                                break;
                            }
                        }
                    }
                }
            }

            return ErrCode::Success;
        }

        boost::system::error_code Session::handleSeqPkt(
                const string& localID, const string& remoteID, const shared_ptr<pb::Packet> &pkt) {
            const string &data = pkt->data();
            if (data.length() > recvMtu) {
                spdlog::info("Session::handleSeqPkt() invalid data len {}", data.length());
                return ErrCode::ErrDataSizeTooLarge;
            }

            uint32_t seq = pkt->sequence_id();
            spdlog::info("Session::handleSeqPkt({}), recvWinStart: {}", seq, recvWindowStartSeq);
            if (CompareSeq(seq, recvWindowStartSeq) >= 0) {
                if (recvWindowData->count(seq) == 0) {  // not received seq yet
                    if (recvWindowUsed + data.length() > recvWindowSize) {
                        return ErrCode::ErrRecvWindowFull;
                    }

                    spdlog::info("Session::handleSeqPkt({}) update recv data & {} bytes WindowUsed", seq, data.length());
                    (*recvWindowData)[seq] = make_shared<string>(data);
                    recvWindowUsed += (uint32_t) data.length();

                    if (seq == recvWindowStartSeq) {
                        recvDataUpdate.push(make_unique<bool>(true), true);
                    }
                }
            }

            auto key = connKey(localID, remoteID);
            if (connections->count(key) > 0) {
                (*connections)[key]->SendAck(seq);
            }

            // spdlog::info("Session::handleSeqPkt({}) reached success Ending", seq);
            return ErrCode::Success;
        }

        boost::system::error_code Session::handleHandshakePacket(const shared_ptr<pb::Packet> &pkt) {
            spdlog::error("Session::handleHandshakePacket received a handshake packet");
            // cerr << "Session::handleHandshakePacket received a handshake packet\n";
            if (isEstablished) {
                return ErrCode::Success;
            }

            if (pkt->window_size() == 0 || pkt->mtu() == 0 || pkt->client_ids_size() == 0) {
                return ErrCode::ErrInvalidPacket;
            }

            sendWindowSize = std::min(pkt->window_size(), sendWindowSize.load());
            sendMtu = std::min(pkt->mtu(), sendMtu.load());

            size_t conn_cnt = std::min((size_t) pkt->client_ids_size(), localClientIDs.size());

            remoteClientIDs.resize(conn_cnt);
            for (size_t i = 0; i < conn_cnt; i++) {
                auto conn_ptr = Connection::NewConnection(shared_from_this(), localClientIDs[i], pkt->client_ids(i));
                if (conn_ptr) {
                    (*connections)[connKey(conn_ptr->localClientID, conn_ptr->remoteClientID)] = conn_ptr;
                    remoteClientIDs[i] = conn_ptr->remoteClientID;
                    // log
                }
            }

            resendChan = make_shared<Channel<uint32_t>>(config->MaxConnectionWindowSize * conn_cnt);
            sendBuffer = make_shared<byteSlice>(sendMtu.load(), 0);
            sendBuffer->resize(0);
            isEstablished = true;

            onAccept.push(make_unique<bool>(true), true);   // handshake completed notify
            return ErrCode::Success;
        }

        boost::system::error_code Session::sendClosePacket() {
            if (!IsEstablished()) {
                return ErrCode::ErrSessionEstablished;
            }

            auto pktPtr = make_shared<pb::Packet>();
            pktPtr->set_close(true);

            auto serialized = make_shared<string>(pktPtr->ByteSizeLong(), 0);
            pktPtr->SerializeToArray((void *) serialized->data(), serialized->length());

            atomic<uint32_t> err_cnt(0);
            auto cnt = connections->size();
            pplx::task_completion_event<boost::system::error_code> send_tce;
            for (auto it = connections->cbegin(); it != connections->cend(); it++) {
                ConnectionPtr_t conn = it->second;
                pplx::create_task(
                        std::bind(this->sendWith, conn->localClientID, conn->remoteClientID, serialized,
                                  conn->RetransmissionTimeout())
                ).then([&err_cnt, &send_tce, cnt](const boost::system::error_code &err) {
                    if (err) {
                        err_cnt++;
                        if (err_cnt == cnt) {
                            send_tce.set(err);
                        }
                    } else {
                        send_tce.set(ErrCode::Success);
                    }
                });
            }

            // TODO deadline send_tce.set(timeout)
            return pplx::create_task(send_tce).get();
        }

        boost::system::error_code Session::handleClosePacket() {
            spdlog::error("{}:{} Recv a close Packet", __PRETTY_FUNCTION__, __LINE__);
            isClosed.store(true);
            // TODO Wait join threads
            return ErrCode::Success;
        }

        boost::system::error_code Session::sendHandshakePacket(chrono::milliseconds timeo) {
            auto pktPtr = make_shared<pb::Packet>();
            pktPtr->set_handshake(true);
            for (auto id = localClientIDs.begin(); id != localClientIDs.end(); id++) {
                pktPtr->add_client_ids(*id);
            }
            pktPtr->set_window_size(recvWindowSize.load());
            pktPtr->set_mtu(recvMtu.load());

            auto raw = make_shared<string>(pktPtr->ByteSizeLong(), 0);
            pktPtr->SerializeToArray((void *) raw->data(), raw->length());

            atomic<uint32_t> err_cnt(0);
            pplx::task_completion_event<boost::system::error_code> send_tce;
            vector<pplx::task<boost::system::error_code>> thrd_grp;
            if (auto cnt = connections->size() > 0) {
                for (auto it = connections->cbegin(); it != connections->cend(); it++) {
                    ConnectionPtr_t conn = it->second;
                    thrd_grp.emplace_back(pplx::create_task(
                            std::bind(sendWith, conn->localClientID, conn->remoteClientID, raw, timeo)
                    ).then([&err_cnt, &send_tce, cnt](const boost::system::error_code &err) {
                        if (err) {
                            err_cnt++;
                            if (err_cnt == cnt) {
                                send_tce.set(err);
                            }
                        } else {
                            send_tce.set(ErrCode::Success);
                        }
                        return err;
                    }));
                }
            } else {
                size_t remoteID_cnt = remoteClientIDs.size();
                auto all = localClientIDs.size();
                for (size_t idx = 0; idx < localClientIDs.size(); idx++) {
                    string localID = localClientIDs[idx];
                    string remoteID = remoteID_cnt > 0 ? remoteClientIDs[idx % remoteID_cnt] : localID;
                    thrd_grp.emplace_back(pplx::create_task(
                            std::bind(sendWith, localID, remoteID, raw, timeo)
                    ).then([&err_cnt, &send_tce, all, localID, remoteID](const boost::system::error_code &err) {
                        spdlog::error("****** sendHandshakePacket {}-{} result: {}:{}\n", localID, remoteID, err.message(), err.value());
                        // cerr << "****** sendHandshakePacket " << localID << " to " << remoteID << " result: " << err.message() << ":" << err.value() << endl;
                        if (err) {
                            err_cnt++;
                            if (err_cnt == all) {
                                send_tce.set(err);
                            }
                        } else {
                            send_tce.set(ErrCode::Success);
                        }
                        return err;
                    }));
                }
            }

            for (auto& tsk: thrd_grp) {
                tsk.get();
            }
            // TODO deadline send_tce.set(timeout)
            return pplx::create_task(send_tce).get();
        }

        boost::system::error_code Session::Dial(/*timeout*/) {
            // TODO Lock acceptLock
            if (isAccepted) {
                return ErrCode::ErrSessionEstablished;
            }
            isClosed = false;

            auto err = sendHandshakePacket(chrono::milliseconds(config->InitialRetransmissionTimeout));
            if (err)
                return err;

            auto accepted = onAccept.pop(false, milliseconds(10000)/*timeout*/);
            if (accepted == nullptr) {  // timeout
                return ErrCode::ErrMaxWait;
            }

            start();
            isAccepted = true;
            return ErrCode::Success;
        }

        uint32_t Session::waitForSendWindow(uint32_t n) {
            // spdlog::info("waitForSendWindow({}):{} current winUsed:{}, sess state: {}", n, __LINE__, SendWindowUsed(), IsClosed()?"closed":"opening");
            while (SendWindowUsed() + n > sendWindowSize) { // check until SendWindowUsed()+n < sendWindowSize
                auto c = sendWindowUpdate.pop(false, chrono::milliseconds(1000));
                if (IsClosed()) {
                    return 0;
                }
            }
            // spdlog::info("waitForSendWindow({}):{} return {} - {}", n, __LINE__, sendWindowSize, SendWindowUsed());
            return sendWindowSize - SendWindowUsed();
        }

        boost::system::error_code Session::flushSendBuffer() {
            // TODO Lock
            // spdlog::info("flushSendBuffer():{} {} bytes from buff[{}]", __LINE__, sendBuffer->length(), (void*)sendBuffer.get());

            if (sendBuffer->length() <= 0) {
                return ErrCode::Success;
            }

            // alloc new buf and swap out the previous buf
            shared_ptr<byteSlice> buf = make_shared<byteSlice>(sendMtu.load(), 0);
            buf->resize(0);
            std::swap(buf, sendBuffer);

            uint32_t seq = sendWindowEndSeq;

            // construct a pb::Packet obj with old buf
            auto pktPtr = make_shared<pb::Packet>();
            pktPtr->set_sequence_id(seq);
            pktPtr->set_data(*buf);

            // Serialized pb obj to a shared_ptr<string>
            auto serialized = make_shared<string>(pktPtr->ByteSizeLong(), 0);
            pktPtr->SerializeToArray((void *) serialized->data(), serialized->length());

            (*sendWindowData)[seq] = serialized;
            sendWindowEndSeq = NextSeq(seq, 1);

            // notify seq
            while (true) {
                auto ok = sendChan.push(make_unique<uint32_t>(seq), false, chrono::milliseconds(1000));
                if (ok) {
                    break;
                }else{
                    spdlog::warn("{}:{} push seq:{} to sendChan timeout", __FILE__, __LINE__, seq);
                }

                if (IsClosed())
                    return ErrCode::ErrSessionClosed;
            }
            spdlog::info("{}:{} push seq:{} to sendChan success", __FILE__, __LINE__, seq);
            return ErrCode::Success;
        }

        void Session::startFlush(uint32_t interval) {
            while (!IsClosed()) {
                this_thread::sleep_for(chrono::milliseconds(interval));

                // TODO Lock
                if (sendBuffer->length() <= 0) {
                    continue;
                }

                auto err = flushSendBuffer();
                if (err) {
                    spdlog::error("{}:{} met error: {}:{}", __PRETTY_FUNCTION__, __LINE__, err.message(), err.value());
                }
            }
        }

        void Session::start() {
            auto *thrdFlush = new std::thread([this, capture0 = config->FlushInterval] { startFlush(capture0); });
            thrdFlush->detach();

            auto *thrdCheckRead = new std::thread([this] { startCheckBytesRead(); });
            thrdCheckRead->detach();

            for (auto it = connections->cbegin(); it != connections->cend(); it++) {
                const ConnectionPtr_t &conn = it->second;
                conn->Start();
            }
        }

        boost::system::error_code Session::startCheckBytesRead() {
            boost::system::error_code ec;
            boost::asio::io_context io;

            boost::asio::deadline_timer t(io);
            auto interval = chrono::milliseconds(config->CheckBytesReadInterval);

            while (!IsClosed()) {
                this_thread::sleep_for(interval);

                // TODO Lock
                time_point sentTime(bytesReadSentTime);
                time_point updateTime(bytesReadUpdateTime);
                uint64_t bRead = bytesRead;

                if (bRead == 0 || sentTime > updateTime ||
                    chrono::steady_clock::now() - updateTime < chrono::milliseconds(config->SendBytesReadThreshold)) {
                    continue;
                }

                auto pktPtr = make_shared<pb::Packet>();
                pktPtr->set_bytes_read(bRead);

                auto raw = make_shared<string>(pktPtr->ByteSizeLong(), 0);
                pktPtr->SerializeToArray((void *) raw->data(), raw->length());

                // Send pb raw concurrence via all connections
                pplx::task_completion_event<boost::system::error_code> send_tce;
                auto cnt = connections->size();
                atomic<uint32_t> err_cnt(0);
                for (auto it = connections->cbegin(); it != connections->cend(); it++) {
                    ConnectionPtr_t conn = it->second;
                    pplx::create_task(
                            std::bind(this->sendWith, conn->localClientID, conn->remoteClientID, raw,
                                      conn->RetransmissionTimeout())
                    ).then([&err_cnt, &send_tce, cnt](const boost::system::error_code &err) {
                        if (err) {
                            err_cnt++;
                            if (err_cnt == cnt) {   // all failed
                                send_tce.set(err);
                            }
                        } else {    // any one success
                            send_tce.set(ErrCode::Success);
                        }
                    });
                }

                auto err = pplx::create_task(send_tce).get();
                if (err == ErrCode::Success) {
                    updateBytesReadSentTime();
                }
            }
            return ErrCode::ErrSessionClosed;
        }

        boost::system::error_code Session::Accept() {
            if (isAccepted) {
                return ErrCode::ErrSessionEstablished;
            }

            auto on = onAccept.pop(true);
            if (on == nullptr) {
                return ErrCode::ErrNotHandshake;
            }

            start();
            isAccepted = true;

            return sendHandshakePacket(chrono::milliseconds(config->InitialRetransmissionTimeout));
        }

        size_t Session::Write(const byteSlice &data) {
            if (IsClosed()) {
                spdlog::error("{}:{} Session[{}] had closed.", __PRETTY_FUNCTION__, __LINE__, this->remoteAddr);
                // log ErrCode::ErrSessionClosed
                return 0;
            }

            if (!IsEstablished()) {
                // log ErrCode::ErrSessionNotEstablished
                spdlog::error("Session[{}] has not established yet.", this->remoteAddr);
                return 0;
            }

            spdlog::info("write {} bytes to {} mode Session[{}]", data.length(), IsStream()?"stream":"non-stream", this->remoteAddr);
            uint32_t len = data.length();
            if (len == 0) {
                return 0;
            }

            if (!IsStream() && (len > sendMtu.load() || len > sendWindowSize.load())) {
                // log ErrCode::ErrDataSizeTooLarge
                spdlog::error("Session[{}] met DataSizeTooLarge error", this->remoteAddr);
                return 0;
            }

            uint32_t cnt = 0, sent = 0;
            auto src_ptr = data.data();
            auto end_ptr = src_ptr + data.length();
            if (IsStream()) {
                while (src_ptr < end_ptr) {
                    // spdlog::info("{}:{} sess[{}] Waiting SendWindow for write data from {} to {} ...",
                            // __PRETTY_FUNCTION__, __LINE__, this->remoteAddr, (void*)src_ptr, (void*)end_ptr);
                    auto sendWindowAvailable = waitForSendWindow(1);
                    if (IsClosed()) {   // if closed during wait
                        // log ErrCode::ErrSessionClosed
                        spdlog::error("{}:{} Session[{}] had closed.", __PRETTY_FUNCTION__, __LINE__, this->remoteAddr);
                        return 0;
                    }

                    if (sendWindowAvailable == 0) {
                        this_thread::sleep_for(milliseconds(1000));
                    }

                    uint32_t cnt = std::min(uint32_t(end_ptr - src_ptr), sendWindowAvailable);
                    uint32_t buf_remaining = sendMtu.load() - sendBuffer->length();

                    bool shouldFlush = sendWindowAvailable == sendWindowSize.load();
                    if (cnt >= buf_remaining) {
                        cnt = buf_remaining;
                        shouldFlush = true;
                    }
                    sendBuffer->append(src_ptr, cnt);
                    bytesWrite += cnt;
                    sent += cnt;
                    // spdlog::info("Appended {} bytes to sendBuff. sent:{}, bytesWrite:{}", cnt, sent, bytesWrite);

                    if (shouldFlush) {
                        auto err = flushSendBuffer();
                        if (err) {
                            // log err
                            return sent;
                        }
                    }
                    src_ptr += cnt;
                    // spdlog::info("{}:{} flushSendBuffer finished. src_ptr:{}, end_ptr:{}", __FILE__, __LINE__, (void*)src_ptr, (void*)end_ptr);
                }
            } else {
                // TODO for non-stream mode
            }

            // spdlog::info("Session::Write reach ending.");
            return sent;
        }

        size_t Session::Read(byteSlice &buf, size_t) {
            // spdlog::info("sess->Read():{} Entry, buf size:{}, cap:{}", __LINE__, buf.length(), buf.capacity());

            if (IsClosed()) {    // if closed during channel waiting
                // log ErrCode::ErrSessionClosed
                spdlog::error("{}:{} Session[{}] had closed.", __PRETTY_FUNCTION__, __LINE__, this->remoteAddr);
                return 0;
            }

            if (!IsEstablished()) {
                // log ErrCode::ErrSessionNotEstablished
                spdlog::error("Session[{}] has not established yet.", this->remoteAddr);
                return 0;
            }

            size_t wanted = buf.capacity();
            if (wanted == 0) {
                return 0;
            }

            // spdlog::info("sess->Read():{} Entry, wanted {} bytes", __LINE__, wanted);

            uint32_t recv_seq = 0;
            while (true) {
                if (IsClosed()) {    // if closed during channel waiting
                    // log ErrCode::ErrSessionClosed
                    return 0;
                }

                recv_seq = recvWindowStartSeq;
                if (recvWindowData->count(recv_seq) > 0) {  // if seq has ready
                    spdlog::warn("Session::Read():{} seq {} data arrived, continue...", __LINE__, recv_seq);
                    break;
                }
                // spdlog::warn("sess->Read():{} recvWindowData[{}] count:{}. Waiting for recvDataUpdate",
                        // __LINE__, recv_seq, recvWindowData->count(recv_seq));
                recvDataUpdate.pop(false, chrono::milliseconds(1000));  // wait on channel
            }

            if (!IsStream() &&
                wanted < recvWindowData->at(recv_seq)->size()) { // Not support partial read in non-stream mode
                // log ErrCode::ErrBufferSizeTooSmall
                return 0;
            }

            auto pos = buf.begin();
            auto read_cnt = _recvAndUpdateSeq(recv_seq, pos);
            assert(read_cnt <= wanted);

            /* auto remain = wanted - read_cnt;
            if (IsStream()) {
                while (remain != 0) {    // prev data->size < wanted, read continue from next seq
                    recv_seq = recvWindowStartSeq;
                    if (recvWindowData->count(recv_seq) < 1) {  // if next seq not ready, give up append buf.
                        break;
                    }

                    auto cnt = _recvAndUpdateSeq(recv_seq, pos);
                    assert(cnt <= remain);
                    remain -= cnt;
                    read_cnt += cnt;
                }
            } */

            return read_cnt;
        }

        size_t Session::_recvAndUpdateSeq(uint32_t seq, string::iterator &output_pos) {
            if (recvWindowData->count(seq) <= 0) {  // if map[seq] not exist
                spdlog::error("_recvAndUpdateSeq({}):{} data not ready", seq, __LINE__);
                return 0;
            }

            auto data = (*recvWindowData)[seq];
            auto new_pos = std::copy(data->cbegin(), data->cend(), output_pos);
            int read_cnt = new_pos - output_pos;
            assert(read_cnt >= 0);
            // spdlog::warn("_recvAndUpdateSeq:{} copied {}/{} data to buff", __LINE__, read_cnt, data->size());

            if ((size_t) read_cnt == data->size()) { // all data was copied
                recvWindowData->erase(seq);
                recvWindowStartSeq.store(NextSeq(recvWindowStartSeq, 1));
            } else {    // data partial copied in stream mode
                (*recvWindowData)[seq]->erase(0, read_cnt);
            }

            recvWindowUsed -= read_cnt;
            bytesRead += read_cnt;
            bytesReadUpdateTime = chrono::steady_clock::now();

            output_pos = new_pos;   // update output_pos
            return read_cnt;
        }

        boost::system::error_code Session::Close() {
            spdlog::error("{}:{} called", __PRETTY_FUNCTION__, __LINE__);
            if (config->Linger != 0) {
                auto err = flushSendBuffer();
                if (err) {
                    // log err
                }

            }

            time_point deadline = chrono::steady_clock::now() + chrono::milliseconds(config->Linger);
            while (true) {
                this_thread::sleep_for(chrono::milliseconds(100));
                if (sendWindowStartSeq == sendWindowEndSeq || steady_clock::now() >= deadline) {
                    break;
                }
            }

            auto err = sendClosePacket();
            if (err) {
                // log err
            }

            isClosed = true;
            return ErrCode::Success;
        }
    };  // namespace NCP
};  // namespace NKN
