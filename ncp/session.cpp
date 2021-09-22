#include <chrono>
#include <memory>
#include <thread>

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

        Session::Session(string localAddr, string remoteAddr,
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
                  resendChan(nullptr), isAccepted(false),
                  isEstablished(false),
                  isClosed(true),
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
                auto err = handleACKPkt(pktPtr);
                if (err)
                    return err;
            }

            // is BytesRead packet
            if (isEst && pktPtr->bytes_read() > remoteBytesRead) {
                remoteBytesRead = pktPtr->bytes_read();
                sendWindowUpdate.push(make_unique<bool>(true), true);
            }

            // is seq packet
            if (isEst && pktPtr->sequence_id() > 0) {
                auto err = handleSeqPkt(pktPtr);
                if (err)
                    return err;
            }

            return ErrCode::Success;
        }

        boost::system::error_code Session::handleACKPkt(const shared_ptr<pb::Packet> &pkt) {
            auto ack_start_seq_len = pkt->ack_start_seq_size();
            auto ack_seq_count_len = pkt->ack_seq_count_size();

            if (ack_start_seq_len > 0 && ack_seq_count_len > 0 && ack_start_seq_len != ack_seq_count_len) {
                return ErrCode::ErrInvalidPacket;
            }
            // TODO
            return ErrCode::Success;
        }

        boost::system::error_code Session::handleSeqPkt(const shared_ptr<pb::Packet> &pkt) {
            const string &data = pkt->data();
            if (data.length() > recvMtu) {
                return ErrCode::ErrDataSizeTooLarge;
            }

            uint32_t seq = pkt->sequence_id();
            if (CompareSeq(seq, recvWindowStartSeq) >= 0) {
                if (recvWindowData->count(seq) == 0) {  // not received seq yet
                    if (recvWindowUsed + data.length() > recvWindowSize) {
                        return ErrCode::ErrRecvWindowFull;
                    }

                    (*recvWindowData)[seq] = make_shared<string>(data);
                    recvWindowUsed += (uint32_t) data.length();

                    if (seq == recvWindowStartSeq) {
                        recvDataUpdate.push(make_unique<bool>(true), true);
                    }
                }
            }

            return ErrCode::Success;
        }

        boost::system::error_code Session::handleHandshakePacket(const shared_ptr<pb::Packet> &pkt) {
            if (isEstablished) {
                return ErrCode::Success;
            }

            if (pkt->window_size() == 0 || pkt->mtu() == 0 || pkt->client_ids_size() == 0) {
                return ErrCode::ErrInvalidPacket;
            }

            sendWindowSize = std::min(pkt->window_size(), sendWindowSize.load());
            sendMtu = std::min(pkt->mtu(), sendMtu.load());

            size_t conn_cnt = std::min((size_t) pkt->client_ids_size(), localClientIDs.size());

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
                        std::bind(this->sendWith, this->tunaCli, conn->localClientID, conn->remoteClientID, serialized,
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
            if (auto cnt = connections->size() > 0) {
                for (auto it = connections->cbegin(); it != connections->cend(); it++) {
                    ConnectionPtr_t conn = it->second;
                    pplx::create_task(
                            std::bind(sendWith, tunaCli, conn->localClientID, conn->remoteClientID, raw, timeo)
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
            } else {
                size_t remoteID_cnt = remoteClientIDs.size();
                auto all = localClientIDs.size();
                for (size_t idx = 0; idx < localClientIDs.size(); idx++) {
                    string localID = localClientIDs[idx];
                    string remoteID = remoteID_cnt > 0 ? remoteClientIDs[idx % remoteID_cnt] : localID;
                    pplx::create_task(
                            std::bind(sendWith, tunaCli, localID, remoteID, raw, timeo)
                    ).then([&err_cnt, &send_tce, all](const boost::system::error_code &err) {
                        if (err) {
                            err_cnt++;
                            if (err_cnt == all) {
                                send_tce.set(err);
                            }
                        } else {
                            send_tce.set(ErrCode::Success);
                        }
                    });
                }
            }

            // TODO deadline send_tce.set(timeout)
            return pplx::create_task(send_tce).get();
        }

        boost::system::error_code Session::Dial(/*timeout*/) {
            // TODO Lock acceptLock
            if (isAccepted) {
                return ErrCode::ErrSessionEstablished;
            }

            auto err = sendHandshakePacket(chrono::milliseconds(config->InitialRetransmissionTimeout));
            if (err)
                return err;

            auto accepted = onAccept.pop(/*timeout*/);
            if (accepted == nullptr) {  // timeout
                return ErrCode::ErrMaxWait;
            }

            start();
            isAccepted = true;
            return ErrCode::Success;
        }

        uint32_t Session::waitForSendWindow(uint32_t n) {
            while (SendWindowUsed() + n > sendWindowSize) { // check until SendWindowUsed()+n < sendWindowSize
                auto c = sendWindowUpdate.pop(true, chrono::milliseconds(1000));
                if (IsClosed()) {
                    return 0;
                }
            }
            return sendWindowSize - SendWindowUsed();
        }

        boost::system::error_code Session::flushSendBuffer() {
            // TODO Lock
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
            pktPtr->set_allocated_data(buf.get());

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
                }

                if (IsClosed())
                    return ErrCode::ErrSessionClosed;
            }
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
                    fprintf(stderr, "%s:%d met error: ", __PRETTY_FUNCTION__, __LINE__);
                    cerr << err.message() << ":" << err.value() << '\n';
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

            while (true) {
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
                            std::bind(this->sendWith, this->tunaCli, conn->localClientID, conn->remoteClientID, raw,
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
                // log ErrCode::ErrSessionClosed
                return 0;
            }

            if (!IsEstablished()) {
                // log ErrCode::ErrSessionNotEstablished
                return 0;
            }

            uint32_t len = data.length();
            if (len == 0) {
                return 0;
            }

            if (!IsStream() && (len > sendMtu.load() || len > sendWindowSize.load())) {
                // log ErrCode::ErrDataSizeTooLarge
                return 0;
            }

            uint32_t cnt = 0, sent = 0;
            auto src_ptr = data.data();
            auto end_ptr = src_ptr + data.length();
            if (IsStream()) {
                while (src_ptr <= end_ptr) {
                    auto sendWindowAvailable = waitForSendWindow(1);
                    if (IsClosed()) {   // if closed during wait
                        // log ErrCode::ErrSessionClosed
                        return 0;
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

                    if (shouldFlush) {
                        auto err = flushSendBuffer();
                        if (err) {
                            // log err
                            return sent;
                        }
                    }
                    src_ptr += cnt;
                }
            } else {
                // TODO for non-stream mode
            }

            return sent;
        }

        size_t Session::Read(byteSlice &buf, size_t) {
            if (IsClosed()) {    // if closed during channel waiting
                // log ErrCode::ErrSessionClosed
                return 0;
            }

            if (!IsEstablished()) {
                // log ErrCode::ErrSessionNotEstablished
                return 0;
            }

            size_t wanted = buf.capacity();
            if (wanted == 0) {
                return 0;
            }

            uint32_t recv_seq = 0;
            while (!IsClosed()) {
                if (IsClosed()) {    // if closed during channel waiting
                    // log ErrCode::ErrSessionClosed
                    return 0;
                }

                recv_seq = recvWindowStartSeq;
                if (recvWindowData->count(recv_seq) > 0) {  // if seq has ready
                    break;
                }
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

            auto remain = wanted - read_cnt;
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
            }

            return read_cnt;
        }

        size_t Session::_recvAndUpdateSeq(uint32_t seq, string::iterator &output_pos) {
            if (recvWindowData->count(seq) <= 0) {  // if map[seq] not exist
                return 0;
            }

            auto data = (*recvWindowData)[seq];
            auto new_pos = std::copy(data->cbegin(), data->cend(), output_pos);
            int read_cnt = new_pos - output_pos;
            assert(read_cnt >= 0);

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
