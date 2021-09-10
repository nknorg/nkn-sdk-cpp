#include <iostream>
#include <memory>
#include <functional>
#include <future>
#include <chrono>
#include <cassert>
// #include <thread>

#include <pplx/pplxtasks.h>
#include <boost/asio.hpp>

#include "include/byteslice.h"
#include "include/crypto/hex.h"
#include "tuna/message.h"


namespace NKN {
namespace TUNA {
// using namespace std;
// using namespace web;
using namespace boost::system;
using namespace boost::asio;
using namespace boost::asio::ip;

typedef class TCPConn TCPConn_t;
class TCPConn: public std::enable_shared_from_this<TCPConn> {
public:
    constexpr static size_t MAX_BUFF_SIZE = 4096;
    typedef enum {
        CREATED,
        DIALING,
        CONNECTED,
        DISCONNECTED,
        CLOSED,
    } state_t;

    TCPConn(const string& host, uint16_t port)
        : io_context_()
        , endpoints_(tcp::resolver(io_context_).resolve(host, to_string(port)))
        , socket_(io_context_)
        , dial_deadline_(io_context_)
        , work_guard(make_work_guard(io_context_))
        , state(CREATED)
        , io_thrd(std::async(launch::async, [](io_context& io){ io.run(); }, std::ref(io_context_)))
    {
        fprintf(stderr, "%s:%d: \n", __PRETTY_FUNCTION__, __LINE__);
    }

    TCPConn(const tcp::resolver::results_type& endpoints)
        : io_context_()
        , endpoints_(endpoints)
        , socket_(io_context_)
        , dial_deadline_(io_context_)
        , work_guard(make_work_guard(io_context_))
        , state(CREATED)
        , io_thrd(std::async(launch::async, [](io_context& io){ io.run(); }, std::ref(io_context_)))
    {
        fprintf(stderr, "%s:%d: \n", __PRETTY_FUNCTION__, __LINE__);
    }

    /* void start() {
        do_connect(endpoints_.begin());
        dial_deadline_.async_wait(std::bind(&TCPConn::check_deadline, this));
    } */

    pplx::task<boost::system::error_code> Dial(/*tcp::endpoint ep,*/ int timeout) {
        fprintf(stderr, "%s:%d: \n", __PRETTY_FUNCTION__, __LINE__);
        switch (state.load()) {
            case CREATED:
            case DISCONNECTED:
                break;
            case DIALING:
            case CONNECTED:
                fprintf(stderr, "%s:%d: Connected already.\n", __PRETTY_FUNCTION__, __LINE__);
                return pplx::task_from_result<boost::system::error_code>(boost::asio::error::already_connected);
                // return pplx::task_from_result(boost::system::errc::make_error_code(boost::system::errc::already_connected));
            case CLOSED:
                fprintf(stderr, "%s:%d: Connection has closed.\n", __PRETTY_FUNCTION__, __LINE__);
                return pplx::task_from_result<boost::system::error_code>(boost::asio::error::connection_aborted);
                // return pplx::task_from_result(boost::system::errc::make_error_code(boost::system::errc::connection_aborted));
        }

        /* if (! socket_.is_open()) {
            connect_tce.set(boost::asio::error::broken_pipe);
            return pplx::task<boost::system::error_code>(connect_tce);
        } */
        // if (ep_it == endpoints_.end()) {
        //     ;
        // }

        auto self(this->shared_from_this());

        state = DIALING;
        socket_.async_connect(*endpoints_.begin(), [self](const boost::system::error_code& err){
            if (err) { // handle error
                self->state = DISCONNECTED;
                self->connect_tce.set(err);
                // self->dial_deadline_.expires_at(steady_timer::time_point::max());    // cancel deadline
                return;
            }
            // handle success
            self->dial_deadline_.expires_at(steady_timer::time_point::max());    // cancel deadline
            self->state = CONNECTED;
            self->connect_tce.set(boost::system::errc::make_error_code(boost::system::errc::success));

            fprintf(stderr, "%s:%d Connect success\n", __PRETTY_FUNCTION__, __LINE__);
            self->do_read();    // start recursive read
        });

        // set deadline
        dial_deadline_.expires_after(std::chrono::milliseconds(timeout));
        dial_deadline_.async_wait([self](const boost::system::error_code& err){
            if (err) {
                fprintf(stderr, "dial_deadline_.async_wait:%d met error: ", __LINE__);
                cerr << err.message() << ":" << err.value() << endl;
                return;
            }
            fprintf(stderr, "dial_deadline_:%d was triggered\n", __LINE__);

            boost::system::error_code ec;
            self->socket_.cancel(ec); // cancel asio
            if (err) {
                fprintf(stderr, "%s:%d met error: ", __PRETTY_FUNCTION__, __LINE__);
                cerr << err.message() << ":" << err.value() << endl;
            }

            self->state = DISCONNECTED;
            self->connect_tce.set(boost::system::errc::make_error_code(boost::system::errc::timed_out));
        });

        return pplx::task<boost::system::error_code>(connect_tce);
    }

    // pplx::task<boost::system::error_code> Write(const byteSlice& data) {
    size_t Write(const byteSlice& data) {
        fprintf(stderr, "%s:%d send data: ", __PRETTY_FUNCTION__, __LINE__);
        cerr << HEX::EncodeToString(data) << '\n';

        uint32_t len = u32ToLSB(data.length());
        size_t n = write(socket_, buffer(&len, sizeof(uint32_t)));
        assert(n == sizeof(uint32_t));

        // pplx::task_completion_event<size_t> tce;
        n = write(socket_, buffer(data.data(), data.length()));
        assert(n == data.length());

        return n;
        // return pplx::task_from_result<boost::system::error_code>(ErrCode::Success);
    }

    string LocalAddr() {
        auto ep = socket_.local_endpoint();
        return ep.address().to_string() + ":" + to_string(ep.port());
    }

    string RemoteAddr() {
        auto ep = socket_.remote_endpoint();
        return ep.address().to_string() + ":" + to_string(ep.port());
    }

    boost::system::error_code Close() {
        fprintf(stderr, "%s:%d \n", __PRETTY_FUNCTION__, __LINE__);
        stopped_ = true;
        state = CLOSED;
        dial_deadline_.cancel();
        work_guard.reset();
        boost::system::error_code err;
        socket_.close(err);
        return err;
    }

    inline void set_msg_handler(const std::function<void(shared_ptr<MsgFrame_t>)>& fn) {
        external_msg_handler = fn;
    }

private:
    /* void check_deadline() {
        if (stopped_)
            return;

        if (dial_deadline_.expiry() <= steady_timer::clock_type::now()) {
            socket_.close();    // close socket to cancel any ongoing asynchronous operations
            dial_deadline_.expires_at(steady_timer::time_point::max());
        }

        dial_deadline_.async_wait(std::bind(&TCPConn::check_deadline, this));
    } */

    /* void do_connect(ip::tcp::resolver::results_type::iterator ep_it) {
        if (ep_it == endpoints_.end()) {
            Close();
            return;
        }

        cout << "Connecting to " << ep_it->endpoint() << "...\n";
        dial_deadline_.expires_after(std::chrono::seconds(60));

        auto self(shared_from_this());
        socket_.async_connect(ep_it->endpoint(), std::bind(
            [](const boost::system::error_code& err,
                decltype(self) self,  ip::tcp::resolver::results_type::iterator ep_it) {
                if (self->stopped_) {
                    fprintf(stdout, "TCPConn[%p] was stopped\n", self.get());
                    return;
                }

                if (! self->socket_.is_open()) {
                    cout << "Connect " << ep_it->endpoint() << " timed out\n";
                    self->do_connect(++ep_it);
                    return;
                }

                if (err) {
                    cout << "Connect " << ep_it->endpoint() << " met error: " << err.message();
                    self->do_connect(++ep_it);
                    return;
                }

                cout << "Connected to " << ep_it->endpoint() << "\n";
                self->do_read();
            }, std::placeholders::_1, self, ep_it)
        );
    } */

    void do_read() {
        // fprintf(stderr, "%s:%d entry... \n", __PRETTY_FUNCTION__, __LINE__);
        auto self(shared_from_this());
        auto fr = make_shared<MsgFrame_t>(MsgFrame_t::PAGE, true);
        async_read(socket_, buffer(fr->p, sizeof(uint32_t)),
            std::bind(&TCPConn::read_frame_len, this, std::placeholders::_1, std::placeholders::_2, fr)
        );
    }

    void read_frame_len(const boost::system::error_code& err, std::size_t n, shared_ptr<MsgFrame_t> frame) {
        if (err) {
            fprintf(stderr, "%s:%d met error: ", __PRETTY_FUNCTION__, __LINE__);
            cerr << err.message() << endl;

            // TODO reset socket_ or reconnect?
            this_thread::sleep_for(std::chrono::milliseconds(500));
            do_read();
            return;
        }
        if (n==0) {
            fprintf(stderr, "Trigger read_frame_len with %zu bytes read\n", n);
            this_thread::sleep_for(std::chrono::milliseconds(500));
            do_read();
        }

        assert(n == sizeof(uint32_t));

        dial_deadline_.expires_after(std::chrono::milliseconds(5*1000));

        uint32_t len = u32FromLSB(frame->p);
        assert(len <= 4*1024);
        frame->buff->len = len;
        async_read(socket_, buffer(frame->buff->data, len),
            std::bind(&TCPConn::read_frame_body, this, std::placeholders::_1, std::placeholders::_2, frame)
        );
    }

    void read_frame_body(const boost::system::error_code& err, std::size_t n, shared_ptr<MsgFrame_t> frame) {
        fprintf(stderr, "%s:%d entry... \n", __PRETTY_FUNCTION__, __LINE__);
        dial_deadline_.expires_at(steady_timer::time_point::max());

        if (err) {
            fprintf(stderr, "%s:%d met error: ", __PRETTY_FUNCTION__, __LINE__);
            cerr << err.message() << endl;
            this_thread::sleep_for(std::chrono::milliseconds(500));
            do_read();
            return;
        }
        assert(n == frame->buff->len);

        if (external_msg_handler) {
            external_msg_handler(frame);
        }

        do_read();
    }

    inline uint32_t u32FromLSB(char* p) {
        return uint32_t(p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24);
    }

    inline uint32_t u32ToLSB(uint32_t u) {
        uint32_t ret;
        char *p = (char*)&ret;
        p[0] = u, p[1] = u>>8, p[2] = u>>16, p[3] = u>>24;
        return ret;
    }

    void write_frame_len(const boost::system::error_code& err, std::size_t n, shared_ptr<MsgFrame_t> frame) {
        if (err) {
            fprintf(stderr, "%s:%d met error: ", __PRETTY_FUNCTION__, __LINE__);
            cerr << err.message() << endl;
            send_tce.set(err);
            return;
        }

        if (n==0) {
            fprintf(stderr, "Trigger write_frame_len with %zu bytes read\n", n);
            send_tce.set(boost::asio::error::no_data);
            // TODO retry
            // return;
        }
        fprintf(stderr, "%s:%d %zu bytes success\n", __PRETTY_FUNCTION__, __LINE__, n);
        assert(n == sizeof(uint32_t));

        fprintf(stderr, "write_frame_len:%d\n", __LINE__);

        // TODO deadline_
        async_write(socket_, buffer(frame->buff->data, frame->buff->len),
                std::bind(&TCPConn::write_frame_body, this, std::placeholders::_1, std::placeholders::_2, frame));
    }

    void write_frame_body(const boost::system::error_code& err, std::size_t n, shared_ptr<MsgFrame_t> frame) {
        if (err) {
            fprintf(stderr, "%s:%d met error: ", __PRETTY_FUNCTION__, __LINE__);
            cerr << err.message() << endl;
            send_tce.set(err);
            return;
        }

        if (n==0) {
            fprintf(stderr, "Trigger write_frame_body with %zu bytes read\n", n);
            send_tce.set(boost::asio::error::in_progress);
            // return;
        }
        fprintf(stderr, "%s:%d %zu bytes success\n", __PRETTY_FUNCTION__, __LINE__, n);
        assert(n == frame->buff->len);
        send_tce.set(boost::system::errc::make_error_code(boost::system::errc::success));
    }

    bool stopped_ = false;
    io_context          io_context_;
    ip::tcp::resolver::results_type endpoints_;
    ip::tcp::socket     socket_;
    steady_timer        dial_deadline_;
    executor_work_guard<io_context::executor_type> work_guard;
    std::atomic<state_t> state;
    pplx::task_completion_event<boost::system::error_code> connect_tce;
    pplx::task_completion_event<boost::system::error_code> send_tce;
    // pplx::task_completion_event<boost::system::error_code> recv_tce;

    std::future<void>   io_thrd;
    std::function<void(shared_ptr<MsgFrame_t>)> external_msg_handler;
    // array<char, MAX_BUFF_SIZE> buffer_;
};  // class TCPConn
};  // namespace TUNA
};  // namespace NKN
