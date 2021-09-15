#ifndef __TUNA_CONN_H__
#define __TUNA_CONN_H__

#include <iostream>
#include <memory>
#include <atomic>
#include <chrono>

#include <pplx/pplxtasks.h>
#include <boost/asio.hpp>

#include "include/byteslice.h"
#include "tuna/interface.h"
#include "tuna/error.h"

namespace NKN {
namespace TUNA {

using namespace std;
using namespace boost::system;
using namespace boost::asio;

typedef class TCPConn TCPConn_t;
class TCPConn: public Conn/*, public std::enable_shared_from_this<TCPConn>*/ {
public:

    constexpr static size_t MAX_BUFF_SIZE = 4096;

    TCPConn(const string& host, uint16_t port)
        : io_context_()
        , remote_eps_(ip::tcp::resolver(io_context_).resolve(host, to_string(port)))
        , socket_(io_context_)
    {}

    void _connHandler(pplx::task_completion_event<boost_err>& tce,
            ip::tcp::resolver::results_type::const_iterator ep, const boost_err& err) {
        if (!err) { // if Success
            // save ep
            tce.set(err);
            return;
        }

        if (isStoped_) {
            tce.set(ErrCode::ErrConnClosed);
            return;
        }

        if (++ep == remote_eps_.cend()) { // error and iter->next reached end
            tce.set(err);
            return;
        }

        socket_.async_connect(*ep, std::bind(&TCPConn::_connHandler, this, tce, ep, std::placeholders::_1));
    }

    pplx::task<boost_err> Dial(uint32_t timeout) {
        if (isStoped_) {
            return pplx::task_from_result(boost_err(ErrCode::ErrConnClosed));
        }

        pplx::task_completion_event<boost_err> tce;
        auto ep = remote_eps_.cbegin();
        socket_.async_connect(*ep, std::bind(&TCPConn::_connHandler, this, tce, ep, std::placeholders::_1));

        io_context_.restart();
        io_context_.run_for(std::chrono::milliseconds(timeout));
        if (!io_context_.stopped()) {   // timeout
            tce.set(ErrCode::ErrMaxWait);
            io_context_.stop();
        }

        return pplx::create_task(tce);
    }

    inline std::string LocalAddr() final {
        auto ep = socket_.local_endpoint();
        return ep.address().to_string() + ":" + to_string(ep.port());
    }

    inline std::string RemoteAddr() final {
        auto ep = socket_.remote_endpoint();
        return ep.address().to_string() + ":" + to_string(ep.port());
    }

    boost_err Close() final {
        isStoped_ = true;
        boost_err err;
        socket_.close(err);
        io_context_.stop();
        return err;
    }

    inline shared_ptr<byteSlice> readMessage(size_t maxMsgSize) {
        auto ret = make_shared<byteSlice>(maxMsgSize, 0);
        auto n = Read(*ret, maxMsgSize);
        return ret;
    }

    size_t Read(byteSlice& out, size_t maxMsgSize) final {
        boost_err err;

        // set deadline
        steady_timer timer(io_context_);
        timer.expires_after(std::chrono::milliseconds(3000));
        timer.async_wait([&err,this](const boost_err& ec){
            if (ec) {  // aborted by err code
                err = ec;
                return;
            }
            socket_.cancel();   // timeout
        });

        uint32_t len = 0;
        size_t n = read(socket_, buffer(&len, sizeof(uint32_t)), err);
        assert (n == sizeof(uint32_t));

        n = u32FromLSB((char*)&len);
        if (n > maxMsgSize) { // if n too large
            err = ErrCode::ErrDataSizeTooLarge;
            return 0;
        }

        out.resize(n, 0);
        len = read(socket_, buffer((void*)out.data(), n), err);
        assert (len == n);

        if (err) {
            fprintf(stderr, "%s:%d met err: ", __PRETTY_FUNCTION__, __LINE__);
            cerr << err.message() << '\n';
        }

        return n;
    }

    /* size_t Read_async(byteSlice& out) {
        boost_err ec;

        auto read_body = [&ec](const boost_err& err, size_t n) -> void {
            if (err) {
                // log err
                ec = err;
            } else {
                ec = ErrCode::Success;
            }
        };

        uint32_t len = 0;
        async_read(socket_, buffer(&len, sizeof(uint32_t)),
            [&read_body,&out,&ec,&len,this](const boost_err& err, size_t n){
                if (err) {
                    ec = err;
                    return;
                }
                assert(n == sizeof(uint32_t));

                uint32_t cnt = this->u32FromLSB((char*)&len);
                out.resize(cnt, 0);  // resize out with cnt
                async_read(socket_, buffer((void*)out.data(), cnt), read_body);
            }
        );

        io_context_.restart();
        io_context_.run_for(std::chrono::milliseconds(3000));
        if (!io_context_.stopped()) {   // timeout
            io_context_.stop();
            if (!ec) {
                ec = ErrCode::ErrMaxWait;
            }
        }

        if (ec) {
            // log err code
        }

        return out.length();
    } */

    size_t Write(const byteSlice& data) final {
        boost_err err;

        // set deadline
        steady_timer timer(io_context_);
        timer.expires_after(std::chrono::milliseconds(3000));
        timer.async_wait([&err,this](const boost_err& ec){
            if (ec) {  // aborted by err code
                err = ec;
                return;
            }
            socket_.cancel();
        });

        uint32_t len = u32ToLSB(data.length());
        auto n = write(socket_, buffer(&len, sizeof(uint32_t)), err);
        assert (n == sizeof(uint32_t));

        n = write(socket_, buffer(data.data(), data.length()), err);
        assert (n == data.length());

        if (err) {
            fprintf(stderr, "%s:%d met err: ", __PRETTY_FUNCTION__, __LINE__);
            cerr << err.message() << '\n';
        }

        return n;
    }

    /* size_t Write_async(const byteSlice& data) {
        boost_err ec;
        size_t cnt = 0;

        auto write_body = [&ec,&cnt](const boost_err& err, size_t n){
            cnt = n;
            if (err) {
                ec = err;
            } else {
                ec = ErrCode::Success;
            }
        };

        uint32_t len = u32ToLSB(data.length());
        async_write(socket_, buffer(&len, sizeof(uint32_t)),
            [&write_body,&ec,&data,this](const boost_err& err, size_t n){
                if (err) {
                    ec = err;
                    return;
                }
                assert(n == sizeof(uint32_t));

                async_write(this->socket_, buffer(data.data(), data.length()), write_body);
            }
        );

        io_context_.restart();
        io_context_.run_for(std::chrono::milliseconds(3000));
        if (!io_context_.stopped()) {   // timeout
            io_context_.stop();
            if (!ec) {
                ec = ErrCode::ErrMaxWait;
            }
        }

        if (ec) {
            // log err code
        }

        return cnt;
    } */

    inline uint32_t u32FromLSB(char* p) {
        return uint32_t(p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24);
    }

    inline uint32_t u32ToLSB(uint32_t u) {
        uint32_t ret;
        char *p = (char*)&ret;
        p[0] = u, p[1] = u>>8, p[2] = u>>16, p[3] = u>>24;
        return ret;
    }

private:
    atomic_bool isStoped_;
    io_context          io_context_;
    ip::tcp::resolver::results_type remote_eps_;
    ip::tcp::socket     socket_;
};
using namespace boost::system;
using namespace boost::asio;
};  // namespace TUNA
};  // namespace NKN
#endif // __TUNA_CONN_H__
