#ifndef __NKN_INTERFACE_H__
#define __NKN_INTERFACE_H__

// #include <utility>
// #include <vector>
#include <string>
#include <memory>
// #include <algorithm>
// #include <unordered_map>

// #include <boost/asio.hpp>

#include "include/byteslice.h"
// #include "tuna/message.h"

namespace NKN {
namespace TUNA {
using namespace std;
// using namespace boost::asio;

/* typedef class Conn {
public:
    typedef shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;

    virtual void   Close() = 0;
    virtual size_t Write(const std::string&) = 0;
    virtual size_t Read(std::string&)  = 0;
    virtual const std::string LocalAddr()  = 0;
    virtual const std::string RemoteAddr() = 0;

    boost::asio::io_context io_context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard;

    unordered_map<string, socket_ptr> sessionConns;

    Conn() : work_guard(make_work_guard(io_context)) {}
    Conn(const vector<PubAddr_ptr>& Addrs) : work_guard(make_work_guard(io_context)) {
        int idx = 0;
        for_each(Addrs.cbegin(), Addrs.cend(), [this,&idx](PubAddr_ptr addr){
            auto sock = make_shared<boost::asio::ip::tcp::socket>(this->io_context);
            this->sessionConns[to_string(idx++)] = sock;

            boost::system::error_code err;
            auto endpoints = boost::asio::ip::tcp::resolver(io_context).resolve(
                    boost::asio::ip::tcp::resolver::query(addr->IP, to_string(addr->Port)), err
                );

            if (err) {
                cerr << "NameResolve failed for " << addr->IP << "with error: " << err << endl;
                return;
            }

            boost::asio::async_connect(*sock, endpoints, [](boost::system::error_code ec, boost::asio::ip::tcp::endpoint ep){
                if (ec) {
                    cerr << "async_connect failed for " << ep << " with error: " << ec << endl;
                }
                cout << "async_connect success for " << ep << endl;
            });
        });
    }

} Conn_t;
typedef std::shared_ptr<Conn_t> ConnPtr_t; */

typedef class Conn {
public:
    virtual void Close() = 0;
    virtual std::string LocalAddr()  = 0;
    virtual std::string RemoteAddr()  = 0;
    virtual size_t Read(byteSlice& out) = 0;
    virtual size_t Write(const byteSlice& in) = 0;
} Conn_t;
typedef std::shared_ptr<Conn_t> ConnPtr_t;

typedef class Listener {
public:
    virtual void Close() = 0;
    virtual std::string Addr()  = 0;
    virtual std::shared_ptr<Conn> Accept() = 0;
} Listener_t;
typedef std::shared_ptr<Listener_t> ListenerPtr_t;

typedef class Dialer {
public:
    virtual void Close() = 0;
    virtual std::string Addr() = 0;
    virtual std::shared_ptr<Conn> Dial(const std::string& addr) = 0;
} Dialer_t;
typedef std::shared_ptr<Dialer_t> DialerPtr_t;

};  // namespace TUNA
};  // namespace NKN
#endif // __NKN_INTERFACE_H__
