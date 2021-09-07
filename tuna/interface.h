#ifndef __NKN_INTERFACE_H__
#define __NKN_INTERFACE_H__

#include <string>
#include <memory>

#include <boost/system/error_code.hpp>

#include "include/byteslice.h"

namespace NKN {
namespace TUNA {
using namespace std;

typedef class Conn {
public:
    virtual boost::system::error_code Close() = 0;
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
