#ifndef __NCP_ERROR_H
#define __NCP_ERROR_H

#include <boost/system/error_code.hpp>
#include <iostream>
#include <string>

namespace NKN {
namespace NCP {
    enum class ErrCode {
        Success = 0,
        ErrSessionEstablished = 1,
        ErrSessionNotEstablished = 2,
        ErrReadDeadlineExceeded = 3,
        ErrWriteDeadlineExceeded = 4,
        ErrBufferSizeTooSmall = 5,
        ErrDataSizeTooLarge = 6,
        ErrInvalidPacket = 7,
        ErrRecvWindowFull = 8,
        ErrNotHandshake = 9,
        ErrSessionClosed = 10,
        ErrConnClosed = 11,
        ErrMaxWait = 12,
    };
};  // namespace NCP
};  // namespace NKN
extern inline boost::system::error_code make_error_code(NKN::NCP::ErrCode e);

namespace boost {
    namespace system {
        template <> struct is_error_code_enum<NKN::NCP::ErrCode> : std::true_type {};
    };
};

namespace NKN {
namespace NCP {
    // Define a custom error code category derived from boost::system::error_category
    class ErrCode_category : public boost::system::error_category {
    public:
        virtual const char *name() const noexcept override final { return "NCP Error"; }
        virtual std::string message(int c) const override final {
            switch(static_cast<ErrCode>(c)) {
                case ErrCode::Success:
                    return "successful";
                case ErrCode::ErrSessionEstablished:
                    return "session was established already";
                case ErrCode::ErrSessionNotEstablished:
                    return "session not established yet";
                case ErrCode::ErrReadDeadlineExceeded:
                    return "read deadline exceeded";
                case ErrCode::ErrWriteDeadlineExceeded:
                    return "write deadline exceeded";
                case ErrCode::ErrBufferSizeTooSmall:
                    return "read buffer size is less than data length in non-stream mode";
                case ErrCode::ErrDataSizeTooLarge:
                    return "data size is greater than session mtu";
                case ErrCode::ErrInvalidPacket:
                    return "invalid packet";
                case ErrCode::ErrRecvWindowFull:
                    return "receive window full";
                case ErrCode::ErrNotHandshake:
                    return "first packet is not handshake packet";
                case ErrCode::ErrSessionClosed:
                    return "session closed";
                case ErrCode::ErrConnClosed:
                    return "connection closed";
                case ErrCode::ErrMaxWait:
                    return "max wait time reached";
                default:
                    return "unknown error";
            }
        }
        // For be compare with generic error conditions
        virtual boost::system::error_condition default_error_condition(int c) const noexcept override final {
            switch(static_cast<ErrCode>(c)) {
                case ErrCode::ErrSessionEstablished:
                    return make_error_condition(boost::system::errc::invalid_argument);
                /* case ErrCode::ErrSessionNotEstablished:
                    return make_error_condition();
                case ErrCode::ErrReadDeadlineExceeded:
                    return make_error_condition();
                case ErrCode::ErrWriteDeadlineExceeded:
                    return make_error_condition();
                case ErrCode::ErrBufferSizeTooSmall:
                    return make_error_condition();
                case ErrCode::ErrDataSizeTooLarge:
                    return make_error_condition();
                case ErrCode::ErrInvalidPacket:
                    return make_error_condition();
                case ErrCode::ErrRecvWindowFull:
                    return make_error_condition();
                case ErrCode::ErrNotHandshake:
                    return make_error_condition();
                case ErrCode::ErrSessionClosed:
                    return make_error_condition();
                case ErrCode::ErrConnClosed:
                    return make_error_condition();
                case ErrCode::ErrMaxWait:
                    return make_error_condition(); */
                default:
                    return boost::system::error_condition(c, *this);
            }
        }
    };

    extern inline const ErrCode_category& Get_ErrCode_category() {
        static ErrCode_category c;
        return c;
    }

    inline boost::system::error_code make_error_code(NCP::ErrCode e) {
        return {static_cast<int>(e), NCP::Get_ErrCode_category()};
    }
};  // namespace NCP
};  // namespace NKN
#endif // __NCP_ERROR_H

