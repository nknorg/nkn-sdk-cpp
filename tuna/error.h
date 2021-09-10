#ifndef __TUNA_ERROR_H
#define __TUNA_ERROR_H

#include <boost/system/error_code.hpp>
#include <iostream>
#include <string>

namespace NKN {
namespace TUNA {
    enum class ErrCode {
        Success = 0,
        ErrNullConnection = 1,
        ErrOperationAborted = 2,
        ErrInvalidPacket = 3,
        ErrConnClosed = 11,
    };
};  // namespace TUNA
};  // namespace NKN
extern inline boost::system::error_code make_error_code(NKN::TUNA::ErrCode e);

namespace boost {
    namespace system {
        template <> struct is_error_code_enum<NKN::TUNA::ErrCode> : std::true_type {};
    };
};

namespace NKN {
namespace TUNA {
    // Define a custom error code category derived from boost::system::error_category
    class ErrCode_category : public boost::system::error_category {
    public:
        virtual const char *name() const noexcept override final { return "TUNA Error"; }
        virtual std::string message(int c) const override final {
            switch(static_cast<ErrCode>(c)) {
                case ErrCode::Success:
                    return "successful";
                case ErrCode::ErrNullConnection:
                    return "conn is null";
                case ErrCode::ErrConnClosed:
                    return "connection closed";
                default:
                    return "unknown error";
            }
        }
        // For be compare with generic error conditions
        virtual boost::system::error_condition default_error_condition(int c) const noexcept override final {
            switch(static_cast<ErrCode>(c)) {
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

    inline boost::system::error_code make_error_code(TUNA::ErrCode e) {
        return {static_cast<int>(e), TUNA::Get_ErrCode_category()};
    }
};  // namespace TUNA
};  // namespace NKN
#endif // __TUNA_ERROR_H

