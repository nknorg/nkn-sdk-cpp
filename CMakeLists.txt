cmake_minimum_required(VERSION 3.20)
project(nkn_sdk_cpp_priv)

set(CMAKE_CXX_STANDARD 14)
set(Boost_USE_MULTITHREADED FALSE)
set(OPENSSL_ROOT_DIR /usr/local/opt/openssl /usr/local/Cellar/openssl@1.1/1.1.1h/)

include_directories(client)
include_directories(include)
include_directories(include/crypto)
include_directories(json)
include_directories(ncp)
include_directories(ncp/pb)
include_directories(payloads)
include_directories(pb)
include_directories(transaction)
include_directories(tuna)
include_directories(wallet)
include_directories(thirdparty/cpprestsdk/Release/include)
include_directories(thirdparty/rapidjson/include)
include_directories(thirdparty/object_threadsafe)
include_directories(/usr/local/Cellar/boost/1.74.0/include/)
include_directories(/usr/local/opt/protobuf/include/)
include_directories(/usr/local/Cellar/gmp/6.2.1/include)
include_directories(/usr/local/Cellar/libsodium/1.0.18_1/include)
include_directories(/usr/local/Cellar/openssl@1.1/1.1.1h/include)
include_directories(.)


set(HEADERS
        client/address.h
        client/client.h
        client/config.h
        client/message.h
        client/multiclient.h
        include/crypto/aes.h
        include/crypto/base58.h
        include/crypto/crypto.h
        include/crypto/ed25519.h
        include/crypto/hash.h
        include/crypto/hex.h
        include/crypto/random.h
        include/crypto/scrypt.h
        include/crypto/secretbox.h
        include/crypto/sodium_random.h
        include/crypto/xchacha20-poly1305.h
        include/account.h
        include/byteslice.h
        include/channel.h
        include/rpc.h
        include/serialize.h
        include/SFINAE.h
        include/transaction.h
        include/uBigInt.h
        include/unique_ptr_backporting.h
        include/wallet.h
        include/walletData.h
        json/NKNCodec.h
        tuna/interface.h
        tuna/message.h
        json/NKNCodec.h
        ncp/pb/packet.pb.h
        ncp/config.h
        ncp/connection.h
        ncp/error.h
        ncp/session.h
        ncp/util.h
        payloads/gogo.pb.h
        payloads/payloads.pb.h
        pb/block.pb.h
        pb/clientmessage.pb.h
        pb/node.pb.h
        pb/nodemessage.pb.h
        pb/sigchain.pb.cc
        pb/sigchain.pb.h
        pb/transaction.pb.h
        transaction/sigchain.h
        )
set(SOURCES
        transaction/transaction.cpp
        transaction/txBuilder.cpp
        tuna/interface.h
        tuna/message.h
        wallet/account.cpp
        wallet/nanopay.cpp
        wallet/wallet.cpp
        wallet/walletData.cpp
        config.cpp
        rpc.cpp
        json/NKNCodec.cpp
        ncp/connection.cpp
        ncp/session.cpp
        ncp/pb/packet.pb.cc
        payloads/gogo.pb.cc
        payloads/payloads.pb.cc
        pb/block.pb.cc
        pb/clientmessage.pb.cc
        pb/node.pb.cc
        pb/nodemessage.pb.cc
        pb/sigchain.pb.cc
        pb/transaction.pb.cc
        pb/sigchain.pb.cc
        )


add_library(nkn_sdk_cpp_priv STATIC ${SOURCES})
target_link_libraries(nkn_sdk_cpp_priv
        /Users/chow/test/c8d172709018780eb069/protobuf/platform/x86_64_ios/lib/libprotobuf.a
        /Users/chow/test/libsodium-1.0.18/src/libsodium/.libs/libsodium.a
        /Users/chow/test/gmp-6.1.0-20151019/ios/lib/libgmp.a
        /Users/chow/test/gmp-6.1.0-20151019/ios/lib/libgmpxx.a
        /usr/local/Cellar/openssl@1.1/1.1.1h/lib/libcrypto.a
        /usr/local/Cellar/cpprestsdk/2.10.16/lib/libcpprest.dylib)
