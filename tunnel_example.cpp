#include <cstdio>
#include <cassert>
#include <memory>
#include <future>
#include <chrono>
#include <cstdlib>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/system/error_code.hpp>

#include <spdlog/spdlog.h>

#include "include/byteslice.h"
#include "client/address.h"
#include "client/multiclient.h"
#include "spdlog/spdlog.h"
#include "tuna/client.h"

using namespace std;
using namespace NKN;
using namespace boost::asio;

typedef boost::system::error_code boost_err;

shared_ptr<const Wallet::Account_t> g_account = nullptr;
shared_ptr<Client::MultiClient_t> g_mCli = nullptr;
shared_ptr<TUNA::TunaSessionClient_t> g_tunaCli = nullptr;
shared_ptr<Client::Address_t> toNKN = nullptr;

boost_err pipe_read(shared_ptr<ip::tcp::socket> sock, TUNA::ConnPtr_t conn) {
    boost_err err = make_error_code(boost::system::errc::success);
    const auto& ep = sock->remote_endpoint();

    // boost::array<char, 1024> buf;
    string buf(4096, 0);
    while (true) {
        buf.resize(4096);
        auto n = sock->read_some(buffer(buf), err);
        if (err) {
            if (err == boost::asio::error::eof) {
                break;
            }
            spdlog::error("pipe_read({}:{}) met error {}:{}", ep.address().to_string(), ep.port(), err.message(), err.value());
            this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        if (n == 0) {
            this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        buf.resize(n);
        // spdlog::info("Recv from [{}:{}]: {}", ep.address(), ep.port(), buf);

        while (n > 0) {
            size_t w = conn->Write(buf);
            assert (w <= n || w==0);
            buf.erase(0, w);
            n -= w;
        }
    }
    spdlog::error("pipe_read[{}:{}] exit due to err {}:{}", ep.address().to_string(), ep.port(), err.message(), err.value());
    return err;
}

boost_err pipe_write(shared_ptr<ip::tcp::socket> sock, TUNA::ConnPtr_t conn) {
    boost_err err = make_error_code(boost::system::errc::success);
    const auto& ep = sock->remote_endpoint();

    byteSlice buf(4096, 0);
    while (true) {
        buf.resize(0);
        size_t n = conn->Read(buf, 4096);
        if (n == 0) {
            spdlog::warn("pipe_write[{}:{}] read 0 bytes.", ep.address().to_string(), ep.port());
            this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        while (n > 0) {
            size_t w = sock->write_some(buffer((void*)buf.data(), n), err);
            if (err) {
                if (err == boost::asio::error::eof) {
                    break;
                }
                spdlog::error("pipe_write({}:{}) met error {}:{}", ep.address().to_string(), ep.port(), err.message(), err.value());
                this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            assert(w <= n);

            buf.erase(w);
            n -= w;
        }
    }

    return err;
}

inline void pipe(shared_ptr<ip::tcp::socket> sock, TUNA::ConnPtr_t conn) {
    async(launch::async, pipe_read, sock, conn);
    async(launch::async, pipe_write, sock, conn);
}

void handle_dial(shared_ptr<ip::tcp::socket> sock) {
    auto sess = g_tunaCli->Dial(toNKN->v);
    if (sess == nullptr) {
        spdlog::error("TunaCli[{}] dialed to {} failed", g_tunaCli->clientAccount->PrivateKey.toHexString(), toNKN->v);
        return;
    }

    return pipe(sock, sess);
}


int main(int argc, char* argv[]) {
    boost_err err;
    io_context ioc;

    if (argc < 5) {
        spdlog::error("Usage: {} <listenIP> <port> <Seed> <toNKN>", argv[0]);
        exit(22);
    }

    ip::address_v4 local = ip::make_address_v4(argv[1], err);
    if (err) {
        cerr << argv[0] << " parsed host: " << argv[1] << " met Host error: " << err.message() << ":" << err.value() << '\n';
        return err.value();
    }

    toNKN = make_shared<Client::Address_t>(string(argv[4]));
    g_account = make_shared<const Wallet::Account_t>(argv[3]);

    g_mCli = Client::MultiClient::NewMultiClient(g_account, "test", 4, false, nullptr);
    unique_ptr<bool> succ = g_mCli->OnConnect.pop(false, std::chrono::milliseconds(g_mCli->config->WsHandshakeTimeout));
    if (succ==nullptr || (*succ)==false) {
        spdlog::error("MultiClient[{}] can't join NKN network until timeout", g_account->PrivateKey.toHexString());
    }
    this_thread::sleep_for(std::chrono::milliseconds(1000));
    spdlog::info("MultiClient[{}] connected to NKN network", g_account->PrivateKey.toHexString());

    auto g_tunaCli = TUNA::TunaSessionClient::NewTunaSessionClient(g_account, g_mCli, Wallet::NewWallet(g_account), nullptr);

    // Listen on local and spawn thread for each connection
    ip::tcp::acceptor acceptor(ioc, {local, (uint16_t)stoul(argv[2])});
    while (true) {
        // auto sock = make_shared<ip::tcp::socket>(ioc);
        auto sock = make_shared<ip::tcp::socket>(ioc);
        acceptor.accept(*sock);
        std::cout << "Accepted from: " << sock->remote_endpoint().address() << ":" << sock->remote_endpoint().port() << '\n';
        new thread(handle_dial, sock);
    }
}
