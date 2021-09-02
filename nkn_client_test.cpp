#include <iostream>

#include <cpprest/json.h>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include "include/rpc.h"
#include "client/client.h"

int main(int argc, char* argv[]) {
    vector<string> dests(argv+2, argv+argc);
    if (dests.size() < 1) {
        cout << "Msg has no destinations." << endl;
        return -22;
    }
    for (auto& it: dests) {
        cout << "Remote peer: " << it << endl;
    }

    auto cli = NKN::Client::Client::NewClient(make_shared<const NKN::Wallet::Account_t>(argv[1]), "9zAq");

    cout << "Waiting for Client connection..." << endl;
    cli->OnConnect.pop();
    cout << "Client connected" << endl;
    fprintf(stderr, "connect to %s\n", argv[1]);

    std::thread t([&cli](){
        while (cli->state != NKN::Client::Client::state_t::CLOSED) {
            unique_ptr<NKN::Client::Message> msg = cli->OnMessage.pop();
            cerr << "main.thread recv type[" << msg->Type << "] msg: " << msg->Data << " from: " << msg->Src->v << "!" << endl;
        }
    });
    t.detach();

    string line;    // read istream line by line
    web::websockets::client::websocket_outgoing_message msg;

    while (getline(cin, line)) {
        cerr << "Sent input: " << line << endl;
        auto js = NewJson(initializer_list<kvPair_t>({
                            kvPair_t("id", to_string(boost::uuids::random_generator()())),
                            kvPair_t("contentType", "text"),
                            kvPair_t("content", line),
                            kvPair_t("timestamp", uint64_t(std::time(nullptr)*1000)),
                    }));
        cli->Send(dests, js->serialize());
    }

    cerr << "stdin reach EOF." << endl;
    cli->Close().get();
    cerr << "Client close success." << endl;
}
