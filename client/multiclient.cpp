
#include "client/multiclient.h"

namespace NKN {
namespace Client {
using namespace std;

MultiClient::MultiClient(Account_ptr acc, const string& baseIdentifier, int cliCnt, bool originalClient, ClientConfig_ptr cfg)
    : config(ClientConfig_t::MergeClientConfig(cfg))
        , offset(originalClient)
        // , addr(Address::MakeAddressString(acc->PublicKey, baseIdentifier))
        , addr(make_shared<Address_t>(acc->PublicKey, baseIdentifier))
        , OnConnect(1), OnMessage(config->MsgChanLen)
        , isClosed(false), createDone(false)
{
    for (int idx=0-offset; idx<cliCnt+offset; idx++) {
        cli_thrd_grp.emplace_back(
            std::async(launch::async, &MultiClient::subClient_handler, this, idx, acc, baseIdentifier)
        );
    }
}

bool MultiClient::Close() {
    isClosed = true;

    vector<future<int>> close_thrd_grp; // for future<int>.wait() in destructor
    for_each(clients->cbegin(), clients->cend(), [&close_thrd_grp](decltype(clients)::obj_t::value_type kv){
        close_thrd_grp.emplace_back(
            std::async(launch::async, [](int idx, decltype(kv)::second_type cli){
                fprintf(stdout, "%s:%d waiting for close subClient[%d] ...\n", __PRETTY_FUNCTION__, __LINE__, idx);
                cli->Close();   //.get();
                fprintf(stdout, "%s:%d asynchronous close subClient[%d].\n", __PRETTY_FUNCTION__, __LINE__, idx);
                return idx;
            }, kv.first, kv.second)
        );
    });
    return isClosed;
}
};  // namespace Client
};  // namespace NKN
