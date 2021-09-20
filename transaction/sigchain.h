#include <memory>
#include <sstream>

#include "include/crypto/random.h"
#include "include/serialize.h"
#include "include/account.h"
#include "pb/sigchain.pb.h"

using namespace std;

namespace NKN {
namespace TXN {
shared_ptr<pb::SigChainElem> NewSigChainElem(shared_ptr<Uint256> id, const Wallet::PubKey_t& nextPubkey,
        const string& signature, const string& vrf, const string& proof, bool mining, const pb::SigAlgo& sigAlgo);

shared_ptr<pb::SigChain> InitSigChain(const Uint256& srcID, const Wallet::PubKey_t& srcPubKey,
        const Uint256& destID, const Wallet::PubKey_t& destPubKey, shared_ptr<Uint256> blockHash,
        uint32_t dataSize, uint32_t nonce);
}; // namespace TXN
}; // namespace NKN
