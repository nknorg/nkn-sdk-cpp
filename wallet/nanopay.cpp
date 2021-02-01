#ifndef __NKN_NANOPAY_H__
#define __NKN_NANOPAY_H__

#include "include/crypto/ed25519.h"
#include "include/wallet.h"
#include "include/rpc.h"
#include "include/transaction.h"
#include <system_error>

using namespace std;

namespace NKN {
namespace Wallet {
    Uint64 AmountStrToUint64(const string& amount) {
        mpz_class val, exp;

        auto dot = amount.rfind('.');
        if (dot == string::npos) {
            val.set_str(amount, 10);
            val *= StorageFactor;
            return Uint64(val);
        }

        auto dot_len = amount.size()-dot-1;
        if (dot_len > MaximumPrecision) { // TODO throw unsupported precision exception
            fprintf(stderr, "%s:%d Amount %s is invalid precision\n", __PRETTY_FUNCTION__, __LINE__, amount.c_str());
            return 0;
        }

        val.set_str(amount.substr(0, dot) + amount.substr(dot+1), 10);
        mpz_ui_pow_ui(exp.get_mpz_t(), 10L, MaximumPrecision-dot_len);
        return Uint64(val*exp);
    }

    shared_ptr<pb::Transaction> NanoPay::IncrementAmount(const string& delta, std::error_code& ecRef) {
        if (rpcClient == NULL){  // TODO uninitialized error
            ecRef = make_error_code(std::errc::not_connected);
            return nullptr;
        }

        uint32_t height = 0;
        try {
            height = rpcClient->GetHeight();
        } catch (const std::exception& ex) {
            fprintf(stderr, "JsonRPC met exception: %s\n", ex.what());
            if (0 == expiration) {
                ecRef = make_error_code(std::errc::timed_out);
                return nullptr;
            }
        }

        // TODO mutex lock
        if ( 0 == expiration || expiration <= height+senderExpirationDelta ) {
            id = Uint64::Random<Uint64>();
            expiration = height + duration;
            amount = 0;
        }

        amount += AmountStrToUint64(delta);
        auto txn = TXN::NewNanoPayTransaction(senderWallet->account->ProgramHash,
                recipientProgramHash, id, amount, expiration, expiration);
        txn->mutable_unsigned_tx()->set_fee(fee.Value().get_si());
        return txn;
    }

    shared_ptr<NanoPay_t> NanoPay::NewNanoPay(
                    shared_ptr<JsonRPC> rpcCli, shared_ptr<Wallet_t> senderWallet,
                    string recvAddr, Uint64 fee, uint32_t duration) {
        auto ret = shared_ptr<NanoPay_t>(new NanoPay());
        ret->rpcClient = rpcCli;
        ret->senderWallet = senderWallet;
        ret->recipientProgramHash = ED25519::ProgramHash::fromAddress(recvAddr);
        ret->recipientAddress = recvAddr;
        ret->id = Uint64::Random<Uint64>();
        ret->fee = fee;
        ret->amount = 0;
        ret->duration = duration;
        ret->expiration = 0;
        return ret;
    }
};  // namespace Wallet
};  // namespace NKN
#endif  // __NKN_NANOPAY_H__
