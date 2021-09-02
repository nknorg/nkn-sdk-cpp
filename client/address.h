#ifndef __NKN_CLIENT_ADDR_H__
#define __NKN_CLIENT_ADDR_H__

#include <iostream>
#include <memory>

#include "include/wallet.h"

namespace NKN {
namespace Client {

using namespace std;

typedef struct Address {
    string v;
    string identifier;
    string domain;  // NKN DNS
    shared_ptr<Wallet::PubKey_t> pubKey;
    shared_ptr<Uint256> addressID;

    Address(const string& addr): v(addr), identifier(""), domain(""), pubKey(nullptr), addressID(nullptr) {
        auto const pos    = addr.find_last_of('.');
        auto const suffix = addr.substr(pos+1); // npos+1=0 in not found case
        if (pos != string::npos)    // if found '.' in addr
            identifier      = addr.substr(0, pos);

        if (isPubKey(suffix)) {
            pubKey    = make_shared<Wallet::PubKey_t>(suffix);
            // v      = MakeAddressString(pubKey, identifier);  // Update v
            addressID = HASH("sha256").sum<shared_ptr,uBigInt,256>(v);
        } else {    // suffix is NS name
            domain = suffix;
            // lazy pubKey from NameResolver(suffix)
            // lazy addressID Hash
            // update v after suffix was resolved to pubKey
        }
    }

    Address(const string& registrant, const string& iden)
        : v(""), identifier(iden), domain(""), pubKey(nullptr), addressID(nullptr) {
        v = (identifier.length() == 0) ? registrant : identifier + "." + registrant;
        if (isPubKey(registrant)) {
            pubKey    = make_shared<Wallet::PubKey_t>(registrant);
            addressID = HASH("sha256").sum<shared_ptr,uBigInt,256>(v);
        } else {    // NS name
            domain = registrant;
            // lazy pubKey from NameResolver(suffix)
            // lazy addressID Hash
            // update v after suffix was resolved to pubKey
        }
    }

    Address(shared_ptr<ED25519::PubKey_t> pk, const string& iden="")
        : v(MakeAddressString(*pk,iden)), identifier(iden), domain(""), pubKey(pk),
        addressID(HASH("sha256").sum<shared_ptr,uBigInt,256>(v)) {}

    Address(const Wallet::PubKey_t& pk, const string& iden="")
        : v(MakeAddressString(pk,iden)), identifier(iden), domain(""), pubKey(make_shared<Wallet::PubKey_t>(pk)),
        addressID(HASH("sha256").sum<shared_ptr,uBigInt,256>(v)) {}

    inline static bool isPubKey(const string& str) {
        return (str.length() == Wallet::PubKey_t::HexStrLen) && Wallet::PubKey_t::isValid(str);
    }

    inline static const string MakeAddressString(const ED25519::PubKey_t& pk, const string& identifier="") {
        return identifier.size() ? identifier + "." + pk.toHexString() : pk.toHexString();
    }

    bool ResolveNS() {
        if (pubKey) {
            v=MakeAddressString(*pubKey, identifier);
            addressID = HASH("sha256").sum<shared_ptr,uBigInt,256>(v);
            return true;
        }
        // TODO getRegistrant RPC got pubKey
        return false;
    }

    constexpr const char* Network() const { return "nkn"; }
    const string& String() const { return v; }
} Address_t;

};  // namespace Client
};  // namespace NKN
#endif  // __NKN_CLIENT_ADDR_H__
