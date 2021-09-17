#include <iostream>
#include <iomanip>
#include <vector>
#include <deque>
#include <list>

#include "crypto/random.h"

using namespace std;
using namespace NKN;

int main() {
    cout << "string: " << Random<string>()(8) << endl;
    cout << "Int: " << Random<int>()(4) << endl;
    cout << "char: " << Random<char>()() << endl;
    cout << "LLU: " << Random<uint64_t>()() << endl;

    cout << "vector: ";
    auto vec = Random<vector<char>>()(8);
    for (auto& c: vec) {
        cout << setfill('0') << setw(2) << hex << c;
    }
    cout << endl;

    auto deq = Random<deque<char>>()(1024);
    auto lst = Random<list<char>>()(1024);

    auto arr = Random<array<char,256>>()(16);
    cout << string(arr.cbegin(), arr.cend()) << endl;
    // cout << "char*: " << Random<char*>()() << endl;  // should trigger primitive type check error

    cout << "Uint256: " << Random<Uint256>()() << endl;
    cout << "shared_ptr<Uint160>: " << *(Random<shared_ptr<Uint160>>()()) << endl;
}
