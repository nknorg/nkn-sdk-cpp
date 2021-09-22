#ifndef __NCP_UTIL_H__
#define __NCP_UTIL_H__

#include <cstdint>
#include <string>

namespace NKN {
    namespace NCP {
        constexpr int32_t MinSequenceID = 1;
    };
};

inline uint32_t NextSeq(uint32_t seq, int64_t step) {
    int64_t max = UINT32_MAX - NKN::NCP::MinSequenceID + 1;
    int32_t res = (int64_t(seq) - NKN::NCP::MinSequenceID + step) % max;

    if (res < 0)
        res += max;
    return uint32_t(res + NKN::NCP::MinSequenceID);
}

inline bool SeqInBetween(uint32_t startSeq, uint32_t endSeq, uint32_t targetSeq) {
    return (startSeq <= endSeq)
           ? (startSeq <= targetSeq && targetSeq < endSeq)  // not turn round
           : (targetSeq < endSeq || startSeq <= targetSeq);    // turn round
}

// CompareSeq: Comparison of int32_t
inline int CompareSeq(uint32_t seq1, uint32_t seq2) {
    if (seq1 == seq2)
        return 0;

    if (seq1 < seq2)
        return (seq2 - seq1 < UINT32_MAX / 2) ? -1 : 1;

    return (seq1 - seq2 < UINT32_MAX / 2) ? 1 : -1;
}

inline std::string connKey(const std::string &localID, const std::string &remoteID) {
    return localID + " - " + remoteID;
}

#endif  // __NCP_UTIL_H__
