#include "ascon-hash.h"

std::vector<uint8_t> hashing(const std::string &s, const uint64_t &nbytes, std::array<uint64_t, 5> state) {
    static constexpr uint16_t A = 12;
    std::vector<uint8_t> ret;
    ret.reserve(nbytes);

    //absorb message
    auto blocks = ascon_plaintext_to_block64(s);
    for (auto i: blocks) {
        state[0] ^= i;
        ascon_permutation(state, A);
    }

    //squeeze
    for (uint64_t i = 0; i < nbytes; i += 8) {
        auto tmp = ascon_block64_to_byte_vector(state[0], (i + 7 < nbytes) ? 8 : nbytes % 8);
        ret.insert(ret.end(), tmp.begin(), tmp.end());
        ascon_permutation(state, A);
    }

    //return
    return ret;
}

std::vector<uint8_t> ascon_hash(const std::string &s) {
    static constexpr std::array<uint64_t, 5> INIT_STATE = {0xee9398aadb67f03d,
                                                           0x8bb21831c60f1002,
                                                           0xb48a92db98d5da62,
                                                           0x43189921b8f8e3e8,
                                                           0x348fa5c9d525e140};

    return hashing(s, 32, INIT_STATE);
}

std::vector<uint8_t> ascon_xof(const std::string &s, const uint64_t &nbytes) {
    static constexpr std::array<uint64_t, 5> INIT_STATE = {0xb57e273b814cd416,
                                                           0x2b51042562ae2420,
                                                           0x66a3a7768ddf2218,
                                                           0x5aad0a7a8153650c,
                                                           0x4f3e0e32539493b6};

    return hashing(s, nbytes, INIT_STATE);
}
