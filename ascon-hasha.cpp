#include "ascon-hash.h"

std::vector<uint8_t> hashing_a(const std::string &s, const uint64_t &nbytes, ascon_state_t state) {
    static constexpr uint16_t A = 12;
    static constexpr uint16_t B = 8;
    std::vector<uint8_t> ret;
    ret.reserve(nbytes);

    //absorb message
    auto blocks = ascon_plaintext_to_block64(s);
    for (auto it = blocks.begin(); it != blocks.end(); ++it) {
        state[0] ^= *it;
        if (it + 1 != blocks.end()) ascon_permutation(state, B);
    }

    //squeeze
    ascon_permutation(state, A);
    for (uint64_t i = 0; i < nbytes; i += 8) {
        append_vector(ret, ascon_block64_to_byte_vector(state[0], (i + 7 < nbytes) ? 8 : nbytes % 8));
        ascon_permutation(state, B);
    }

    //return
    return ret;
}

std::vector<uint8_t> ascon_hasha(const std::string &s) {
    static constexpr ascon_state_t INIT_STATE = {0x01470194fc6528a6,
                                                 0x738ec38ac0adffa7,
                                                 0x2ec8e3296c76384c,
                                                 0xd6f6a54d7f52377d,
                                                 0xa13c42a223be8d87};

    return hashing_a(s, 32, INIT_STATE);
}

std::vector<uint8_t> ascon_xofa(const std::string &s, const uint64_t &nbytes) {
    static constexpr ascon_state_t INIT_STATE = {0x44906568b77b9832,
                                                 0xcd8d6cae53455532,
                                                 0xf7b5212756422129,
                                                 0x246885e1de0d225b,
                                                 0xa8cb5ce33449973f};

    return hashing_a(s, nbytes, INIT_STATE);
}

