#include "ascon-util.h"

constexpr uint64_t ROUND_CONSTANTS[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
                                          0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

constexpr uint64_t right_rotate(uint64_t n, uint16_t r) {
    return (n >> r) | (n << (64 - r));
}

constexpr uint8_t get_byte(uint64_t n, uint16_t r) {
    return (n >> (8 * (7 - r))) & 0xFF;
}

void ascon_permutation(std::array<uint64_t, 5> &state, uint16_t rounds) {
    std::array<uint64_t, 5> t{};

    while (rounds) {
        //Addition of Constant
        state[2] ^= ROUND_CONSTANTS[12 - rounds];

        //Substitution layer
        state[0] ^= state[4];
        state[4] ^= state[3];
        state[2] ^= state[1];

        for (auto i = 0; i < 5; ++i) {
            t[i] = ~state[i] & state[(i + 1) % 5];
        }

        for (auto i = 0; i < 5; ++i) {
            state[i] ^= t[(i + 1) % 5];
        }

        state[1] ^= state[0];
        state[0] ^= state[4];
        state[3] ^= state[2];

        state[2] = ~state[2];

        //Linear Diffusion layer
        state[0] ^= right_rotate(state[0], 19) ^ right_rotate(state[0], 28);
        state[1] ^= right_rotate(state[1], 61) ^ right_rotate(state[1], 39);
        state[2] ^= right_rotate(state[2], 1) ^ right_rotate(state[2], 6);
        state[3] ^= right_rotate(state[3], 10) ^ right_rotate(state[3], 17);
        state[4] ^= right_rotate(state[4], 7) ^ right_rotate(state[4], 41);

        //End round
        --rounds;
    }
}

void ascon_set_init_state(std::array<uint64_t, 5> &state, const uint64_t &iv, const std::array<uint32_t, 4> &key,
                          const std::array<uint32_t, 4> &nonce) {
    state[0] = iv;
    state[1] = (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[2] = (uint64_t) key[2] << 32 | (uint64_t) key[3];
    state[3] = (uint64_t) nonce[0] << 32 | (uint64_t) nonce[1];
    state[4] = (uint64_t) nonce[2] << 32 | (uint64_t) nonce[3];
}

void ascon_set_init_state(std::array<uint64_t, 5> &state, const uint32_t &iv, const std::array<uint32_t, 5> &key,
                          const std::array<uint32_t, 4> &nonce) {
    state[0] = (uint64_t) iv << 32 | (uint64_t) key[0];
    state[1] = (uint64_t) key[1] << 32 | (uint64_t) key[2];
    state[2] = (uint64_t) key[3] << 32 | (uint64_t) key[4];
    state[3] = (uint64_t) nonce[0] << 32 | (uint64_t) nonce[1];
    state[4] = (uint64_t) nonce[2] << 32 | (uint64_t) nonce[3];
}

std::vector<uint64_t> ascon_plaintext_to_block64(const std::string &s) {
    std::vector<uint64_t> ret;
    ret.reserve((s.length() + 7) / 8);
    for (auto i = 0; i <= s.length(); i += 8) {
        uint64_t block = 0;
        for (auto j = 0; j < 8; ++j) {
            block = block << 8;
            if (i + j < s.length()) block |= (uint8_t) s[i + j];
            else if (i + j == s.length()) block |= 0x80;
        }
        ret.push_back(block);
    }
    return ret;
}

std::vector<uint64_t> ascon_ciphertext_to_block64(const std::vector<uint8_t> &s) {
    std::vector<uint64_t> ret;
    ret.reserve((s.size() + 7) / 8);
    for (auto i = 0; i <= s.size(); i += 8) {
        uint64_t block = 0;
        for (auto j = 0; j < 8; ++j) {
            block = (block << 8) | ((i + j < s.size()) ? s[i + j] : 0);
        }
        ret.push_back(block);
    }
    return ret;
}

std::string ascon_block64_to_string(const uint64_t &block, const uint16_t &count) {
    if (count > 8) throw std::out_of_range("Argument \"count\" exceed 8");

    std::string ret;
    ret.reserve(count);
    for (uint16_t j = 0; j < count; ++j) {
        ret.push_back((char) get_byte(block, j));
    }
    return ret;
}

std::vector<uint8_t> ascon_block64_to_byte_vector(const uint64_t &block, const uint16_t &count) {
    if (count > 8) throw std::out_of_range("Argument \"count\" exceed 8");

    std::vector<uint8_t> ret;
    ret.reserve(count);
    for (uint16_t j = 0; j < count; ++j) {
        ret.push_back(get_byte(block, j));
    }
    return ret;
}
