#include "ascon128.h"

ascon_encrypted_t ascon128_encrypt(std::array<uint32_t, 4> key, std::array<uint32_t, 4> nonce,
                                   const std::string &asso_data, const std::string &plaintext) {
    static constexpr uint16_t A = 12, B = 6;
    std::array<uint64_t, 5> state{};
    ascon_encrypted_t ret;
    ret.ciphertext.reserve(plaintext.length());

    //initialization
    ascon_set_init_state(state, 0x80400c0600000000, key, nonce);
    ascon_permutation(state, A);

    state[3] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[4] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];

    //process associated data
    if (asso_data.length() > 0) {
        auto blocks = ascon_plaintext_to_block64(asso_data);
        for (auto i: blocks) {
            state[0] ^= i;
            ascon_permutation(state, B);
        }
    }
    state[4] ^= 0x1;

    //process plaintext
    auto blocks = ascon_plaintext_to_block64(plaintext);
    for (auto i: blocks) {
        state[0] ^= i;
        if (i != blocks.back()) {
            append_vector(ret.ciphertext, ascon_block64_to_byte_vector(state[0]));
            ascon_permutation(state, B);
        } else {
            append_vector(ret.ciphertext, ascon_block64_to_byte_vector(state[0], plaintext.length() % 8));
        }
    }

    //finalization
    state[1] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[2] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];
    ascon_permutation(state, A);

    ret.tag[0] = state[3] ^ ((uint64_t) key[0] << 32 | (uint64_t) key[1]);
    ret.tag[1] = state[4] ^ ((uint64_t) key[2] << 32 | (uint64_t) key[3]);

    //return
    return ret;
}

std::optional<std::string>
ascon128_decrypt(std::array<uint32_t, 4> key, std::array<uint32_t, 4> nonce, const std::string &asso_data,
                 const ascon_encrypted_t &msg) {
    static constexpr uint16_t A = 12, B = 6;
    std::array<uint64_t, 5> state{};
    std::string ret;
    ret.reserve(msg.ciphertext.size());

    //initialization
    ascon_set_init_state(state, 0x80400c0600000000, key, nonce);
    ascon_permutation(state, A);

    state[3] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[4] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];

    //process associated data
    if (asso_data.length() > 0) {
        auto blocks = ascon_plaintext_to_block64(asso_data);
        for (auto i: blocks) {
            state[0] ^= i;
            ascon_permutation(state, B);
        }
    }
    state[4] ^= 0x1;

    //process ciphertext
    auto blocks = ascon_ciphertext_to_block64(msg.ciphertext);
    for (auto i: blocks) {
        uint64_t p = state[0] ^ i;
        if (i != blocks.back()) {
            ret += ascon_block64_to_string(p);
            state[0] = i;
            ascon_permutation(state, B);
        } else {
            auto last_block_size = msg.ciphertext.size() % 8;
            ret += ascon_block64_to_string(p, last_block_size);
            state[0] ^= (p & (0xFFFFFFFFFFFFFF00 << (8 * (7 - last_block_size))))
                        | ((uint64_t) 0x80 << (8 * (7 - last_block_size)));
        }
    }

    //finalization
    state[1] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[2] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];
    ascon_permutation(state, A);

    std::array<uint64_t, 2> tag = {state[3] ^ ((uint64_t) key[0] << 32 | (uint64_t) key[1]),
                                   state[4] ^ ((uint64_t) key[2] << 32 | (uint64_t) key[3])};

    //return
    if (tag == msg.tag) return ret;
    else return std::nullopt;
}

