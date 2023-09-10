#include "ascon128a.h"

ascon_encrypted_t
ascon128a_encrypt(std::array<uint32_t, 4> key, std::array<uint32_t, 4> nonce, const std::string &asso_data,
                  const std::string &plaintext) {
    static constexpr uint16_t A = 12, B = 8;
    std::array<uint64_t, 5> state{};
    ascon_encrypted_t ret;
    ret.ciphertext.reserve(plaintext.length());

    //initialization
    ascon_set_init_state(state, 0x80800c0800000000, key, nonce);
    ascon_permutation(state, A);

    state[3] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[4] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];

    //process associated data
    if (asso_data.length() > 0) {
        auto blocks = ascon_plaintext_to_block64(asso_data);
        for (uint64_t i = 0; i < blocks.size(); i += 2) {
            state[0] ^= blocks[i];
            state[1] ^= (i + 1 < blocks.size()) ? blocks[i + 1] : 0;
            ascon_permutation(state, B);
        }
    }
    state[4] ^= 0x1;

    //process plaintext
    auto blocks = ascon_plaintext_to_block64(plaintext);
    for (uint64_t i = 0; i < blocks.size(); i += 2) {
        state[0] ^= blocks[i];
        state[1] ^= (i + 1 < blocks.size()) ? blocks[i + 1] : 0;
        if (i + 2 < blocks.size()) {
            append_vector(ret.ciphertext, ascon_block64_to_byte_vector(state[0]));
            append_vector(ret.ciphertext, ascon_block64_to_byte_vector(state[1]));
            ascon_permutation(state, B);
        } else {
            auto last_block_size = plaintext.length() % 16;
            if (last_block_size >= 8) {
                append_vector(ret.ciphertext, ascon_block64_to_byte_vector(state[0]));
                append_vector(ret.ciphertext, ascon_block64_to_byte_vector(state[1], last_block_size % 8));
            } else {
                append_vector(ret.ciphertext, ascon_block64_to_byte_vector(state[0], last_block_size % 8));
            }
        }
    }

    //finalization
    state[2] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[3] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];
    ascon_permutation(state, A);

    ret.tag[0] = state[3] ^ ((uint64_t) key[0] << 32 | (uint64_t) key[1]);
    ret.tag[1] = state[4] ^ ((uint64_t) key[2] << 32 | (uint64_t) key[3]);

    //return
    return ret;
}

std::optional<std::string>
ascon128a_decrypt(std::array<uint32_t, 4> key, std::array<uint32_t, 4> nonce, const std::string &asso_data,
                  const ascon_encrypted_t &msg) {
    static constexpr uint16_t A = 12, B = 8;
    std::array<uint64_t, 5> state{};
    std::string ret;
    ret.reserve(msg.ciphertext.size());

    //initialization
    ascon_set_init_state(state, 0x80800c0800000000, key, nonce);
    ascon_permutation(state, A);

    state[3] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[4] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];

    //process associated data
    if (asso_data.length() > 0) {
        auto blocks = ascon_plaintext_to_block64(asso_data);
        for (uint64_t i = 0; i < blocks.size(); i += 2) {
            state[0] ^= blocks[i];
            state[1] ^= (i + 1 < blocks.size()) ? blocks[i + 1] : 0;
            ascon_permutation(state, B);
        }
    }
    state[4] ^= 0x1;

    //process ciphertext
    auto blocks = ascon_ciphertext_to_block64(msg.ciphertext);
    for (uint64_t i = 0; i < blocks.size(); i += 2) {
        uint64_t p[2] = {state[0] ^ blocks[i], state[1] ^ ((i + 1 < blocks.size()) ? blocks[i + 1] : 0)};
        if (i + 2 < blocks.size()) {
            ret += ascon_block64_to_string(p[0]) + ascon_block64_to_string(p[1]);
            state[0] = blocks[i];
            state[1] = blocks[i + 1];
            ascon_permutation(state, B);
        } else {
            auto last_block_size = msg.ciphertext.size() % 16;
            if (last_block_size >= 8) {
                ret += ascon_block64_to_string(p[0]) + ascon_block64_to_string(p[1], last_block_size % 8);
                state[0] ^= p[0];
                state[1] ^= (p[1] & (0xFFFFFFFFFFFFFF00 << (8 * (7 - last_block_size % 8))))
                            | ((uint64_t) 0x80 << (8 * (7 - last_block_size % 8)));
            } else {
                ret += ascon_block64_to_string(p[0], last_block_size % 8);
                state[0] ^= (p[0] & (0xFFFFFFFFFFFFFF00 << (8 * (7 - last_block_size % 8))))
                            | ((uint64_t) 0x80 << (8 * (7 - last_block_size % 8)));
            }
        }
    }

    //finalization
    state[2] ^= (uint64_t) key[0] << 32 | (uint64_t) key[1];
    state[3] ^= (uint64_t) key[2] << 32 | (uint64_t) key[3];
    ascon_permutation(state, A);

    std::array<uint64_t, 2> tag = {state[3] ^ ((uint64_t) key[0] << 32 | (uint64_t) key[1]),
                                   state[4] ^ ((uint64_t) key[2] << 32 | (uint64_t) key[3])};

    //return
    if (tag == msg.tag) return ret;
    else return std::nullopt;
}
