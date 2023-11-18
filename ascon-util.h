#ifndef ASCON_ASCON_UTIL_H
#define ASCON_ASCON_UTIL_H

#include <vector>
#include <array>
#include <cstdint>
#include <string>
#include <stdexcept>

typedef std::array<uint64_t, 5> ascon_state_t;
typedef std::array<uint32_t, 4> ascon_key128_t;
typedef std::array<uint32_t, 5> ascon_key160_t;
typedef std::array<uint32_t, 4> ascon_nonce_t;
typedef std::array<uint64_t, 2> ascon_tag_t;

struct ascon_encrypted_t {
    std::vector<uint8_t> ciphertext;
    ascon_tag_t tag;
};

void ascon_set_init_state(ascon_state_t &state, const uint64_t &iv,
                          const ascon_key128_t &key, const ascon_nonce_t &nonce);

void ascon_set_init_state(ascon_state_t &state, const uint32_t &iv,
                          const ascon_key160_t &key, const ascon_nonce_t &nonce);

void ascon_permutation(ascon_state_t &state, uint16_t rounds);

std::vector<uint64_t> ascon_plaintext_to_block64(const std::string &s);

std::vector<uint64_t> ascon_ciphertext_to_block64(const std::vector<uint8_t> &s);

std::string ascon_block64_to_string(const uint64_t &block, const uint16_t &count = 8);

std::vector<uint8_t> ascon_block64_to_byte_vector(const uint64_t &block, const uint16_t &count = 8);

template<class T>
inline void append_vector(std::vector<T> &des, const std::vector<T> &src) {
    des.insert(des.end(), src.begin(), src.end());
}

#endif //ASCON_ASCON_UTIL_H
