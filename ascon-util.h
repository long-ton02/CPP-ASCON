#ifndef ASCON_ASCON_UTIL_H
#define ASCON_ASCON_UTIL_H

#include <vector>
#include <array>
#include <cstdint>
#include <string>
#include <stdexcept>

struct ascon_encrypted_t {
    std::vector<uint8_t> ciphertext;
    std::array<uint64_t, 2> tag;
};

void ascon_set_init_state(std::array<uint64_t, 5> &state, const uint64_t &iv,
                          const std::array<uint32_t, 4> &key, const std::array<uint32_t, 4> &nonce);

void ascon_set_init_state(std::array<uint64_t, 5> &state, const uint32_t &iv,
                          const std::array<uint32_t, 5> &key, const std::array<uint32_t, 4> &nonce);

void ascon_permutation(std::array<uint64_t, 5> &state, uint16_t rounds);

std::vector<uint64_t> ascon_plaintext_to_block64(const std::string &s);

std::vector<uint64_t> ascon_ciphertext_to_block64(const std::vector<uint8_t> &s);

std::string ascon_block64_to_string(uint64_t block, uint16_t count = 8);

std::vector<uint8_t> ascon_block64_to_byte_vector(uint64_t block, uint16_t count = 8);

#endif //ASCON_ASCON_UTIL_H
