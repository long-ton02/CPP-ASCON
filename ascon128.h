#ifndef ASCON_ASCON128_H
#define ASCON_ASCON128_H

#include <optional>

#include "ascon-util.h"

ascon_encrypted_t ascon128_encrypt(std::array<uint32_t, 4> key, std::array<uint32_t, 4> nonce,
                                   const std::string &asso_data, const std::string &plaintext);

std::optional<std::string> ascon128_decrypt(std::array<uint32_t, 4> key, std::array<uint32_t, 4> nonce,
                                            const std::string &asso_data, const ascon_encrypted_t &msg);

#endif //ASCON_ASCON128_H