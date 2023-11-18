#ifndef ASCON_ASCON128A_H
#define ASCON_ASCON128A_H

#include <optional>
#include "ascon-util.h"

ascon_encrypted_t ascon128a_encrypt(const ascon_key128_t &key, const ascon_nonce_t &nonce,
                                    const std::string &asso_data, const std::string &plaintext);

std::optional<std::string> ascon128a_decrypt(const ascon_key128_t &key, const ascon_nonce_t &nonce,
                                             const std::string &asso_data, const ascon_encrypted_t &msg);

#endif //ASCON_ASCON128A_H
