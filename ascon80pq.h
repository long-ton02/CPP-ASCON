#ifndef ASCON_ASCON80PQ_H
#define ASCON_ASCON80PQ_H

#include <optional>

#include "ascon-util.h"

ascon_encrypted_t ascon80pq_encrypt(const std::array<uint32_t, 5> &key, const std::array<uint32_t, 4> &nonce,
                                    const std::string &asso_data, const std::string &plaintext);

std::optional<std::string> ascon80pq_decrypt(const std::array<uint32_t, 5> &key, const std::array<uint32_t, 4> &nonce,
                                             const std::string &asso_data, const ascon_encrypted_t &msg);

#endif //ASCON_ASCON80PQ_H
