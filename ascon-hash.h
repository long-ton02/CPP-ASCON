#ifndef ASCON_ASCON_HASH_H
#define ASCON_ASCON_HASH_H

#include "ascon-util.h"

std::vector<uint8_t> ascon_hash(const std::string &s);

std::vector<uint8_t> ascon_xof(const std::string &s, const uint64_t &nbytes);

#endif //ASCON_ASCON_HASH_H
