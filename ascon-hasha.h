#ifndef ASCON_ASCON_HASHA_H
#define ASCON_ASCON_HASHA_H

#include "ascon-util.h"

std::vector<uint8_t> ascon_hasha(const std::string &s);

std::vector<uint8_t> ascon_xofa(const std::string &s, const uint64_t &nbytes);

#endif //ASCON_ASCON_HASHA_H
