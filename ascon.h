#ifndef ASCON_ASCON_H
#define ASCON_ASCON_H

#include "ascon128.h"
#include "ascon128a.h"
#include "ascon80pq.h"
#include "ascon-hash.h"
#include "ascon-hasha.h"

template <class T>
typename std::enable_if<std::is_integral<T>::value, std::string>::type
to_little_endian_array(T n) {
    std::string ret;
    for (auto i = 0; i < sizeof(n); ++i) {
        ret += (n >> (i * 8)) & 0xFF;
    }
    return ret;
}

#endif //ASCON_ASCON_H
