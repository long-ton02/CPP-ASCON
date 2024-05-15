#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include "ascon.h"

#define TEST_ENCDEC

static const std::string UNENCRYPTED_FILE = "li.txt";
static const std::string ENCRYPTED_FILE = "li-encrypted.txt";
static const std::string DECRYPTED_FILE = "li-decrypted.txt";

#ifdef TEST_HASH

int main() {
    std::string str = "The quick brown fox jumps over the lazy dog.";
    auto hash = ascon_hash(str);
    for (auto it = hash.begin(); it != hash.end(); ++it) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (uint32_t) *it << ((it + 1 != hash.end()) ? ':' : '\n');
    }

    return 0;
}

#endif


#ifdef TEST_ENCDEC

int main() {
    std::fstream fs;
    decltype(std::chrono::high_resolution_clock::now()) start, end;

    fs.open(UNENCRYPTED_FILE);
    if (!fs.is_open()) return -1;
    std::string plaintext((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    fs.close();

    std::string associated_data;
    ascon_key160_t key = {0xC3C3C3C3, 0xAAAA1337, 0x88111188, 0xDEADDEED, 0xBEEFCAFE};
    ascon_nonce_t nonce = {0xA2052221, 0xA2052153, 0xFEDCBA98, 0x76543210};

    start = std::chrono::high_resolution_clock::now();
    auto m = ascon80pq_encrypt(key, nonce, associated_data, plaintext);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Encryption time: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
              << "ms\n";

    std::cout << "Tag (hex): ";
    for (auto i: m.tag) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << i;
    }
    fs.open(ENCRYPTED_FILE);
    if (!fs.is_open()) return -1;
    for (auto it = m.ciphertext.begin(); it != m.ciphertext.end(); ++it) {
        fs << std::hex << std::setw(2) << std::setfill('0')
            << (uint16_t) *it << ((it + 1 != m.ciphertext.end()) ? ":" : "");
    }
    fs.close();
    std::cout << "\n\n" << std::resetiosflags(std::ios::hex);

    fs.open(ENCRYPTED_FILE);
    if (!fs.is_open()) return -1;
    ascon_encrypted_t msg;
    std::string tmp;
    msg.tag = m.tag;
    while (std::getline(fs, tmp, ':')) {
        msg.ciphertext.push_back((uint8_t) std::stoul(tmp, nullptr, 16));
    }
    fs.close();

    start = std::chrono::high_resolution_clock::now();
    auto decrypted_msg = ascon80pq_decrypt(key, nonce, associated_data, msg);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Decryption time: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
              << "ms\n";

    fs.open(DECRYPTED_FILE);
    if (!fs.is_open()) return -1;
    fs << ((decrypted_msg) ? decrypted_msg->data() : "Decryption failed");
    fs.close();

    return 0;
}

#endif


#ifdef DEV

int main() {
    std::fstream fs;
    decltype(std::chrono::high_resolution_clock::now()) start, end;

    fs.open(UNENCRYPTED_FILE);
    if (!fs.is_open()) return -1;
    std::string plaintext((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    fs.close();

    start = std::chrono::high_resolution_clock::now();
    ascon_plaintext_to_block64(plaintext);
    end = std::chrono::high_resolution_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms";
    return 0;
}

#endif


#ifdef TEST

int main() {
    ascon_key128_t key = {0, 0, 0, 0};
    ascon_nonce_t nonce = {0, 0, 0, 0};

    auto i = ascon128_encrypt(key, nonce, "", "AAAAAAA");

    for (auto byte : i.ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint32_t)byte;
    }
    std::cout << std::endl << "Tag: " << std::hex << std::setw(8) << std::setfill('0') << i.tag[0] << i.tag[1] << std::endl;
}

#endif
