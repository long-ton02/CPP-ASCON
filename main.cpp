#include <iostream>
#include <iomanip>
#include <fstream>
#include <iterator>
#include <getopt.h>
#include <map>
#include "ascon.h"

static const char* short_options = "edsEDSk:n:a:i:t:o:h";
static struct option long_options[] = {
        {"encrypt",         no_argument,        nullptr,'e'},
        {"decrypt",         no_argument,        nullptr,'d'},
        {"hash",            no_argument,        nullptr,'s'},
        {"encrypt-a",       no_argument,        nullptr,'E'},
        {"decrypt-a",       no_argument,        nullptr,'D'},
        {"hash-a",          no_argument,        nullptr,'S'},
        {"key",             required_argument,  nullptr,'k'},
        {"nonce",           required_argument,  nullptr,'n'},
        {"associated-data", required_argument,  nullptr,'a'},
        {"input",           required_argument,  nullptr,'i'},
        {"output",          required_argument,  nullptr,'o'},
        {"tag",             required_argument,  nullptr,'t'},
        {"help",            no_argument,        nullptr,'h'},
        {nullptr,           0,                  nullptr,0}
};


void print_help() {
    std::cout << "Usage:    ASCON\r\n"
                 "          -e|--encrypt|-d|--decrypt|-E|--encrypt-a|-D|--decrypt-a\r\n"
                 "          -k|--key                <key_path>\r\n"
                 "          -n|--nonce              <nonce_path>\r\n"
                 "          -a|--associated-data    <ad_path>\r\n"
                 "          -t|--tag                <tag_path>\r\n"
                 "          -i|--input              <input_path>\r\n"
                 "          -o|--output             <output_path>\r\n"
                 "\r\n"
                 "          ASCON\r\n"
                 "          -s|--hash|-S|--hash-a\r\n"
                 "          -i|--input              <input_path>\r\n"
                 "          -o|--output             <output_path>\r\n";
}

template <class T>
typename std::enable_if<std::is_integral<T>::value,std::string>::type
to_big_endian_array(T n){
    std::string ret;
    ret.reserve(sizeof(n));
    for (auto i = 0; i < sizeof(n); ++i){
        ret += (n >> ((sizeof(n) - 1 - i) * 8)) & 0xFF;
    }
    return ret;
}

void encrypt(const std::string& k_path, const std::string& n_path, const std::string& a_path,
             const std::string& p_path, const std::string& output_cipher_path, const std::string& output_tag_path,
             bool variant){
    // buffer
    char buffer[4];

    // Read the plaintext from file
    std::ifstream in_file(p_path, std::ios_base::binary);
    if (!in_file.is_open()) {
        std::cerr << "Error opening file: " << p_path << std::endl;
        return;
    }

    std::string plaintext((std::istreambuf_iterator<char>(in_file)), std::istreambuf_iterator<char>());

    in_file.close();

    // Get ad
    std::ifstream ad_file(a_path, std::ios_base::binary);
    if (!ad_file.is_open()) {
        std::cerr << "Error opening file: " << a_path << std::endl;
        return;
    }

    std::string associated_data((std::istreambuf_iterator<char>(ad_file)), std::istreambuf_iterator<char>());

    ad_file.close();

    // Fetch the key
    std::ifstream key_file(k_path, std::ios_base::binary);
    if (!key_file.is_open()) {
        std::cerr << "Error opening file: " << k_path << std::endl;
        return;
    }

    ascon_key128_t key = {};
    for (auto i = 0; i < 4; ++i) {
        key_file.read(buffer, 4);
        for (auto byte : buffer) {
            key[i] = (key[i] << 8) | (uint8_t)byte;
        }
    }

    key_file.close();

    // Fetch the nonce
    std::ifstream nonce_file(n_path, std::ios_base::binary);
    if (!nonce_file.is_open()) {
        std::cerr << "Error opening file: " << n_path << std::endl;
        return;
    }

    ascon_nonce_t nonce = {};
    for (auto i = 0; i < 4; ++i) {
        nonce_file.read(buffer, 4);
        for (auto byte : buffer) {
            nonce[i] = (nonce[i] << 8) | (uint8_t)byte;
        }
    }

    nonce_file.close();

    // Invoke ascon128_encrypt()
    auto m = variant ? ascon128a_encrypt(key, nonce, associated_data, plaintext)
                                        : ascon128_encrypt(key, nonce, associated_data, plaintext);

    // get ciphertext and write it to file
    std::remove(output_cipher_path.c_str());
    std::ofstream enc_byte_file(output_cipher_path, std::ios_base::binary | std::ios_base::app);

    for (auto i: m.ciphertext) {
        enc_byte_file.write(to_big_endian_array(i).c_str(), sizeof(i));
    }

    enc_byte_file.close();

    // get tag and write it to file
    std::remove(output_tag_path.c_str());

    std::ofstream tag_file(output_tag_path, std::ios_base::binary | std::ios_base::app);

    for (auto i: m.tag) {
        tag_file.write(to_big_endian_array(i).c_str(), sizeof(i));
    }

    tag_file.close();
}

void decrypt(const std::string& k_path, const std::string& n_path, const std::string& a_path,
             const std::string& c_path, const std::string& t_path, const std::string& output_path,
             bool variant){
    // buffer
    char buffer[4];

    // Get ad
    std::ifstream ad_file(a_path, std::ios_base::binary);
    if (!ad_file.is_open()) {
        std::cerr << "Error opening file: " << a_path << std::endl;
        return;
    }

    std::string associated_data((std::istreambuf_iterator<char>(ad_file)), std::istreambuf_iterator<char>());

    ad_file.close();

    // Fetch the key
    std::ifstream key_file(k_path, std::ios_base::binary);
    if (!key_file.is_open()) {
        std::cerr << "Error opening file: " << k_path << std::endl;
        return;
    }

    ascon_key128_t key = {};
    for (auto i = 0; i < 4; ++i) {
        key_file.read(buffer, 4);
        for (auto byte : buffer) {
            key[i] = (key[i] << 8) | (uint8_t)byte;
        }
    }

    key_file.close();

    // Fetch the nonce
    std::ifstream nonce_file(n_path, std::ios_base::binary);
    if (!nonce_file.is_open()) {
        std::cerr << "Error opening file: " << n_path << std::endl;
        return;
    }

    ascon_nonce_t nonce = {};
    for (auto i = 0; i < 4; ++i) {
        nonce_file.read(buffer, 4);
        for (auto byte : buffer) {
            nonce[i] = (nonce[i] << 8) | (uint8_t)byte;
        }
    }

    nonce_file.close();

    // Get tag & ciphertext
    ascon_encrypted_t encrypt_msg;

    // Fetch tag
    std::ifstream tag_file(t_path, std::ios_base::binary);
    if (!tag_file.is_open()) {
        std::cerr << "Error opening file: " << t_path << std::endl;
        return;
    }

    for (auto i = 0; i < 4; ++i) {
        tag_file.read(buffer, 4);
        for (auto byte : buffer) {
            encrypt_msg.tag[i / 2] = (encrypt_msg.tag[i / 2] << 8) | (uint8_t)byte;
        }
    }

    tag_file.close();

    // Fetch ciphertext
    std::ifstream enc_byte_file(c_path, std::ios_base::binary);
    if (!enc_byte_file.is_open()) {
        std::cerr << "Error opening file: " << c_path << std::endl;
        return;
    }

    encrypt_msg.ciphertext.insert(encrypt_msg.ciphertext.begin(), std::istreambuf_iterator<char>(enc_byte_file), std::istreambuf_iterator<char>());

    enc_byte_file.close();

    // Invoke ascon128_decrypt() to get original text and write it to file
    std::remove(output_path.c_str());
    std::ofstream decrypt_file(output_path, std::ios_base::binary | std::ios_base::app);

    auto decrypt_m = variant ? ascon128a_decrypt(key, nonce, associated_data, encrypt_msg)
                                                : ascon128_decrypt(key, nonce, associated_data, encrypt_msg);
    if (decrypt_m){
        std::cout << "Successfully decrypted data" << std::endl;
        decrypt_file.write(decrypt_m.value().c_str(), static_cast<std::streamsize>(decrypt_m.value().length()));
    } else {
        std::cout << "Failed to decrypt data" << std::endl;
    }

    decrypt_file.close();
}

void hash(const std::string& i_path, const std::string& o_path, bool variant) {
    // Get input
    std::ifstream in_file(i_path, std::ios_base::binary);
    if (!in_file.is_open()) {
        std::cerr << "Error opening file: " << i_path << std::endl;
        return;
    }

    std::string input((std::istreambuf_iterator<char>(in_file)), std::istreambuf_iterator<char>());

    in_file.close();

    // Hash
    auto h = variant ? ascon_hasha(input) : ascon_hash(input);

    // Write to output
    std::remove(o_path.c_str());
    std::ofstream out_file(o_path, std::ios_base::binary | std::ios_base::app);

    for (const auto& i : h) {
        out_file.write((const char *)&i, 1);
    }

    out_file.close();
}

static inline bool check_invalid_filepath() {
    if (optarg[0] == '-') {
        std::cerr << "Invalid argument" << std::endl;
        return true;
    } else return false;
}

int main(int argc, char** argv) {
    typedef std::pair<std::string, std::optional<std::string>> map_type;

    std::map<std::string, std::optional<std::string>> parsed;
    bool variant = false;
    bool enc_mode, dec_mode, hash_mode;

    while (true) {
        const auto opt = getopt_long(argc, argv, short_options, long_options, nullptr);

        if (opt == -1) break;

        switch (opt)
        {
            case 'e':
            case 'E':
                parsed.insert(map_type("enc", std::nullopt));
                variant = opt == 'E';
                break;
            case 'd':
            case 'D':
                parsed.insert(map_type("dec", std::nullopt));
                variant = opt == 'D';
                break;
            case 's':
            case 'S':
                parsed.insert(map_type("hash", std::nullopt));
                variant = opt == 'S';
                break;
            case 'k':
                if (check_invalid_filepath()) return 1;
                parsed.insert(map_type("key", optarg));
                break;
            case 'n':
                if (check_invalid_filepath()) return 1;
                parsed.insert(map_type("nonce", optarg));
                break;
            case 'a':
                if (check_invalid_filepath()) return 1;
                parsed.insert(map_type("ad", optarg));
                break;
            case 'i':
                if (check_invalid_filepath()) return 1;
                parsed.insert(map_type("in", optarg));
                break;
            case 'o':
                if (check_invalid_filepath()) return 1;
                parsed.insert(map_type("out", optarg));
                break;
            case 't':
                if (check_invalid_filepath()) return 1;
                parsed.insert(map_type("tag", optarg));
                break;

            case 'h':
                print_help();
                return 0;

            default:
                return 1;
        }
    }

    if (parsed.empty()) {
        print_help();
        return 0;
    }

    enc_mode = parsed.count("enc");
    dec_mode = parsed.count("dec");
    hash_mode = parsed.count("hash");
    if (enc_mode + dec_mode + hash_mode > 1) {
        std::cerr << "Too many commands" << std::endl;
        return 1;
    }
    if (enc_mode + dec_mode + hash_mode == 0){
        std::cerr << "No action specified" << std::endl;
        return 1;
    }

    std::string input_path;
    if (parsed.count("in")) {
        input_path = parsed["in"].value();
    } else {
        std::cerr << "No input file specified" << std::endl;
        return 1;
    }

    std::string output_path;
    if (parsed.count("out")) {
        output_path = parsed["out"].value();
    } else {
        std::cerr << "No output file specified" << std::endl;
        return 1;
    }

    if (hash_mode) {
        hash(input_path, output_path, variant);
    } else {
        std::string key_path;
        if (parsed.count("key")) {
            key_path = parsed["key"].value();
        } else {
            std::cerr << "No key file specified" << std::endl;
            return 1;
        }

        std::string nonce_path;
        if (parsed.count("nonce")) {
            nonce_path = parsed["nonce"].value();
        } else {
            std::cerr << "No nonce file specified" << std::endl;
            return 1;
        }

        std::string ad_path;
        if (parsed.count("ad")) {
            ad_path = parsed["ad"].value();
        } else {
            std::cerr << "No AD file specified" << std::endl;
            return 1;
        }

        std::string tag_path;
        if (parsed.count("tag")) {
            tag_path = parsed["tag"].value();
        } else {
            std::cerr << "No tag file specified" << std::endl;
            return 1;
        }

        if (enc_mode) {
            encrypt(key_path, nonce_path, ad_path, input_path, output_path, tag_path, variant);
        } else if (dec_mode) {
            decrypt(key_path, nonce_path, ad_path, input_path, tag_path, output_path, variant);
        }
    }

    return 0;
}

