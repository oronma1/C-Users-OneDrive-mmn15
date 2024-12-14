#pragma once
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <hex.h>
#include <cstdlib>
#include <cstring>
#include <boost/asio.hpp>
#include <array>
#include <vector>
#include "Base64W.h"

class RSACipher {
public:
    RSACipher();

    std::string encrypt(const std::string& data);
    std::string decrypt(const uint8_t* encryptedBinary, size_t length);

    std::string getPublicKeyDER() const;
    std::string getPrivateKey() const;

    void savePrivateKeyDER(const std::string& filename) const;
    void loadPrivateKeyDER(const std::string& filename);

    void generatePublicKeyFromPrivate();

private:
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
};

