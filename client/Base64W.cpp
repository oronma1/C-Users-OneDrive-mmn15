#pragma once
#include "Base64W.h"
#include <cryptlib.h>
#include <base64.h>
#include <filters.h>
#include <string>
#include <array>

std::string Base64W::encode(const std::string& str)
{
    std::string encoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource

    return encoded;
}

std::string Base64W::decode(const std::string& str)
{
    std::string decoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        ) // Base64Decoder
    ); // StringSource

    return decoded;
}

std::string Base64W::encode(const std::array<uint8_t, 160>& data)
{
    std::string encoded;
    // Convert std::array<uint8_t, 160> to a string-like structure
    CryptoPP::ArraySource as(data.data(), data.size(), true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        ) // Base64Encoder
    ); // ArraySource

    return encoded;
}