#pragma once
#include "AESCipher.h"

#include <modes.h>
#include <aes.h>
#include <filters.h>

#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step


unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
    for (size_t i = 0; i < length; i += sizeof(unsigned int))
        _rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
    return buffer;
}

AESWrapper::AESWrapper()
{
    GenerateKey(_key, DEFAULT_KEYLENGTH);
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
    if (length != DEFAULT_KEYLENGTH)
        throw std::length_error("key length must be 16 bytes");
    memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}
// Constructor when the key is provided as a string containing bytes
AESWrapper::AESWrapper(const std::string& key) {
    if (key.size() != DEFAULT_KEYLENGTH) {
        throw std::length_error("Key length must be 16 bytes");
    }
    memcpy_s(_key, DEFAULT_KEYLENGTH, key.data(), DEFAULT_KEYLENGTH);  // Copy the string bytes into _key
}

AESWrapper::~AESWrapper()
{
}

const unsigned char* AESWrapper::getKey() const
{
    return _key;
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

    CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    std::string cipher;
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher),CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
    stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
    stfEncryptor.MessageEnd();

    return cipher;
}


std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

    CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    std::string decrypted;
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted),CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
    stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
    stfDecryptor.MessageEnd();

    return decrypted;
}
