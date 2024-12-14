#pragma once
#include "RSACipher.h"
#include <iostream>

// Constructor
RSACipher::RSACipher() {
    privateKey.Initialize(rng, 1024);
    publicKey.AssignFrom(privateKey);
   
}

// Encrypt a string using the public key
std::string RSACipher::encrypt(const std::string& data) {
    std::string ciphertext;

    // Create RSA encryptor using the public key
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    // Encrypt the data
    CryptoPP::StringSource ss(data, true,
        new CryptoPP::PK_EncryptorFilter(rng, encryptor,
            new CryptoPP::StringSink(ciphertext)
        ) // PK_EncryptorFilter
    ); // StringSource

    return ciphertext;
}

// Decrypt a message using the private key
std::string RSACipher::decrypt(const uint8_t* encryptedBinary, size_t length) {
    std::string decrypted;

    // Step 1: Decrypt the binary data using RSA and the private key
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    CryptoPP::StringSource ss(encryptedBinary, length, true,
        new CryptoPP::PK_DecryptorFilter(rng, decryptor,
            new CryptoPP::StringSink(decrypted)));

    return decrypted;
}

// Get the public key in DER format
std::string RSACipher::getPublicKeyDER() const {
    std::string key;
    CryptoPP::StringSink ss(key);
    publicKey.DEREncode(ss);  // Export the public key in DER format
    return key;
}

// Get the private key as a string
std::string RSACipher::getPrivateKey() const {
    std::string key;
    CryptoPP::StringSink ss(key);
    privateKey.Save(ss);
    return key;
}

// Save the private key in DER format
void RSACipher::savePrivateKeyDER(const std::string& filename) const {
    CryptoPP::FileSink file(filename.c_str());
    privateKey.DEREncode(file);  // Save the key in DER format
}

// Load the private key from a DER file
void RSACipher::loadPrivateKeyDER(const std::string& filename) {
    CryptoPP::FileSource file(filename.c_str(), true);  // true means pump all data immediately
    privateKey.BERDecode(file);  // BER and DER are compatible for RSA keys
}

// Generate the public key from the private key
void RSACipher::generatePublicKeyFromPrivate() {
    if (privateKey.Validate(rng, 3)) {
        publicKey.AssignFrom(privateKey);  // Generates the public key from the private key
    }
    else {
        throw std::runtime_error("Invalid private key");
    }
}
