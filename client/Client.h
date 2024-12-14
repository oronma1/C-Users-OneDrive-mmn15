#pragma once
#include <string>
#include <vector>
#include <rsa.h>
#include "AESCipher.h"
#include "socket.h"
#include "Request.h"
#include "Response.h"
#include "RSACipher.h"

#define MAX_TRY 3


class Client {
public:
    Client();  // Constructor

    // Protocol start
    void start_protocol();

    // File operations
    bool file_exists();
    bool registration();
    void reconnect();
    void send_public_key();
    bool receive_AES_key();
    void send_file();
    bool CRC_stat(unsigned int num_of_try);
    void responseCRC();

    // File encryption
    std::string encryptFile(const std::string& filePath, AESWrapper& aes);
    std::size_t getFileSize(const std::string& filePath);

    // Utility
    void setClientID(const Response& response);
    void printAESkey(const std::string& decryptedMessage);
    unsigned int getCrcResult(const std::string& result);

private:
    // Sensitive data handling
    void SecureZeroMemory(uint8_t* data, size_t size);

    // Member variables
    std::string name;
    std::string filePath;
    std::string clientID;
    Socket ss;
    std::string aesKey;
    RSACipher rsa;
    std::string fileName;
};
