#pragma once
#include <iostream>
#include <cstring>
#include <cstdint>



enum size
{
    CLIENT_ID_SIZE = 16,
    AES_KEY_SIZE = 16,
    FILE_NAME_SIZE = 255,
    AES_KEY_ENCRYPTED_SIZE = 128
};

enum ResponseCode
{
    REGISTRATION_SUCCESS = 1600,
    REGISTRATION_FAILED = 1601,
    SEND_AES_KEY = 1602,
    VALID_FILE_CRC = 1603,
    CONFIRM_MSG = 1604,
    RECONNECTION_CONFIRMED_RESEND_AES_KEY = 1605,
    RECONNECT_DENIED = 1606,
};

class Response
{
public:
#pragma pack(push, 1)
    struct ResponseHeader {
        uint8_t version;       // 1 byte
        uint16_t code;         // 2 bytes
        uint32_t payloadSize;  // 4 bytes
    } header;

    struct ResponsePacket {
        ResponseHeader header;
        uint8_t ClientID[CLIENT_ID_SIZE];  // Optional, 16 bytes if present
        uint8_t symmetricKeyEncrypted[AES_KEY_ENCRYPTED_SIZE];  // Optional, only if payloadSize indicates it's present
        bool hasClientID = false;  // To track if ClientID is present
        bool hasSymmetricKey = false;  // To track if SymmetricKey is present
    } packet;

    struct ResponseFilePacket {
        ResponseHeader header;
        uint8_t ClientID[CLIENT_ID_SIZE];   // Optional, 16 bytes if present
        uint32_t ContentSize;
        uint8_t FileName[FILE_NAME_SIZE];
        uint32_t CkSum;         // Optional, only if payloadSize indicates it's present
    } payload;

    struct ResponseCRC {
        ResponseHeader header;
        uint8_t ClientID[CLIENT_ID_SIZE];  // Optional, only if payloadSize indicates it's present
    } payloadCrc;
#pragma pack(pop)

    ResponsePacket Deserialize(const uint8_t* buffer, size_t bufferSize);
    ResponseFilePacket DeserializeFile(const uint8_t* buffer, size_t bufferSize);
    ResponseCRC DeserializeCRC(const uint8_t* buffer, size_t bufferSize);

    void printResponseHeader();
    void print();
    void printp();
    void printPayloadCrc();


};

