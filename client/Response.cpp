#pragma once
#include "Response.h"

// Deserialize function to unpack the received data for ResponsePacket
Response::ResponsePacket Response::Deserialize(const uint8_t* buffer, size_t bufferSize) {
    ResponsePacket packet;

    if (bufferSize < sizeof(ResponseHeader)) {
        std::cerr << "Buffer too small to contain the header!" << std::endl;
        exit(1);
    }

    std::memcpy(&packet.header, buffer, sizeof(ResponseHeader));

    size_t currentPosition = sizeof(ResponseHeader);

    if (packet.header.payloadSize >= CLIENT_ID_SIZE && currentPosition + CLIENT_ID_SIZE <= bufferSize) {
        std::memcpy(packet.ClientID, buffer + currentPosition, CLIENT_ID_SIZE);
        packet.hasClientID = true;
        currentPosition += CLIENT_ID_SIZE;
    }

    if (packet.header.payloadSize > AES_KEY_SIZE && currentPosition + AES_KEY_SIZE <= bufferSize) {
        std::memcpy(packet.symmetricKeyEncrypted, buffer + currentPosition, packet.header.payloadSize - AES_KEY_SIZE);
        packet.hasSymmetricKey = true;
    }

    return packet;
}

// Deserialize function for ResponseFilePacket
Response::ResponseFilePacket Response::DeserializeFile(const uint8_t* buffer, size_t bufferSize) {
    ResponseFilePacket payload;

    if (bufferSize < sizeof(ResponseHeader)) {
        std::cerr << "Buffer too small to contain the header!" << std::endl;
        exit(1);
    }

    if (bufferSize < sizeof(ResponseFilePacket)) {
        std::cerr << "Buffer too small to contain the entire packet!" << std::endl;
        exit(1);
    }

    std::memcpy(&payload.header, buffer, sizeof(ResponseHeader));
    size_t currentPosition = sizeof(ResponseHeader);

    std::memcpy(payload.ClientID, buffer + currentPosition, CLIENT_ID_SIZE);
    currentPosition += CLIENT_ID_SIZE;

    std::memcpy(&payload.ContentSize, buffer + currentPosition, sizeof(payload.ContentSize));
    currentPosition += sizeof(payload.ContentSize);

    std::memcpy(payload.FileName, buffer + currentPosition, FILE_NAME_SIZE);
    currentPosition += FILE_NAME_SIZE;

    std::memcpy(&payload.CkSum, buffer + currentPosition, sizeof(payload.CkSum));

    return payload;
}

// Deserialize function for ResponseCRC
Response::ResponseCRC Response::DeserializeCRC(const uint8_t* buffer, size_t bufferSize) {
    ResponseCRC payloadCrc;

    if (bufferSize < sizeof(ResponseHeader)) {
        std::cerr << "Buffer too small to contain the header!" << std::endl;
        exit(1);
    }

    if (bufferSize < sizeof(ResponseCRC)) {
        std::cerr << "Buffer too small to contain the entire packet!" << std::endl;
        exit(1);
    }

    std::memcpy(&payloadCrc.header, buffer, sizeof(ResponseHeader));
    size_t currentPosition = sizeof(ResponseHeader);

    std::memcpy(payloadCrc.ClientID, buffer + currentPosition, CLIENT_ID_SIZE);

    return payloadCrc;
}

// Print function to print the header
void Response::printResponseHeader() {
    std::cout << "Version: " << static_cast<int>(packet.header.version) << std::endl;
    std::cout << "Code: " << packet.header.code << std::endl;
    std::cout << "Payload Size: " << packet.header.payloadSize << std::endl;
}

// Print function for ResponsePacket
void Response::print() {
    printResponseHeader();

    if (true) {
        std::cout << "Client ID: ";
        for (int i = 0; i < 16; i++) {
            std::cout << std::hex << static_cast<int>(packet.ClientID[i]);
            if (i != 15) {
                std::cout << ":";
            }
        }
        std::cout << std::dec << std::endl;
    }
    else {
        std::cout << "No Client ID in the response." << std::endl;
    }

    if (packet.hasSymmetricKey) {
        std::cout << "Symmetric Key: ";
        for (int i = 0; i < 128; i++) {
            std::cout << std::hex << static_cast<int>(packet.symmetricKeyEncrypted[i]) << " ";
        }
        std::cout << std::dec << std::endl;
    }
    else {
        std::cout << "No Symmetric Key in the response." << std::endl;
    }
}

// Print function for ResponseFilePacket
void Response::printp() {
    std::cout << "Version: " << static_cast<int>(payload.header.version) << std::endl;
    std::cout << "Code: " << payload.header.code << std::endl;
    std::cout << "Payload Size: " << payload.header.payloadSize << std::endl;

    std::cout << "Client ID: ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(payload.ClientID[i]);
        if (i != 15) {
            std::cout << ":";
        }
    }
    std::cout << std::dec << std::endl;
    std::cout << "ContentSize: " << payload.ContentSize << std::endl;
    std::cout << "FileName: " << payload.FileName << std::endl;
    std::cout << "CkSum: " << payload.CkSum << std::endl;
}

// Print function for ResponseCRC
void Response::printPayloadCrc() {
    
    std::cout << "Version: " << static_cast<int>(payloadCrc.header.version) << std::endl;
    std::cout << "Code: " << payloadCrc.header.code << std::endl;
    std::cout << "Payload Size: " << payloadCrc.header.payloadSize << std::endl;
    std::cout << "Client ID: ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << static_cast<int>(payloadCrc.ClientID[i]);
        if (i != 15) {
            std::cout << ":";
        }
    }
    std::cout << std::dec << std::endl;
}
