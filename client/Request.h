#pragma once
#include <array>
#include <cstring> 
#include <cstdio>  
#include <iostream>   // For std::cout
#include <iomanip>    // For std::setw and std::setfill
#include <string>     // For std::string

enum esize
{
    DEF_VAL = 0,
    DEF_VERSION = 3,
};

enum RequestCode
{
    REGISTRATION = 825,   // uuid ignored.
    SEND_PUBLIC_KEY = 826,
    RECONNECT = 827,
    SEND_FILE = 828,
    VALID_CRC = 900,
    INVALID_CRC = 901,
    INVALID_CRC_END = 902
};



#pragma pack(push, 1)
struct CHeader
{
    uint8_t version;
    uint16_t code;
    std::array<uint8_t, 16> ClientID;
    uint32_t payload_size;

    // Default constructor
    CHeader() : version(DEF_VERSION), code(DEF_VAL), payload_size(DEF_VAL)
    {
        ClientID.fill(DEF_VAL); // Zero-initializing ClientID to avoid uninitialized data
    }

    // Constructor with request code
    CHeader(uint16_t code) : version(DEF_VERSION), code(code), payload_size(DEF_VAL)
    {
        ClientID.fill(DEF_VAL); // Zero-initializing ClientID
    }

    // Clear sensitive data
    void Clear()
    {
        ClientID.fill(DEF_VAL);
    }
    // Print function
    void Print() const
    {
        std::cout << "  CHeader {\n";
        std::cout << "    Version: " << static_cast<int>(version)
            << " (" << ((version == DEF_VERSION) ? "DEF_VERSION" : "UNKNOWN") << ")\n";
        std::cout << "    Code: " << code << " (";

        // Convert code to string using switch-case
        switch (code)
        {
        case REGISTRATION:
            std::cout << "REGISTRATION";
            break;
        case SEND_PUBLIC_KEY:
            std::cout << "SEND_PUBLIC_KEY";
            break;
        case RECONNECT:
            std::cout << "RECONNECT";
            break;
        case SEND_FILE:
            std::cout << "SEND_FILE";
            break;
        case VALID_CRC:
            std::cout << "VALID_CRC";
            break;
        case INVALID_CRC:
            std::cout << "INVALID_CRC";
            break;
        case INVALID_CRC_END:
            std::cout << "INVALID_CRC_END";
            break;
        default:
            std::cout << "UNKNOWN_CODE";
            break;
        }

        std::cout << ")\n";
        std::cout << "    ClientID: ";
        for (const auto& byte : ClientID)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << "\n"; // Reset to decimal
        std::cout << "    Payload Size: " << payload_size << "\n";
        std::cout << "  }\n\n";
    }
};

struct RegisterPacket
{
    CHeader header;
    std::array<uint8_t, 255> Name;

    RegisterPacket(RequestCode code) : header(code)
    {
        Name.fill('\0'); // Initialize Name to avoid garbage values
    }

    // Ensure name fits within the allocated buffer
    void SetName(const char* name)
    {
        strncpy_s(reinterpret_cast<char*>(Name.data()), Name.size(), name, _TRUNCATE);
    }

    // Print function
    void Print() const
    {
        std::cout << "RegisterPacket {\n";
        header.Print(); // Print nested CHeader

        // Safely convert Name array to string
        std::string nameStr(reinterpret_cast<const char*>(Name.data()));
        std::cout << "  Name: " << nameStr << "\n";
        std::cout << "}\n\n";
    }
};

struct SendPublicKeyPacket
{
    CHeader header;
    std::array<uint8_t, 255> Name;
    std::array<uint8_t, 160> PublicKey;

    SendPublicKeyPacket() : header(SEND_PUBLIC_KEY)
    {
        Name.fill('\0');       // Initialize Name
        PublicKey.fill('\0');  // Initialize PublicKey
    }

    // Clear sensitive data
    void Clear()
    {
        PublicKey.fill(DEF_VAL); // Zero out public key data when no longer needed
    }

    // Set public key securely (limiting to 160 bytes)
    void SetPublicKey(const uint8_t* key, size_t size)
    {
        if (size <= PublicKey.size())
        {
            std::memcpy(PublicKey.data(), key, size);
        }
    }
    // Print function
    void Print() const
    {
        std::cout << "SendPublicKeyPacket {\n";
        header.Print(); // Print nested CHeader

        // Safely convert Name array to string
        std::string nameStr(reinterpret_cast<const char*>(Name.data()));
        std::cout << "  Name: " << nameStr << "\n";

        // Print PublicKey in hexadecimal
        std::cout << "  PublicKey: ";
        for (const auto& byte : PublicKey)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << "\n"; // Reset to decimal
        std::cout << "}\n\n";
    }
};

struct FilePayload
{
    CHeader header;
    uint32_t ContentSize;
    uint32_t OrigFileSize;
    uint16_t PacketNumber;
    uint16_t TotalPackets;
    std::array<uint8_t, 255> FileName;
    std::array<uint8_t, 680> Msg;

    FilePayload() : header(SEND_FILE), ContentSize(DEF_VAL), OrigFileSize(DEF_VAL), PacketNumber(DEF_VAL), TotalPackets(DEF_VAL)
    {
        FileName.fill('\0');   // Initialize FileName
        Msg.fill('\0');        // Initialize Msg
    }

    // Set file name with bounds checking
    void SetFileName(const char* fileName)
    {
        strncpy_s(reinterpret_cast<char*>(FileName.data()), FileName.size(), fileName, _TRUNCATE);
    }

    // Set Msg securely (limiting to 160 bytes)
    void SetMsg(const uint8_t* msg, size_t size)
    {
        if (size <= Msg.size())
        {
            std::memcpy(Msg.data(), msg, size);
        }
    }

    // Print function
    void Print() const
    {
        std::cout << "FilePayload {\n";
        header.Print(); // Print nested CHeader

        std::cout << "  Content Size: " << ContentSize << "\n";
        std::cout << "  Original File Size: " << OrigFileSize << "\n";
        std::cout << "  Packet Number: " << PacketNumber << "\n";
        std::cout << "  Total Packets: " << TotalPackets << "\n";

        // Safely convert FileName array to string
        std::string fileNameStr(reinterpret_cast<const char*>(FileName.data()));
        std::cout << "  FileName: " << fileNameStr << "\n";

        // Safely convert Msg array to string (assuming it's text)
        std::string msgStr(reinterpret_cast<const char*>(Msg.data()));
        std::cout << "  Msg: " << msgStr << "\n";
        std::cout << "}\n\n";
    }
};

struct CRC
{
    CHeader header;
    std::array<uint8_t, 255> FileName;

    CRC() : header(DEF_VAL)
    {
        FileName.fill('\0');   // Initialize FileName
    }

    // Set file name with bounds checking
    void SetFileName(const char* fileName)
    {
        strncpy_s(reinterpret_cast<char*>(FileName.data()), FileName.size(), fileName, _TRUNCATE);
    }

    // Print function
    void Print() const
    {
        std::cout << "CRC {\n";
        header.Print(); // Print nested CHeader

        // Safely convert FileName array to string
        std::string fileNameStr(reinterpret_cast<const char*>(FileName.data()));
        std::cout << "  FileName: " << fileNameStr << "\n";
        std::cout << "}\n\n";
    }
};

#pragma pack(pop)


