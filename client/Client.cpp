#pragma once
#include "Client.h"
#include <filesystem>
#include "cksum.h"
#include "functions.h"

Client::Client() {
    ss.get_connection_info(ss.host, ss.port);
    ss.connect();
    name = read_line(TRANSFER_FILE_NAME, 2);
    filePath = read_line(TRANSFER_FILE_NAME, 3);
    fileName = std::filesystem::path(filePath).filename().string();
    
}

void Client::start_protocol() {
    std::cout << "start protocol for client " << name << "\n" << std::endl;
    bool check = false;
    unsigned int crctry = 0;
    try {
        if (file_exists()) {
            reconnect();
            check = receive_AES_key();
            if (!check) {
                std::cerr << "Error: Reconnect denied - the client is not registered." << std::endl;
            }
        }

        if (!check) {
            check = registration();
            if (!check) {
                std::cerr << "Error: registration denied." << std::endl;
                ss.close();
            }
            else {
                send_public_key();
                check = receive_AES_key();
            }
        }

        if (check) {
            do {
                std::cout << "try number :" << crctry << std::endl;
                crctry++;
                send_file();
            } while ((check = CRC_stat(crctry)) != true && crctry < MAX_TRY);

            if (check == false) {
                ss.close();
                exit(1);
            }
            responseCRC();
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}


bool Client::registration() {

    RegisterPacket request = RegisterPacket(REGISTRATION);
    Response response;

    if (name.size() <= request.Name.size()) {
        std::memcpy(request.Name.data(), name.data(), name.size());
        request.header.payload_size = static_cast<uint32_t>(name.size());
    }
    else {
        std::cerr << "Error: Name is too large to fit into the request packet!" << std::endl;
        return false;
    }

    std::cout << "\n::: send registration request packet :::" << std::endl;
    request.Print();
    ss.sendData(reinterpret_cast<const uint8_t* const>(&request), sizeof(request));

    std::vector<uint8_t> response_buffer(1024);
    ss.receive_data(response_buffer);

    response.packet = response.Deserialize(response_buffer.data(), response_buffer.size());

    if (response.packet.header.code != REGISTRATION_SUCCESS) {
        response.print();
        return false;
    }

    rsa.getPrivateKey();
    std::cout << "\n:::Registration success:::" << std::endl;
    response.print();
    setClientID(response);
    create_me_file(name, clientID, Base64W::encode(rsa.getPrivateKey()));
    return true;
}

void Client::reconnect() {
    RegisterPacket request = RegisterPacket(RECONNECT);
    rsa.loadPrivateKeyDER("priv.key");
    rsa.generatePublicKeyFromPrivate();
    clientID = unhex(read_line("me.info.txt", 2));

    if (clientID.size() <= request.header.ClientID.size()) {
        std::memcpy(request.header.ClientID.data(), clientID.data(), clientID.size());
    }
    else {
        std::cerr << "Error: ClientID is too large to fit into the packet!" << std::endl;
        return;
    }

    if (name.size() <= request.Name.size()) {
        std::memcpy(request.Name.data(), name.data(), name.size());
        request.header.payload_size = static_cast<uint32_t>(name.size());
    }
    else {
        std::cerr << "Error: Name is too large to fit into the request packet!" << std::endl;
        return;
    }

    std::cout << "\n:::send reconnect request packet:::" << std::endl;
    request.Print();
    ss.sendData(reinterpret_cast<const uint8_t* const>(&request), sizeof(request));
}

void Client::send_public_key() {
    SendPublicKeyPacket request = SendPublicKeyPacket();
    clientID = unhex(clientID);

    if (clientID.size() <= request.header.ClientID.size()) {
        std::memcpy(request.header.ClientID.data(), clientID.data(), clientID.size());
    }
    else {
        std::cerr << "Error: ClientID is too large to fit into the packet!" << std::endl;
        return;
    }

    if (name.size() <= request.Name.size()) {
        std::memcpy(request.Name.data(), name.data(), name.size());
    }
    else {
        std::cerr << "Error: Name is too large to fit into the request packet!" << std::endl;
        return;
    }

    if (rsa.getPublicKeyDER().size() <= request.PublicKey.size()) {
        std::memcpy(request.PublicKey.data(), rsa.getPublicKeyDER().data(), rsa.getPublicKeyDER().size());
    }
    else {
        std::cerr << "Error: Public Key is too large to fit into the packet!" << std::endl;
        return;
    }

    rsa.savePrivateKeyDER("priv.key");

    request.header.payload_size = static_cast<uint32_t>(name.size()) + static_cast<uint32_t>(rsa.getPublicKeyDER().size());
    std::cout << "\n:::send public key request packet:::" << std::endl;
    request.Print();
    ss.sendData(reinterpret_cast<const uint8_t* const>(&request), sizeof(request));
}

bool Client::receive_AES_key() {
    Response response;
    std::vector<uint8_t> response_buffer(1024);
    ss.receive_data(response_buffer);
    response.packet = response.Deserialize(response_buffer.data(), response_buffer.size());

    if (response.packet.header.code == RECONNECT_DENIED) {
        return false;
    }
    if (response.packet.header.code == RECONNECTION_CONFIRMED_RESEND_AES_KEY){
        std::cout << "\n:::Reconnection confirmed :::" << std::endl;
    }
    if (response.packet.header.code == REGISTRATION_SUCCESS) {
        std::cout << "\n:::Registration success:::" << std::endl;
    }

    response.print();
    std::string decryptedMessage = rsa.decrypt(response.packet.symmetricKeyEncrypted, sizeof(response.packet.symmetricKeyEncrypted));
    aesKey = decryptedMessage;

    SecureZeroMemory(response.packet.symmetricKeyEncrypted, sizeof(response.packet.symmetricKeyEncrypted));

    
    return true;
}

void Client::send_file() {
    FilePayload request = FilePayload();
    AESWrapper aes(aesKey);

    std::size_t fileSize = getFileSize(filePath);
    std::string encryptedFileContent = encryptFile(filePath, aes);

    if (clientID.size() <= request.header.ClientID.size()) {
        std::memcpy(request.header.ClientID.data(), clientID.data(), clientID.size());
    }
    else {
        std::cerr << "Error: ClientID is too large to fit into the packet!" << std::endl;
        return;
    }

    request.OrigFileSize = static_cast<uint32_t>(fileSize);
    request.ContentSize = static_cast<uint32_t>(encryptedFileContent.size());

    if (fileName.size() <= request.FileName.size()) {
        std::memcpy(request.FileName.data(), fileName.data(), fileName.size());
    }
    else {
        std::cerr << "Error: FileName is too large to fit into the packet!" << std::endl;
        return;
    }

    request.header.payload_size = static_cast<uint32_t>(sizeof(request.ContentSize) + sizeof(request.OrigFileSize) +
        request.ContentSize + sizeof(request.FileName));

    std::cout << "\n:::send file request packet:::" << std::endl;
    request.Print();
    ss.sendEncryptedFile(request, encryptedFileContent);
}

bool Client::CRC_stat(unsigned int num_of_try) {
    Response response;
    CRC request = CRC();
    std::string res = readfilecksum(filePath);
    unsigned int crcres = getCrcResult(res);

    std::vector<uint8_t> response_buffer(1024);
    ss.receive_data(response_buffer);
    response.payload = response.DeserializeFile(response_buffer.data(), response_buffer.size());
    response.printp();

    if (fileName.size() <= request.FileName.size()) {
        std::memcpy(request.FileName.data(), fileName.data(), fileName.size());
    }
    else {
        std::cerr << "Error: FileName is too large to fit into the packet!" << std::endl;
        return false;
    }
    if (clientID.size() <= request.header.ClientID.size()) {
        std::memcpy(request.header.ClientID.data(), clientID.data(), clientID.size());
    }
    else {
        std::cerr << "Error: ClientID is too large to fit into the packet!" << std::endl;
        return false;
    }
    if (crcres == response.payload.CkSum) {
        request.header.code = VALID_CRC;
        std::cout << "\n:::send valid crc request packet:::" << std::endl;
        request.Print();
        ss.sendData(reinterpret_cast<const uint8_t* const>(&request), sizeof(request));
        return true;
    }
    else {
        if (num_of_try < MAX_TRY) {
            
            request.header.code = INVALID_CRC;
            std::cout << "\n:::send valid crc request packet:::" << std::endl;
        }
        else {
            
            request.header.code = INVALID_CRC_END;
            std::cout << "\n:::send valid crc request packet:::" << std::endl;
        }
        
        request.Print();
        ss.sendData(reinterpret_cast<const uint8_t* const>(&request), sizeof(request));
        return false;
    }
}

void Client::responseCRC() {
    std::vector<uint8_t> response_buffer(1024);
    ss.receive_data(response_buffer);

    Response response;
    response.payloadCrc = response.DeserializeCRC(response_buffer.data(), response_buffer.size());
    response.printPayloadCrc();

    
    ss.close();
}



std::size_t Client::getFileSize(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Could not open the file!" << std::endl;
        return 0;
    }

    std::size_t fileSize = file.tellg();
    file.close();
    return fileSize;
}

// Assuming AESWrapper has a method that accepts unsigned char*
std::string Client::encryptFile(const std::string& filePath, AESWrapper& aes) {
    // Open the file in binary mode and seek to the end to determine its size
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file: " + filePath);
    }

    // Get the size of the file
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read the file content into a buffer
    std::vector<char> buffer(fileSize);
    if (!file.read(buffer.data(), fileSize)) {
        throw std::runtime_error("Error reading file: " + filePath);
    }
    file.close();

    // Encrypt the data
    std::string encryptedData = aes.encrypt(buffer.data(), static_cast<unsigned int>(fileSize));

    

    return encryptedData;
}

void Client::setClientID(const Response& response) {
    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(response.packet.ClientID[i]);
    }
    clientID = oss.str();
}

void Client::printAESkey(const std::string& decryptedMessage) {
    std::cout << "AES key (Hex): ";
    for (unsigned char c : decryptedMessage) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    std::cout << std::dec << std::endl;
}

unsigned int Client::getCrcResult(const std::string& result) {
    std::istringstream iss(result);
    std::string crcStr;

    std::getline(iss, crcStr, '\t');
    return static_cast<unsigned int>(std::stoul(crcStr));
}

bool Client::file_exists() {
    std::string filename = "me.info.txt";
    return std::filesystem::exists(filename);
}

void Client::SecureZeroMemory(uint8_t* data, size_t size) {
    volatile uint8_t* p = data;
    while (size--) *p++ = 0;
}
