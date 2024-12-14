#pragma once
#include "Request.h"
#include <boost/asio.hpp>
#include <iostream>
#include <memory>
#include <vector>

using boost::asio::ip::tcp;
using boost::asio::io_context;

#define TRANSFER_FILE_NAME "transfer.info.txt"

class Socket {
public:
    std::string host;
    std::string port;
    
    // Constructor and destructor
    Socket();
    ~Socket();

    // Connection functions
    void get_connection_info(std::string& host, std::string& port);
    void connect();
    void close();

    // Data transmission functions
    void sendEncryptedFile(FilePayload& request, const std::string& encryptedFileContent);
    void sendData(const uint8_t* const buffer, size_t length);
    void receive_data(std::vector<uint8_t>& buffer);

private:
    std::unique_ptr<tcp::socket> socket;
    std::unique_ptr<tcp::resolver> resolver;
    std::unique_ptr<io_context> ioContext;
    
};

