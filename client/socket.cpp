#pragma once
#include "socket.h"
#include "functions.h"
#include <boost/asio.hpp>
#include <fstream>
#include <cstring>
#include <stdexcept>
#include <cmath>

Socket::Socket() {
    std::cout << "Initializing Socket..." << std::endl;
    ioContext = std::make_unique<io_context>();
    socket = std::make_unique<tcp::socket>(*ioContext);
    resolver = std::make_unique<tcp::resolver>(*ioContext);
}

Socket::~Socket() {
    std::cout << "Destroying Socket..." << std::endl;
    if (socket && socket->is_open()) {
        close();
    }
}

// Fetch connection info from file and extract host and port
void Socket::get_connection_info(std::string& host, std::string& port) {
    std::string connection_info = read_line(TRANSFER_FILE_NAME, 1);
    size_t colon_pos = connection_info.find(':');

    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid connection information format in file.");
    }

    host = connection_info.substr(0, colon_pos);
    port = connection_info.substr(colon_pos + 1);

    if (host.empty() || port.empty()) {
        throw std::runtime_error("Invalid host or port information.");
    }
}

// Establish a connection to the server
void Socket::connect() {
    try {
        boost::asio::connect(*socket, resolver->resolve(host, port));
        std::cout << "Connected to " << host << ":" << port << std::endl;
    }
    catch (boost::system::system_error& e) {
        std::cerr << "Failed to connect: " << e.what() << std::endl;
        throw;
    }
}

// Close the socket connection
void Socket::close() {
    if (socket && socket->is_open()) {
        socket->close();
        std::cout << "Socket closed." << std::endl;
    }
}

// Send an encrypted file in chunks
void Socket::sendEncryptedFile(FilePayload& request, const std::string& encryptedFileContent) {
    const size_t chunkSize = request.Msg.size();  // 160 bytes for Msg field
    size_t totalBytes = encryptedFileContent.size();
    request.TotalPackets = static_cast<uint16_t>(std::ceil(static_cast<double>(totalBytes) / chunkSize));

    size_t bytesSent = 0;
    uint16_t packetNumber = 0;

    while (bytesSent < totalBytes) {
        size_t bytesToSend = std::min(totalBytes - bytesSent, chunkSize);
        std::memcpy(request.Msg.data(), encryptedFileContent.data() + bytesSent, bytesToSend);

        request.ContentSize = static_cast<uint32_t>(bytesToSend);
        request.PacketNumber = ++packetNumber;

        request.header.payload_size = sizeof(request.ContentSize) + request.ContentSize +
            sizeof(request.FileName) + sizeof(request.OrigFileSize) +
            sizeof(request.PacketNumber) + sizeof(request.TotalPackets);

        size_t bytes_sent = boost::asio::write(*socket, boost::asio::buffer(reinterpret_cast<const uint8_t*>(&request), sizeof(request)));
        bytesSent += bytesToSend;

        std::cout << "Sent packet " << request.PacketNumber << " of " << request.TotalPackets << " (" << bytesToSend << " bytes)." << std::endl;
    }

    std::cout << "Encrypted file sent successfully (" << totalBytes << " bytes in " << request.TotalPackets << " packets)." << std::endl;
}

// Send generic data to the server
void Socket::sendData(const uint8_t* const buffer, size_t length) {
    try {
        size_t bytes_sent = boost::asio::write(*socket, boost::asio::buffer(buffer, length));
        std::cout << "Data sent to server successfully (" << bytes_sent << " bytes)." << std::endl;
    }
    catch (boost::system::system_error& e) {
        std::cerr << "Failed to send data: " << e.what() << std::endl;
        throw;
    }
}

// Receive data from the server
void Socket::receive_data(std::vector<uint8_t>& buffer) {
    try {
        size_t bytes_received = socket->read_some(boost::asio::buffer(buffer.data(), buffer.size()));

        if (bytes_received == 0) {
            std::cerr << "No data received from the server." << std::endl;
        }
        else {
            std::cout << "\nReceived " << bytes_received << " bytes from the server." << std::endl;
        }
    }
    catch (boost::system::system_error& e) {
        if (e.code() == boost::asio::error::eof) {
            std::cerr << "Connection closed by the server (EOF)." << std::endl;
        }
        else {
            std::cerr << "Error receiving data: " << e.what() << std::endl;
            throw;
        }
    }
}
