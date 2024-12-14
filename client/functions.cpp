#pragma once
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <boost/asio.hpp>
#include <iostream>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/trim.hpp>



std::string hex_to_dec(const uint8_t* buffer, const size_t size) {
    if (size == 0 || buffer == nullptr)
        return "";
    const std::string byteString(buffer, buffer + size);
    if (byteString.empty())
        return "";
    try
    {
        return boost::algorithm::hex(byteString);
    }
    catch (...)
    {
        return "";
    }
}

const std::string unhex(const std::string& hexString)
{
    if (hexString.empty())
        return "";
    try
    {
        return boost::algorithm::unhex(hexString);
    }
    catch (...)
    {
        return "";
    }
}



void create_me_file(std::string user_name,std::string uuid, std::string privateKey) {

    std::string filename = "me.info.txt";

        // Create and open a text file
    std::ofstream outfile(filename);

    // Check if the file was created successfully
    if (!outfile) {
        std::cerr << "File could not be created." << std::endl;
        // Exit with an error code
    }

    // Write "oron" to the first line
    outfile << user_name << std::endl;

    // Write "markovich" to the next line
    outfile << uuid << std::endl;

    // Write "markovich" to the next line
    outfile << privateKey << std::endl;

    // Close the file
    outfile.close();

std::cout << "File created and written successfully." << std::endl;
}

std::string to_hex(const std::string& input) {
    std::stringstream ss;
    for (unsigned char c : input) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

std::string read_line(const char* fileName, int lineNum) {

    std::ifstream file(fileName);
    if (!file) {
        std::cerr << "Failed to open file" << std::endl;
        return ""; 
    }

    std::string line;
    unsigned int currLine = 0;

    while (std::getline(file, line)) {
        currLine++;
        if (currLine == lineNum) {
            file.close();
            return line;
        }
    }

    
    std::cerr << "Line number " << lineNum << " not found in file." << std::endl;
    file.close();
    return "";

    
}
    

    




