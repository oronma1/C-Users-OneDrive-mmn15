#pragma once
#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <string>

void create_me_file(std::string user_name, std::string uuid, std::string privateKey);
std::string read_line(const char* fileName, int lineNum);
std::string hex_to_dec(const uint8_t* buffer, const size_t size);
const std::string unhex(const std::string& hexString);
std::string to_hex(const std::string& input);

#endif

