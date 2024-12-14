#pragma once

#include <string>
#include <base64.h>


class Base64W
{
public:
    static std::string encode(const std::string& str);
    static std::string decode(const std::string& str);
    static std::string encode(const std::array<uint8_t, 160>& data);
};
