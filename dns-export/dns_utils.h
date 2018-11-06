/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSUtils class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <string>
#include <vector>
#include <iomanip>
#include  <iostream>

/**
 * Class with helpful utilities for DNS data
 */
class dns_utils
{
    struct HexCharStruct
    {
        unsigned char c;

        explicit HexCharStruct(const unsigned char c) : c(c)
        {
        }
    };

    static HexCharStruct hex(unsigned char c);
    friend std::ostream& operator<<(std::ostream& o, const HexCharStruct& hs);
public:
    struct memory_block
    {
        unsigned char* ptr;
        long length;
    };

    static std::vector<unsigned char> parse_name(memory_block& read_head, memory_block& whole_buffer);
    static std::string label_to_string(const std::vector<unsigned char>& dns_name);
    static std::string addr_to_string(const std::vector<unsigned char>& data);
    static std::string hatohn(const std::string& name);
    static std::string address_to_binary(const std::string& name);
    static std::string mem_to_string(memory_block& mem, long length);
    static std::vector<unsigned char> mem_to_vector(memory_block& mem, long length);
    static uint8_t mem_to_uint8(memory_block& mem);
    static uint16_t mem_to_uint16(memory_block& mem);
    static uint32_t mem_to_uint32(memory_block& mem);
    static std::string vec_to_hexstring(std::vector<unsigned char> vec);
};
