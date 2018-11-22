/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief utils class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include <cstring>
#include "utils.h"
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>

/**
 * @brief Parses label format data (eg 3www3fit5vutbr2cz0) to string (www.fit.vutbr.cz). If compression is found data is decompressed.
 * @param read_head Memory block where parsing starts
 * @param whole_buffer If compression is found this buffer is used for decompression.
 * @return Data in string eg. www.fit.vutbr.cz. Returns '.' if label is 0 (root).
 */
std::string utils::parse_label_name(memory_block& read_head, memory_block& whole_buffer, uint8_t recursion_depth)
{
    if (recursion_depth > 30)
    {
        throw other_error("Packet is corrupted.");
    }
    std::string name;
    while (true)
    {
        if (*read_head.get_ptr<uint8_t>() >= 192)
        {
            const uint16_t offset = ntohs(*read_head.get_ptr_and_add<uint16_t>()) & 0x3fff;
            auto p = whole_buffer + offset;
            auto ptr_name = parse_label_name(p, whole_buffer, ++recursion_depth);
            name.insert(name.end(), ptr_name.begin(), ptr_name.end());
            return name;
        }
        const auto label = *read_head.get_ptr_and_add<uint8_t>();
        for (auto i = label; i > 0; i--)
        {
            name.push_back(*read_head.get_ptr_and_add<uint8_t>());
        }
        if (label == 0)
        {
            break;
        }
        name.push_back('.');
    }
    if (name.empty())
    {
        name.push_back('.');
    }
    return name;
}

/**
 * @brief Converts binary data to string representation of IP address.
 * @param address_ptr Pointer to memory containing IPv4 or IPv6 address in binary foramt.
 * @param address_family Address family AF_INET or AF_INET6.
 * @return IP address in string eg. 192.168.0.1
 */
std::string utils::bin_address_to_string(const void* address_ptr, const int address_family)
{
    char address_str[INET6_ADDRSTRLEN];
    memset(address_str, 0, INET6_ADDRSTRLEN);
    const auto ptr = inet_ntop(address_family, address_ptr, address_str, INET6_ADDRSTRLEN);
    if (ptr == address_str)
    {
        return address_str;
    }
    throw other_error("Not IP address.");
}

/**
 * @brief Converts binary IPv4 or IPv6 address to string.
 * @param data Binary data of IP address.
 * @param length Length of address.
 * @return String format of IP address.
 */
std::string utils::bin_address_to_string(memory_block& data, const int64_t length)
{
    int address_family;
    void* address_ptr;
    if (length == sizeof(in_addr))
    {
        address_family = AF_INET;
        address_ptr = data.get_ptr_and_add<in_addr>();
    }
    else if (length == sizeof(in6_addr))
    {
        address_family = AF_INET6;
        address_ptr = data.get_ptr_and_add<in6_addr>();
    }
    else
    {
        throw other_error("Not IP address.");
    }
    return bin_address_to_string(address_ptr, address_family);
}

/**
 * @brief Converts data in memory to string.
 * @param mem Memory block pointing to first byte.
 * @param length Length of data to be converted to string.
 * @return String representation of memory.
 */
std::string utils::mem_to_string(memory_block& mem, const int64_t length)
{
    mem += length;
    auto ret = std::string(mem.begin() - length, mem.begin());
    return ret;
}

/**
 * @brief Converts data in memory to hexadecimal representation of bytes.
 * @param mem Memory block pointing to first byte.
 * @param length Length of data to be converted to hexadecimal format.
 * @return Hexadecimal representation of memory as string.
 */
std::string utils::mem_to_hex_string(memory_block& mem, const int64_t length)
{
    std::stringstream stream;
    for (auto i = 0; i < length; i++)
    {
        stream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(*mem.get_ptr_and_add<uint8_t>());
    }
    return stream.str();
}
