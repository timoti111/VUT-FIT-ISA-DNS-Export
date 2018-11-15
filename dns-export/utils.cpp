/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief utils class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include <cstring>
#include "utils.h"
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>

utils::hex_char_struct utils::hex(const uint8_t c)
{
    return hex_char_struct(c);
}

std::ostream& operator<<(std::ostream& o, const utils::hex_char_struct& hs)
{
    return (o << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(hs.c));
}

utils::memory_block::memory_block(uint8_t* ptr, const int64_t length)
{
    if (length < 0)
    {
        throw memory_error("Memory error");
    }
    this->ptr_ = ptr;
    this->length_ = length;
}

uint8_t* utils::memory_block::begin() const
{
    return ptr_;
}

uint8_t* utils::memory_block::end() const
{
    return ptr_ + length_;
}

int64_t utils::memory_block::size() const
{
    return length_;
}

utils::memory_block utils::memory_block::operator+(const int64_t rhs) const
{
    if (rhs > length_)
    {
        throw memory_error("Memory error");
    }
    return {ptr_ + rhs, length_ - rhs};
}

utils::memory_block& utils::memory_block::operator+=(const int64_t rhs)
{
    if (rhs > length_)
    {
        throw memory_error("Memory error");
    }
    ptr_ += rhs;
    length_ -= rhs;
    return *this;
}

utils::memory_block& utils::memory_block::operator++()
{
    return *this += 1;
}

utils::memory_block utils::memory_block::operator++(int)
{
    const auto result(*this);
    ++(*this);
    return result;
}

/**
 * Parses data to label format (eg 3www3fit5vutbr2cz0) from buffer. If compression is found data is decompressed
 * @param read_head buffer where parsing starts
 * @param whole_buffer if compression is found this buffer is used for decompression
 * @return data in label format eg 3www3fit5vutbr2cz0
 */
std::string utils::parse_name(memory_block& read_head, memory_block& whole_buffer)
{
    std::string name;
    while (true)
    {
        if (*read_head.get_ptr<uint8_t>() >= 192)
        {
            const uint16_t offset = ntohs(*read_head.get_ptr_and_add<uint16_t>()) & 0x3fff;
            auto p = whole_buffer + offset;
            auto ptr_name = parse_name(p, whole_buffer);
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
    if (name.size() > 1)
    {
        name.pop_back();
    }
    else
    {
        name.push_back('.');
    }
    return name;
}

std::string utils::addr_to_string(const void* address_ptr, const int address_family)
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
 * Convert binary IPv4 or IPv6 address to string
 * @param data binary data of IP adress
 * @param length
 * @return string format of IP adress
 */
std::string utils::addr_to_string(memory_block& data, const int64_t length)
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
    return addr_to_string(address_ptr, address_family);
}

std::string utils::mem_to_string(memory_block& mem, const int64_t length)
{
    auto ret = std::string(mem.begin(), mem.end());
    ret.push_back('\0');
    mem += length;
    return ret;
}

std::string utils::mem_to_hexstring(memory_block& mem, const int64_t length)
{
    std::stringstream stream;
    for (auto i = 0; i < length; i++)
    {
        stream << hex(*mem.get_ptr_and_add<uint8_t>());
    }
    return stream.str();
}
