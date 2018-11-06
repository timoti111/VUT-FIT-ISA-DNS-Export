/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSUtils class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include <bitset>
#include "dns_utils.h"
#include <arpa/inet.h>
#include <sstream>
#include <cstring>
#include "error.h"

/**
 * Converts data from label format to string eg. 3www3fit5vutbr2cz0 -> www.fit.vutbr.cz.
 * @param dns_name data in format 3www3fit5vutbr2cz0
 * @return string in format www.fit.vutbr.cz.
 */
std::string dns_utils::label_to_string(const std::vector<unsigned char>& dns_name)
{
    std::string name;
    if (dns_name.size() == 1 && dns_name.back() == 0)
    {
        name.push_back('.');
        return name;
    }
    unsigned char i = 0, len = 0;
    while (i < dns_name.size())
    {
        len = dns_name[i++];
        if (len == 0)
        {
            break;
        }
        for (unsigned char j = 0; j < len; j++)
        {
            name.push_back(dns_name[i++]);
        }
        name.push_back('.');
    }
    name.pop_back();
    return name;
} /**
 * Parses data to label format (eg 3www3fit5vutbr2cz0) from buffer. If compression is found data is decompressed
 * @param read_head buffer where parsing starts
 * @param whole_buffer if compression is found this buffer is used for decompression
 * @return data in label format eg 3www3fit5vutbr2cz0
 */
std::vector<unsigned char> dns_utils::parse_name(memory_block& read_head, memory_block& whole_buffer)
{
    std::vector<unsigned char> name;
    while (true)
    {
        if (*(read_head.ptr) >= 192)
        {
            if (read_head.length < 2)
            {
                throw dns_parsing_error("Error: parse_name compression");
            }
            const uint16_t offset = ((*(read_head.ptr) & 63) << 8) | (*((read_head.ptr) + 1) & 255);
            auto p = memory_block{whole_buffer.ptr + offset, whole_buffer.length - offset};
            auto ptr_name = parse_name(p, whole_buffer);
            name.insert(name.end(), ptr_name.begin(), ptr_name.end());
            read_head.ptr += 2;
            read_head.length -= 2;
            return name;
        }
        if (read_head.length < 1)
        {
            throw dns_parsing_error("Error: parse_name 1");
        }
        name.push_back(*(read_head.ptr));
        read_head.ptr++;
        read_head.length--;
        if (name.back() == 0)
        {
            break;
        }
        for (int i = name.back(); i > 0; i--)
        {
            if (read_head.length < 1)
            {
                throw dns_parsing_error("Error: parse_name 2");
            }
            name.push_back(*(read_head.ptr));
            read_head.ptr++;
            read_head.length--;
        }
    }
    return name;
} /**
 * Convert binary IPv4 or IPv6 address to string
 * @param data binary data of IP adress
 * @return string format of IP adress
 */
std::string dns_utils::addr_to_string(const std::vector<unsigned char>& data)
{
    char str[INET6_ADDRSTRLEN];
    const char* ptr;
    memset(str, 0, INET6_ADDRSTRLEN);
    if (data.size() == sizeof(struct in_addr))
    {
        ptr = inet_ntop(AF_INET, data.data(), str, INET_ADDRSTRLEN);
    }
    else if (data.size() == sizeof(struct in6_addr))
    {
        ptr = inet_ntop(AF_INET6, data.data(), str, INET6_ADDRSTRLEN);
    }
    else
    {
        // TODO throw not_address
        return "NOTADDRESS";
    }
    if (ptr != str)
    {
        // TODO throw not_address
        return "NOTADDRESS";
    }
    return std::string(str);
} /**
 * Converts host address to host name eg 147.229.13.238 -> 238.13.229.147.in-addr.arpa.
 * @param name IPv4 or IPv6 address as string
 * @return host name which can be questioned to DNS server
 */
std::string dns_utils::hatohn(const std::string& name)
{
    std::stringstream stream;
    unsigned char buf[sizeof(struct in6_addr)];
    auto s = inet_pton(AF_INET, name.c_str(), buf);
    if (s <= 0)
    {
        s = inet_pton(AF_INET6, name.c_str(), buf);
        if (s <= 0)
        {
            // TODO throw not_address
            return "NOTADDRESS";
        }
        for (int i = sizeof(in6_addr) - 1; i >= 0; i--)
        {
            stream << std::hex << (buf[i] & 15) << ".";
            stream << std::hex << ((buf[i] >> 4) & 15) << ".";
        }
        return stream.str() + "ip6.arpa";
    }
    for (int i = sizeof(in_addr) - 1; i >= 0; i--)
    {
        stream << std::to_string(buf[i]) << ".";
    }
    return stream.str() + "in-addr.arpa";
} /**
 * Converts IPv4 and IPv6 addresses from text to binary form.
 * @param name IPv4 or IPv6 address as string
 */
std::string dns_utils::address_to_binary(const std::string& name)
{
    std::stringstream stream;
    unsigned char buf[sizeof(struct in_addr)];
    unsigned char buf6[sizeof(struct in6_addr)];
    int s = inet_pton(AF_INET, name.c_str(), buf);
    if (s <= 0)
    {
        s = inet_pton(AF_INET6, name.c_str(), buf6);
        if (s <= 0)
        {
            // TODO throw not_address
            return "NOTADDRESS";
        }
        for (int i = sizeof(in6_addr) - 1; i >= 0; i--)
        {
            stream << std::hex << (buf[i] & 15) << ".";
            stream << std::hex << ((buf[i] >> 4) & 15) << ".";
        }
        return stream.str() + "ip6.arpa";
    }
    for (int i = sizeof(in_addr) - 1; i >= 0; i--)
    {
        stream << std::to_string(buf[i]) << ".";
    }
    return stream.str() + "in-addr.arpa";
}

std::string dns_utils::mem_to_string(memory_block& mem, const long length)
{
    if (mem.length < length)
    {
        throw dns_parsing_error("Error: mem_to_string");
    }
    mem.ptr += length;
    mem.length -= length;
    return std::string(mem.ptr - length, mem.ptr);
}

std::vector<unsigned char> dns_utils::mem_to_vector(memory_block& mem, const long length)
{
    if (mem.length < length)
    {
        throw dns_parsing_error("Error: mem_to_vector");
    }
    mem.ptr += length;
    mem.length -= length;
    return std::vector<unsigned char>(mem.ptr - length, mem.ptr);
}

uint16_t dns_utils::mem_to_uint16(memory_block& mem)
{
    if (mem.length < sizeof(uint16_t))
    {
        throw dns_parsing_error("Error: mem_to_uint16");
    }
    uint16_t ret;
    memcpy(&ret, mem.ptr, sizeof(uint16_t));
    mem.ptr += sizeof(uint16_t);
    mem.length -= sizeof(uint16_t);
    return ntohs(ret);
}

uint32_t dns_utils::mem_to_uint32(memory_block& mem)
{
    if (mem.length < sizeof(uint32_t))
    {
        throw dns_parsing_error("Error: mem_to_uint32");
    }
    uint32_t ret;
    memcpy(&ret, mem.ptr, sizeof(uint32_t));
    mem.ptr += sizeof(uint32_t);
    mem.length -= sizeof(uint32_t);
    return ntohl(ret);
}

uint8_t dns_utils::mem_to_uint8(memory_block& mem)
{
    if (mem.length < sizeof(uint8_t))
    {
        throw dns_parsing_error("Error: mem_to_uint32");
    }
    uint8_t ret;
    memcpy(&ret, mem.ptr, sizeof(uint8_t));
    mem.ptr += sizeof(uint8_t);
    mem.length -= sizeof(uint8_t);
    return ret;
}

std::string dns_utils::vec_to_hexstring(std::vector<unsigned char> vec)
{
    std::stringstream stream;
    for (auto element : vec)
    {
        stream << hex(element);
    }
    return stream.str();
}

dns_utils::HexCharStruct dns_utils::hex(unsigned char _c)
{
    return HexCharStruct(_c);
}

std::ostream& operator<<(std::ostream& o, const dns_utils::HexCharStruct& hs)
{
    return (o << std::setfill('0') << std::setw(2) << std::hex << (int)hs.c);
}
