/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResourceRecord class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "dns_utils.h"
#include "dns_type.h"

/**
 * Class representing one Resource Record in response
 */
class dns_resource_record
{
public:
    std::vector<unsigned char> r_name{};
    uint16_t r_type{};
    uint16_t r_class{};
    uint32_t ttl{};
    uint16_t rd_length{};
    dns_type r_data;
    dns_resource_record() = default;
    dns_resource_record(dns_utils::memory_block& read_head, dns_utils::memory_block& whole_buffer);
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, dns_resource_record& obj);
};
