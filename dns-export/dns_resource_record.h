/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResourceRecord class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "dns_type.h"
#include "utils.h"
#include <string>

/**
 * Class representing one Resource Record in response
 */
class dns_resource_record
{
public:
    std::string r_name{};
    uint16_t r_type{};
    uint16_t r_class{};
    uint32_t ttl{};
    uint16_t rd_length{};
    dns_type r_data{};
    dns_resource_record() = default;
    dns_resource_record(utils::memory_block& read_head, utils::memory_block& whole_buffer);
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, dns_resource_record& obj);
};
