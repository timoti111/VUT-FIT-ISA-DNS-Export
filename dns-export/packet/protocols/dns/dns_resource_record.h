/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_resource_record class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "dns_type.h"
#include "../../../utils/utils.h"
#include <string>

/**
 * @brief Class representing one Resource Record in response.
 */
class dns_resource_record
{
public:
    // for more info about DNS Resource Record items see RFC1035
    std::string r_name{};
    uint16_t r_type{};
    uint16_t r_class{};
    uint32_t ttl{};
    uint16_t rd_length{};
    dns_type r_data{};
    dns_resource_record() = default;
    dns_resource_record(memory_block& read_head, memory_block& whole_buffer);
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, dns_resource_record& obj);
};
