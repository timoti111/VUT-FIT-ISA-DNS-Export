/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSQuestion class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "utils.h"
#include <string>

/**
 * Class representing DNS Question section
 */
class dns_query
{
public:
    std::string q_name{};
    uint16_t q_type{};
    uint16_t q_class{};
    dns_query() = default;
    explicit dns_query(utils::memory_block& read_head, utils::memory_block& whole_buffer);
    std::string to_string() const;
    friend std::ostream& operator<<(std::ostream& stream, dns_query& obj);
};
