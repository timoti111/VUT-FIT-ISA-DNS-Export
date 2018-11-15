/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResourceRecords class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "dns_query.h"
#include "utils.h"
#include <vector>

/**
 * Class representing more Questions in query
 */
class dns_queries
{
public:
    std::vector<dns_query> questions{};
    dns_queries() = default;
    dns_queries(utils::memory_block& read_head, utils::memory_block& whole_buffer, uint16_t count);
    dns_query operator[](size_t index);
    size_t size() const;
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, dns_queries& obj);
};
