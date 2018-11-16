/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_queries class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "dns_query.h"
#include "../../../utils/utils.h"
#include <vector>

/**
 * @brief Class representing more queries in message. See Question section in RFC1035.
 */
class dns_queries
{
public:
    std::vector<dns_query> questions{}; // vector of queries
    dns_queries() = default;
    dns_queries(memory_block& read_head, memory_block& whole_buffer, uint16_t count);
    dns_query operator[](size_t index);
    size_t size() const;
};
