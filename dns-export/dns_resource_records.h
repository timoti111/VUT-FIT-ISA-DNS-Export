/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResourceRecords class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "dns_resource_record.h"
#include <vector>

/**
 * Class representing more Resource Records in response
 */
class dns_resource_records
{
public:
    std::vector<dns_resource_record> records{};
    dns_resource_records() = default;
    dns_resource_records(utils::memory_block& read_head, utils::memory_block& whole_buffer, uint16_t count);
    dns_resource_record operator[](size_t index);
    size_t size() const;
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, dns_resource_records& obj);
};
