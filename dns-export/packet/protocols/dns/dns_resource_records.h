/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_resource_records class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "dns_resource_record.h"
#include <vector>

/**
 * @brief Class representing more Resource Records in response. Answer, Authority and Additional section. More in RFC1035
 */
class dns_resource_records
{
public:
    std::vector<dns_resource_record> records{};// vector of resource records
    dns_resource_records() = default;
    dns_resource_records(memory_block& read_head, memory_block& whole_buffer, uint16_t count);
    dns_resource_record operator[](size_t index);
    size_t size() const;
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, dns_resource_records& obj);
};
