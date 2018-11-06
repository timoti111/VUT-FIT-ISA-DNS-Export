/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResponse class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "dns_header.h"
#include "dns_resource_records.h"
#include "dns_queries.h"
#include <ostream>

/**
 * Class representing response from DNS server
 */
class dns_packet
{
public:
    dns_header header; /// Header section of response
    dns_queries questions; /// Question section of response
    dns_resource_records answers; /// Answers section of response
    dns_resource_records authorities; /// Authorities section of response
    dns_resource_records additionals; /// Additionals section of response
    dns_packet() = default;
    dns_packet(const unsigned char* buffer, long length);
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, dns_packet& obj);
};
