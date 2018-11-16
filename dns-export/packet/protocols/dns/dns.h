/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "dns_header.h"
#include "dns_queries.h"
#include "dns_resource_records.h"

/**
 * @brief Class representing DNS message
 */
class dns
{
public:
    dns_header header; /// Header section of response
    dns_queries questions; /// Question section of response
    dns_resource_records answers; /// Answers section of response
    dns_resource_records authorities; /// Authorities section of response
    dns_resource_records additionals; /// Additionals section of response
    explicit dns(memory_block& buffer);
};
