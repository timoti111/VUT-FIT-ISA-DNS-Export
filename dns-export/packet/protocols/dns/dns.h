/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "dns_header.h"
#include "dns_questions.h"
#include "dns_resource_records.h"

/**
 * @brief Class representing DNS message
 */
class dns
{
public:
    dns_header header; // Header section of response
    dns_questions questions; // Question section of response
    dns_resource_records answers; // Answer section of response
    dns_resource_records authorities; // Authority section of response
    dns_resource_records additionals; // Additional section of response
    explicit dns(memory_block& buffer);
};
