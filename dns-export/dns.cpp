/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief dns class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns.h"
#include "utils.h"
#include "exceptions.h"
#include <sstream>

/**
 * This constructor parses whole DNS response from buffer
 * @param buffer buffer to parse from
 * @param length
 */
dns::dns(utils::memory_block& buffer)
{
    auto read_head = buffer;
    header = dns_header(read_head);
    if (header.flags.tc == 1)
    {
        throw dns_parsing_error("Truncated response! Skipping packet.");
    }
    if (header.flags.r_code != 0)
    {
        throw dns_parsing_error("DNS server error! Skipping packet.");
    }
    questions = dns_queries(read_head, buffer, header.qd_count);
    answers = dns_resource_records(read_head, buffer, header.an_count);
    authorities = dns_resource_records(read_head, buffer, header.ns_count);
    additionals = dns_resource_records(read_head, buffer, header.ar_count);
}

std::string dns::to_string()
{
    std::stringstream stream;
    stream << "Questions:" << std::endl;
    stream << questions;
    stream << "Answers:" << std::endl;
    stream << answers;
    stream << "Authorities:" << std::endl;
    stream << authorities;
    stream << "Additionals:" << std::endl;
    stream << additionals;
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, dns& obj)
{
    return stream << obj.to_string();
}
