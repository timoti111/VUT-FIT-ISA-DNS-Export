/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResponse class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_packet.h"
#include "error.h"
#include <sstream>
#include "dns_utils.h"

/**
 * This constructor parses whole DNS response from buffer
 * @param buffer buffer to parse from
 * @param length
 */
dns_packet::dns_packet(const unsigned char* buffer, const long length)
{
    dns_utils::memory_block whole_buffer{const_cast<unsigned char*>(buffer), length};
    dns_utils::memory_block read_head{const_cast<unsigned char*>(buffer), length};
    header = dns_header(read_head);
    if (header.flags.tc == 1)
    {
        throw dns_parsing_error("Truncated response!");
    }
    if (header.flags.r_code != 0)
    {
        throw dns_parsing_error("DNS server error!");
    }
    questions = dns_queries(read_head, whole_buffer, header.qd_count);
    answers = dns_resource_records(read_head, whole_buffer, header.an_count);
    authorities = dns_resource_records(read_head, whole_buffer, header.ns_count);
    additionals = dns_resource_records(read_head, whole_buffer, header.ar_count);
}

std::string dns_packet::to_string()
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

std::ostream& operator<<(std::ostream& stream, dns_packet& obj)
{
    return stream << obj.to_string();
}
