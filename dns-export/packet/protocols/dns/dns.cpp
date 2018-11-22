/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns.h"
#include "../../../utils/utils.h"
#include "../../../utils/exceptions.h"

/**
 * @brief This constructor parses whole DNS message from buffer
 * @param buffer Pointer to memory which will be parsed as DNS message.
 */
dns::dns(memory_block& buffer)
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
    questions = dns_questions(read_head, buffer, header.qd_count);
    answers = dns_resource_records(read_head, buffer, header.an_count);
    authorities = dns_resource_records(read_head, buffer, header.ns_count);
    additionals = dns_resource_records(read_head, buffer, header.ar_count);
}
