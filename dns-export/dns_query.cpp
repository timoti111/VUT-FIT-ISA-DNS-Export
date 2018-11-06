/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSQuestion class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_query.h"
#include "dns_utils.h"
#include <sstream>
#include "dns_type.h"

/**
 * This constructor reads data from buffer and represents it in DNS Question style
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so question can be decompressed
 */
dns_query::dns_query(dns_utils::memory_block& read_head, dns_utils::memory_block& whole_buffer)
{
    q_name = dns_utils::parse_name(read_head, whole_buffer);
    q_type = dns_utils::mem_to_uint16(read_head);
    q_class = dns_utils::mem_to_uint16(read_head);
}

std::string dns_query::to_string() const
{
    std::stringstream stream;
    stream << dns_utils::label_to_string(q_name);
    stream << " " << "IN";
    stream << " " << dns_type::get_type_name(q_type);
    stream << std::endl;
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, dns_query& obj)
{
    return stream << obj.to_string();
}
