/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResourceRecord class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_resource_record.h"
#include "dns_utils.h"
#include <sstream>
#include "dns_type.h"

/**
 * This constructor reads data from buffer and represents it in DNS Resource Record style
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so record can be decompressed
 */
dns_resource_record::dns_resource_record(dns_utils::memory_block& read_head, dns_utils::memory_block& whole_buffer)
{
    r_name = dns_utils::parse_name(read_head, whole_buffer);
    r_type = dns_utils::mem_to_uint16(read_head);
    r_class = dns_utils::mem_to_uint16(read_head);
    ttl = dns_utils::mem_to_uint32(read_head);
    rd_length = dns_utils::mem_to_uint16(read_head);
    r_data = dns_type(r_type, read_head, whole_buffer, rd_length);
}

std::string dns_resource_record::to_string()
{
    std::stringstream stream;
    if (r_data.get_type().find("TYPE") == std::string::npos)
    {
        stream << dns_utils::label_to_string(r_name);
        stream << " " << r_data.get_type();
        stream << " " << r_data;
    }
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, dns_resource_record& obj)
{
    return stream << obj.to_string();
}
