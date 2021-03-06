/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_resource_record class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_resource_record.h"
#include "dns_type.h"
#include <sstream>
#include <netinet/in.h>

/**
 * @brief This constructor reads data from buffer and represents it in DNS Resource Record style
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so record can be decompressed
 */
dns_resource_record::dns_resource_record(memory_block& read_head, memory_block& whole_buffer)
{
    r_name = utils::parse_label_name(read_head, whole_buffer);
    r_type = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    r_class = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    ttl = ntohl(*read_head.get_ptr_and_add<uint32_t>());
    rd_length = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    r_data = dns_type(r_type, read_head, whole_buffer, rd_length);
}

/**
 * @brief Converts resource record to string format.
 * @return String format of resource record.
 */
std::string dns_resource_record::to_string()
{
    std::stringstream stream;
    if (r_data.get_type().find("TYPE") == std::string::npos)
    {
        stream << r_name;
        stream << " " << r_data.get_type();
        stream << " " << r_data;
    }
    return stream.str();
}

/**
 * @brief Allows this class to be appended to stream via << operator.
 * @param stream Stream.
 * @param obj Statistics object.
 * @return To stream.
 */
std::ostream& operator<<(std::ostream& stream, dns_resource_record& obj)
{
    return stream << obj.to_string();
}
