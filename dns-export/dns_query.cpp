/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief dns_query class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_query.h"
#include "dns_type.h"
#include "utils.h"
#include <sstream>
#include <netinet/in.h>

/**
 * This constructor reads data from buffer and represents it in DNS Question style
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so question can be decompressed
 */
dns_query::dns_query(utils::memory_block& read_head, utils::memory_block& whole_buffer)
{
    q_name = utils::parse_name(read_head, whole_buffer);
    q_type = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    q_class = ntohs(*read_head.get_ptr_and_add<uint16_t>());
}

std::string dns_query::to_string() const
{
    std::stringstream stream;
    stream << q_name;
    stream << " " << "IN";
    stream << " " << dns_type::get_type_name(q_type);
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, dns_query& obj)
{
    return stream << obj.to_string();
}
