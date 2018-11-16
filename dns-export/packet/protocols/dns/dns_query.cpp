/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_query class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_query.h"
#include "dns_type.h"
#include <netinet/in.h>

/**
 * @brief This constructor reads data from buffer and represents it in DNS question style
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so question can be decompressed
 */
dns_query::dns_query(memory_block& read_head, memory_block& whole_buffer)
{
    q_name = utils::parse_label_name(read_head, whole_buffer);
    q_type = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    q_class = ntohs(*read_head.get_ptr_and_add<uint16_t>());
}
