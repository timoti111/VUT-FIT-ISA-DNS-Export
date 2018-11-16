/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_header class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_header.h"
#include <netinet/in.h>

/**
 * @brief This constructor reads data from buffer and represents it in DNS Header style
 * @param read_head reference to memory where read head is currently
 */
dns_header::dns_header(memory_block& read_head)
{
    id = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    flags_ = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    qd_count = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    an_count = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    ns_count = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    ar_count = ntohs(*read_head.get_ptr_and_add<uint16_t>());
    flags.qr |= (flags_ >> 15) & 1;
    flags.op_code |= (flags_ >> 11) & 15;
    flags.aa |= (flags_ >> 10) & 1;
    flags.tc |= (flags_ >> 9) & 1;
    flags.rd |= (flags_ >> 8) & 1;
    flags.ra |= (flags_ >> 7) & 1;
    flags.z |= (flags_ >> 4) & 7;
    flags.r_code |= flags_ & 15;
}
