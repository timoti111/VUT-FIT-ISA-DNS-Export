/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSHeader class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_header.h"

/**
 * This constructor reads data from buffer and represents it in DNS Header style
 * @param read_head reference to memory where read head is currently
 */
dns_header::dns_header(dns_utils::memory_block& read_head)
{
    id = dns_utils::mem_to_uint16(read_head);
    flags_ = dns_utils::mem_to_uint16(read_head);
    qd_count = dns_utils::mem_to_uint16(read_head);
    an_count = dns_utils::mem_to_uint16(read_head);
    ns_count = dns_utils::mem_to_uint16(read_head);
    ar_count = dns_utils::mem_to_uint16(read_head);
    flags.qr |= (flags_ >> 15) & 1;
    flags.op_code |= (flags_ >> 11) & 15;
    flags.aa |= (flags_ >> 10) & 1;
    flags.tc |= (flags_ >> 9) & 1;
    flags.rd |= (flags_ >> 8) & 1;
    flags.ra |= (flags_ >> 7) & 1;
    flags.z |= (flags_ >> 4) & 7;
    flags.r_code |= flags_ & 15;
}
