/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief ipv6 class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "ipv6.h"

ipv6::ipv6(utils::memory_block& buffer)
{
    ip6_ = buffer.get_ptr_and_add<ip6_hdr>();
    next_type_ = ip6_->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    if (next_type_ == 44)
    {
        ip6_frag_ = buffer.get_ptr_and_add<ip6_frag>();
        fragmented_packets_[ntohl(ip6_frag_->ip6f_ident)].assembly_data(
            buffer, ntohs(ip6_frag_->ip6f_offlg) & IP6F_OFF_MASK,
            !(ntohs(ip6_frag_->ip6f_offlg) & IP6F_MORE_FRAG));
        next_type_ = ip6_->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    }
}

uint8_t ipv6::get_next_type() const
{
    return next_type_;
}

std::map<uint32_t, ip_fragments> ipv6::fragmented_packets_;
