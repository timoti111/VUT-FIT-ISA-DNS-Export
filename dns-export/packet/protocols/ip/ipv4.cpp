/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief ipv4 class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "ipv4.h"

ipv4::ipv4(memory_block& buffer)
{
    ip_ = buffer.get_ptr<ip>();
    const uint8_t size = ip_->ip_hl * 4; // length of IP header
    buffer += size;
    if (ntohs(ip_->ip_off) & IP_MF || ntohs(ip_->ip_off) & IP_OFFMASK)
    {
        fragmented_packets_[ntohs(ip_->ip_id)].assembly_data(buffer, ntohs(ip_->ip_off) & IP_OFFMASK,
                                                             !(ntohs(ip_->ip_off) & IP_MF));
    }
    next_type_ = ip_->ip_p;
}

uint8_t ipv4::get_next_type() const
{
    return next_type_;
}

std::map<uint16_t, ip_fragments> ipv4::fragmented_packets_;
