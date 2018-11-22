/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief ipv4 class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "ipv4.h"
#include <sstream>

/**
 * @brief Parses IPv4 packet. If fragmented, collects fragment and skips for now until packet can be assembled.
 * @param buffer Actual pointer to memory of packet.
 */
ipv4::ipv4(memory_block& buffer)
{
    ip_ = buffer.get_ptr<ip>();
    const uint8_t size = ip_->ip_hl * 4; // length of IP header
    buffer += size;
    std::stringstream packet_identification;
    packet_identification << ip_->ip_src.s_addr << " " << ip_->ip_dst.s_addr << " " << ntohs(ip_->ip_id);
    if (ntohs(ip_->ip_off) & IP_MF || ntohs(ip_->ip_off) & IP_OFFMASK)
    {
        fragmented_packets_[packet_identification.str()].assembly_data(
            buffer, ntohs(ip_->ip_off) & IP_OFFMASK,
            !(ntohs(ip_->ip_off) & IP_MF));
    }
    next_type_ = ip_->ip_p;
}

/**
 * @brief Returns type of next layer obtained from IP packet.
 * @return Type of upper layer obtained from IP packet.
 */
uint8_t ipv4::get_next_type() const
{
    return next_type_;
}

std::map<std::string, ip_fragments> ipv4::fragmented_packets_;
