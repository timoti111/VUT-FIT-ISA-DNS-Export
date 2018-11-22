/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief ipv6 class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "ipv6.h"
#include <net/ethernet.h>
#include <sstream>

/**
 * @brief Parses IPv6 packet. If fragmented, collects fragment and skips for now until packet can be assembled. Skips extension headers too.
 * @param buffer Actual pointer to memory of packet.
 * @param next_type Type of actual layer data.
 */
ipv6::ipv6(memory_block& buffer, const uint32_t next_type)
{
    next_type_ = next_type;
    auto is_ipv6_header = true;
    std::stringstream packet_identification;
    while (is_ipv6_header)
    {
        switch (next_type_)
        {
            case 0: case 43: case 60: case 135:
                ip6_ext_ = buffer.get_ptr<ip6_ext>();
                buffer += 8 + ip6_ext_->ip6e_len * 8;
                next_type_ = ip6_ext_->ip6e_nxt;
                break;
            case 41: case ETHERTYPE_IPV6:
                ip6_ = buffer.get_ptr_and_add<ip6_hdr>();
                if (ntohs(ip6_->ip6_ctlun.ip6_un1.ip6_un1_plen) > buffer.size())
                {
                    throw packet_parsing_error("Packet is corrupted.");
                }
                next_type_ = ip6_->ip6_ctlun.ip6_un1.ip6_un1_nxt;
                for (auto byte : ip6_->ip6_src.__in6_u.__u6_addr8)
                {
                    packet_identification << static_cast<unsigned>(byte);
                }
                packet_identification << "_";
                for (auto byte : ip6_->ip6_dst.__in6_u.__u6_addr8)
                {
                    packet_identification << static_cast<unsigned>(byte);
                }
                packet_identification << "_";
                break;
            case 44:
                ip6_frag_ = buffer.get_ptr_and_add<ip6_frag>();
                packet_identification << ntohl(ip6_frag_->ip6f_ident);
                fragmented_packets_[packet_identification.str()].assembly_data(
                    buffer, ntohs(ip6_frag_->ip6f_offlg & IP6F_OFF_MASK) >> 3,
                    !(ip6_frag_->ip6f_offlg & IP6F_MORE_FRAG));
                next_type_ = ip6_frag_->ip6f_nxt;
                break;
            case 50:
                throw packet_parsing_error("Encrypted packet. Skip.");
            case 51:
                ip6_ext_ = buffer.get_ptr<ip6_ext>();
                buffer += 8 + ip6_ext_->ip6e_len * 4;
                next_type_ = ip6_ext_->ip6e_nxt;
            case 59:
                throw packet_parsing_error("No next header. Skip.");
            default:
                is_ipv6_header = false;
        }
    }
}

/**
 * @brief Returns type of next layer obtained from IP packet.
 * @return Type of upper layer obtained from IP packet.
 */
uint8_t ipv6::get_next_type() const
{
    return next_type_;
}

std::map<std::string, ip_fragments> ipv6::fragmented_packets_;
