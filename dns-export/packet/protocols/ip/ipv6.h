/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief ipv6 class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "../../../utils/utils.h"
#include <netinet/ip6.h>
#include "ip_fragments.h"
#include <map>

/**
 * @brief Class for parsing IPv6 packets.
 */
class ipv6
{
    ip6_hdr* ip6_{}; // Pointer to basic IPv6 header
    ip6_ext* ip6_ext_{}; // Pointer to extension IPv6 header
    ip6_frag* ip6_frag_{}; // Pointer to fragment IPv6 header
    uint32_t next_type_{}; // Next type got from IPv6 header
    static std::map<std::string, ip_fragments> fragmented_packets_; // Static map of fragmented packets which are from different senders and have different IDs.
public:
    explicit ipv6(memory_block& buffer, uint32_t next_type);
    uint8_t get_next_type() const;
};
