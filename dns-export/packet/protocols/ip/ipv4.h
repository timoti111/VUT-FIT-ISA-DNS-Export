/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief ipv4 class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "../../../utils/utils.h"
#include <netinet/ip.h>
#include "ip_fragments.h"
#include <map>

 /**
  * @brief Class for parsing IPv4 packets.
  */
class ipv4
{
    ip* ip_{}; // IPv4 header pointer
    uint8_t next_type_{}; // Next type got from IPv4 header
    static std::map<std::string, ip_fragments> fragmented_packets_; // Static map of fragmented packets which are from different senders and have different IDs.
public:
    explicit ipv4(memory_block& buffer);
    uint8_t get_next_type() const;
};
