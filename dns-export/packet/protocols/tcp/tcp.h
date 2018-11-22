/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief tcp class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "../../../utils/utils.h"
#include <map>
#include <netinet/tcp.h>
#include "tcp_segments.h"

/**
 * @brief  Class for parsing TCP packets.
 */
class tcp
{
    tcphdr* tcp_{}; // Pointer to TCP header
    static std::map<std::string, tcp_segments> segmented_packets_; // Static map of segmented packets which are from different senders and have different SEQs.
public:
    explicit tcp(memory_block& buffer);
};
