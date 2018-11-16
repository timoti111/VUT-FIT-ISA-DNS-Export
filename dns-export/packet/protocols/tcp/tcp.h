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
#include "tcp_fragments.h"

class tcp
{
    tcphdr* tcp_{};
    static std::map<uint32_t, tcp_fragments> fragmented_packets_;
public:
    explicit tcp(memory_block& buffer);
};
