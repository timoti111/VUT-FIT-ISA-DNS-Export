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

class ipv4
{
    ip* ip_{};
    uint8_t next_type_{};
    static std::map<uint16_t, ip_fragments> fragmented_packets_;
public:
    explicit ipv4(memory_block& buffer);
    uint8_t get_next_type() const;
};
