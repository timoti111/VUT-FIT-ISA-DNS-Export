/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief packet_parser class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "../utils/utils.h"

class packet_parser
{
    const static uint16_t IPv4 = 4; // IPv4 packet number
    const static uint16_t IPv6 = 41; // IPv6 packet number
    const static uint16_t TCP = 6; // TCP packet number
    const static uint16_t UDP = 17; // UDP packet number
    static void parse_next_layers(memory_block& buffer, uint16_t next_type);
public:
    packet_parser(memory_block& whole_buffer, int link_type);
};
