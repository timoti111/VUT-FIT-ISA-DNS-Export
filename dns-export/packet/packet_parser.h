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
    const static uint16_t IPv4 = 4;
    const static uint16_t IPv6 = 41;
    const static uint16_t TCP = 6;
    const static uint16_t UDP = 17;
    static void parse_next_layers(memory_block& buffer, uint32_t next_type);
public:
    packet_parser(const uint8_t* buffer, uint32_t length, int link_type, uint32_t packet_num);
};
