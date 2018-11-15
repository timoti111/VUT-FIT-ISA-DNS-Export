#pragma once
#include <cstdint>
#include "utils.h"

class packet_parser
{
    const static uint16_t IPv4 = 4;
    const static uint16_t IPv6 = 41;
    const static uint16_t TCP = 6;
    const static uint16_t UDP = 17;
    static void parse_next_layers(utils::memory_block& buffer, uint32_t next_type);
public:
    packet_parser(const uint8_t* buffer, uint32_t length, int link_type, uint32_t packet_num);
};
