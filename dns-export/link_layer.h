#pragma once
#include <cstdint>
#include <net/ethernet.h>
#include "dns_utils.h"

class link_layer
{
	const static uint16_t IPv4 = 4;
	const static uint16_t IPv6 = 41;
	const static uint16_t TCP = 6;
	const static uint16_t UDP = 17;
	static void parse_next_layers(dns_utils::memory_block buffer, uint16_t next_type);
public:
	static void parse_packet(const unsigned char* buffer, long length, int link_type, const int packet_num);
};

