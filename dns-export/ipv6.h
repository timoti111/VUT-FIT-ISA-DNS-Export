#pragma once
#include "dns_utils.h"
#include <netinet/ip6.h>
#include <map>
#include "ip_fragments.h"

class ipv6
{
	ip6_hdr* ip6_;
	ip6_frag* ip6_frag_;
    uint8_t next_type_;
	static std::map<uint32_t, ip_fragments> fragments_;
public:
    explicit ipv6(dns_utils::memory_block &buffer);
	u_int8_t get_next_type();
};

