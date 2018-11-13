#pragma once
#include "dns_utils.h"
#include <netinet/ip.h>
#include "ip_fragments.h"
#include <map>

class ipv4
{
	ip* ip_{};
    u_int8_t next_type_;
	static std::map<uint16_t, ip_fragments> fragments_;
public:
    explicit ipv4(dns_utils::memory_block &buffer);
	u_int8_t get_next_type();
};

