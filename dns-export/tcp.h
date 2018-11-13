#pragma once
#include "dns_utils.h"
#include <netinet/tcp.h>
#include <map>
#include "tcp_fragments.h"

class tcp
{
	tcphdr* tcp_{};
	static std::map<uint32_t, tcp_fragments> fragments_;
public:
    explicit tcp(dns_utils::memory_block &buffer);
};

