#pragma once
#include "utils.h"
#include <netinet/ip6.h>
#include "ip_fragments.h"
#include <map>

class ipv6
{
    ip6_hdr* ip6_{};
    ip6_frag* ip6_frag_{};
    uint8_t next_type_{};
    static std::map<uint32_t, ip_fragments> fragmented_packets_;
public:
    explicit ipv6(utils::memory_block& buffer);
    uint8_t get_next_type() const;
};
