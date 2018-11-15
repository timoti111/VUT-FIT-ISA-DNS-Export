#pragma once
#include "utils.h"
#include <map>
#include <netinet/tcp.h>
#include "tcp_fragments.h"

class tcp
{
    tcphdr* tcp_{};
    static std::map<uint32_t, tcp_fragments> fragmented_packets_;
public:
    explicit tcp(utils::memory_block& buffer);
};
