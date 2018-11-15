#pragma once
#include <cstdint>
#include "utils.h"
#include <map>
#include <vector>

class ip_fragments
{
    uint64_t length_{};
    uint64_t whole_length_{};
    bool last_fragment_received_{};
    std::map<uint16_t, std::vector<uint8_t>> fragments_{};
    std::vector<uint8_t> reassembled_data_{};
public:
    ip_fragments() = default;
    void assembly_data(utils::memory_block& buffer, uint16_t offset, bool last_fragment);
};
