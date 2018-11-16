/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief tcp_fragments class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "../../../utils/utils.h"
#include <map>
#include <vector>

class tcp_fragments
{
    uint64_t length_{};
    bool last_fragment_received_{};
    std::map<uint32_t, std::vector<uint8_t>> fragments_{};
    std::vector<uint8_t> reassembled_data_{};
public:
    tcp_fragments() = default;
    void assembly_data(memory_block& buffer, uint32_t seq, bool last_fragment);
};
