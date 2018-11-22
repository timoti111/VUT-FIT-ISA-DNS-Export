/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief tcp_segments class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "../../../utils/utils.h"
#include <map>
#include <vector>

/**
 * @brief Class which assembles TCP segments.
 */
class tcp_segments
{
    uint64_t length_{}; // Here current received length of segmented packed is stored
    bool last_segment_received_{}; // If last segment is received is set to true
    std::map<uint32_t, std::vector<uint8_t>> segments_{}; // Collected segments sorted by offset known from packet
    std::vector<uint8_t> reassembled_data_{}; // If possible this represents reassembled packet
public:
    tcp_segments() = default;
    void assembly_data(memory_block& buffer, uint32_t seq, bool last_segment);
};
