/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief ip_fragments class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "../../../utils/utils.h"
#include <map>
#include <vector>

/**
 * @brief Class which assembles IPv4 or IPv6 fragments.
 */
class ip_fragments
{
    uint64_t length_{}; // Here current received length of fragmented packed is stored
    uint64_t whole_length_{}; // Here total length of fragmented packet will be stored when known
    bool last_fragment_received_{}; // If last fragment is received is set to true
    std::map<uint16_t, std::vector<uint8_t>> fragments_{}; // Collected fragments sorted by offset known from packet
    std::vector<uint8_t> reassembled_data_{}; // If possible this represents reassembled packet
public:
    ip_fragments() = default;
    void assembly_data(memory_block& buffer, uint16_t offset, bool last_fragment);
};
