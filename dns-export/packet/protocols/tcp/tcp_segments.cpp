/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief tcp_segments class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "../../../utils/exceptions.h"
#include <netinet/in.h>
#include "tcp_segments.h"
#include <iostream>

/**
 * @brief This method collects segments and reassembles packet if it is possible.
 * @param buffer Actual pointer to memory.
 * @param seq Relative offset of data from first sequence number in this segmented packet in bytes.
 * @param last_segment If actual segment is last set to true. Now if possible packet is reassembled .If not waits for missing segments.
 */
void tcp_segments::assembly_data(memory_block& buffer, const uint32_t seq, const bool last_segment)
{
    if (segments_.find(seq) == segments_.end())
    {
        if (last_segment)
        {
            last_segment_received_ = true;
        }
        length_ += buffer.size();
        segments_[seq] = std::vector<uint8_t>(buffer.begin(), buffer.end());
        if(segments_.begin()->second.size() >= 2) {
            if (ntohs(*reinterpret_cast<uint16_t*>(segments_.begin()->second.data())) + 2 == length_ &&
                last_segment_received_)
            {
                reassembled_data_.reserve(length_);
                for (auto& fragment : segments_)
                {
                    reassembled_data_.insert(reassembled_data_.end(), fragment.second.data(),
                                             fragment.second.data() + fragment.second.size());
                }
                buffer = memory_block(reassembled_data_.data() + 2, reassembled_data_.size() - 2);
                // std::cerr << "TCP data of length " << buffer.size() << " assembled." << std::endl;
                return;
            }
        }
    }
    throw packet_parsing_error("TCP packet segment. Collected.");
}
