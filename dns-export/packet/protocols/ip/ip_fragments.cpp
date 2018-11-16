/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief ip_fragments class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "ip_fragments.h"
#include "../../../utils/exceptions.h"
#include <iostream>

void ip_fragments::assembly_data(memory_block& buffer, const uint16_t offset, const bool last_fragment)
{
    if (fragments_.find(offset) == fragments_.end())
    {
        if (last_fragment)
        {
            whole_length_ = offset * 8 + buffer.size();
            last_fragment_received_ = true;
        }
        length_ += buffer.size();
        fragments_[offset] = std::vector<uint8_t>(buffer.begin(), buffer.end());
        if (whole_length_ == length_ && last_fragment_received_)
        {
            reassembled_data_.reserve(length_);
            for (auto& fragment : fragments_)
            {
                reassembled_data_.insert(reassembled_data_.end(), fragment.second.data(),
                                         fragment.second.data() + fragment.second.size());
            }
            buffer = memory_block(reassembled_data_.data(), reassembled_data_.size());
            std::cerr << "IP data of length " << buffer.size() << " assembled." << std::endl;
            return;
        }
    }
    throw packet_parsing_error("IP packet fragment. Collected.");
}
