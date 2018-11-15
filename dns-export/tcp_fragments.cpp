/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief tcp_fragments class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "exceptions.h"
#include <netinet/in.h>
#include "tcp_fragments.h"

void tcp_fragments::assembly_data(utils::memory_block& buffer, const uint32_t seq, const bool last_fragment)
{
    if (fragments_.find(seq) == fragments_.end())
    {
        if (last_fragment)
        {
            last_fragment_received_ = true;
        }
        length_ += buffer.size();
        fragments_[seq] = std::vector<uint8_t>(buffer.begin(), buffer.end());
        if (ntohs(*reinterpret_cast<uint16_t*>(fragments_.begin()->second.data())) + 2 == length_ &&
            last_fragment_received_)
        {
            reassembled_data_.reserve(length_);
            for (auto& fragment : fragments_)
            {
                reassembled_data_.insert(reassembled_data_.end(), fragment.second.data(),
                                         fragment.second.data() + fragment.second.size());
            }
            buffer = utils::memory_block(reassembled_data_.data() + 2, reassembled_data_.size() - 2);
            std::cerr << "TCP data of length " << buffer.size() << " assembled." << std::endl;
            return;
        }
    }
    throw packet_parsing_error("TCP packet fragment. Collected.");
}
