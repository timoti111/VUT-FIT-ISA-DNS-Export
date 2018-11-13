#include "tcp_fragments.h"
#include <netinet/in.h>
#include "error.h"

void tcp_fragments::assembly_data(dns_utils::memory_block& buffer, const uint32_t seq, const bool last_fragment)
{
	if (buffer.length >= 0)
	{
        if (last_fragment)
        {
		    last_fragment_received_ = true;
        }
		length_ += buffer.length;
		fragments_[seq] = std::vector<unsigned char>(buffer.ptr, buffer.ptr + buffer.length);
		if (ntohs(*reinterpret_cast<uint16_t*>(fragments_.begin()->second.data())) + 2 == length_ && last_fragment_received_)
		{
			reassembled_data_.reserve(length_);
			for (auto fragment : fragments_)
			{
				reassembled_data_.insert(reassembled_data_.end(), fragment.second.data(), fragment.second.data() + fragment.second.size());
			}
			buffer.ptr = reassembled_data_.data() + 2;
			buffer.length = reassembled_data_.size() - 2;
			std::cerr << "TCP data of length " << buffer.length << " assembbled." << std::endl;
			return;
		}
	}
	throw packet_parsing_error("TCP packet fragment. Collected.");
}
