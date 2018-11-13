#include "ip_fragments.h"
#include "error.h"

void ip_fragments::assembly_data(dns_utils::memory_block& buffer, const uint16_t offset, const bool last_fragment)
{
	if (buffer.length >= 0)
	{
	    if (last_fragment)
	    {
		    whole_length_ = offset * 8 + buffer.length;
		    last_fragment_received_ = true;
	    }
		length_ += buffer.length;
		fragments_[offset] = std::vector<unsigned char>(buffer.ptr, buffer.ptr + buffer.length);
		if (whole_length_ == length_ && last_fragment_received_)
		{
			reassembled_data_.reserve(length_);
			for (auto fragment : fragments_)
			{
				reassembled_data_.insert(reassembled_data_.end(), fragment.second.data(), fragment.second.data() + fragment.second.size());
			}
			buffer.ptr = reassembled_data_.data();
			buffer.length = reassembled_data_.size();
			std::cerr << "IP data of length " << buffer.length << " assembbled." << std::endl;
			return;
		}
	}
	throw packet_parsing_error("IPv4 packet fragment. Collected.");
}
