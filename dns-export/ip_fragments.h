#pragma once
#include <vector>
#include <cstdint>
#include <map>
#include "dns_utils.h"

class ip_fragments
{
	uint64_t length_;
	uint64_t whole_length_;
	bool last_fragment_received_;
	std::map<uint16_t, std::vector<unsigned char>> fragments_{};
	std::vector<unsigned char> reassembled_data_{};
public:
	ip_fragments() : length_(0), whole_length_(0), last_fragment_received_(false)
	{	    
	}
    void assembly_data(dns_utils::memory_block& buffer, uint16_t offset, bool last_fragment);
};

