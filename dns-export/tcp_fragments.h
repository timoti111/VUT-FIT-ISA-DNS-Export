#pragma once
#include <cstdint>
#include "dns_utils.h"
#include <map>

class tcp_fragments
{
	uint64_t length_;
	bool last_fragment_received_;
	std::map<uint32_t, std::vector<unsigned char>> fragments_{};
	std::vector<unsigned char> reassembled_data_{};

public:
	tcp_fragments() : length_(0), last_fragment_received_(false)
	{
	}
	void assembly_data(dns_utils::memory_block& buffer, uint32_t seq, bool last_fragment);
};

