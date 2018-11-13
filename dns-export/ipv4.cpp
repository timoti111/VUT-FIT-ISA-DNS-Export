#include "ipv4.h"
#include "error.h"

ipv4::ipv4(dns_utils::memory_block &buffer)
{
	next_type_ = 0;
	if (buffer.length >= sizeof(ip))
	{
		ip_ = reinterpret_cast<ip*>(buffer.ptr); // skip Ethernet header
		long long size = ip_->ip_hl * 4; // length of IP header
		buffer.length -= size;
		buffer.ptr += size;
		if (ntohs(ip_->ip_off) & IP_MF || ntohs(ip_->ip_off) & IP_OFFMASK)
		{
			fragments_[ntohs(ip_->ip_id)].assembly_data(buffer, ntohs(ip_->ip_off) & IP_OFFMASK, !(ntohs(ip_->ip_off) & IP_MF));
		}
		next_type_ = ip_->ip_p;
	}
	else
	{
		throw packet_parsing_error("Not IPv4 packet. Skipping.");
	}
}

u_int8_t ipv4::get_next_type()
{
	return next_type_;
}

std::map<uint16_t, ip_fragments> ipv4::fragments_;
