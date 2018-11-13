#include "ipv6.h"
#include "error.h"

ipv6::ipv6(dns_utils::memory_block &buffer)
{
	next_type_ = 0;
	if (buffer.length >= sizeof(ip6_hdr))
	{
		ip6_ = reinterpret_cast<ip6_hdr*>(buffer.ptr); // skip Ethernet header
		buffer.length -= sizeof(ip6_hdr);
		buffer.ptr += sizeof(ip6_hdr);
		next_type_ = ip6_->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        if (next_type_ == 44)
        {
			if (buffer.length >= sizeof(ip6_frag))
			{
				ip6_frag_ = reinterpret_cast<ip6_frag*>(buffer.ptr); // skip Ethernet header
				buffer.length -= sizeof(ip6_frag);
				buffer.ptr += sizeof(ip6_frag);
				fragments_[ntohl(ip6_frag_->ip6f_ident)].assembly_data(buffer, ntohs(ip6_frag_->ip6f_offlg) & IP6F_OFF_MASK, !(ntohs(ip6_frag_->ip6f_offlg) & IP6F_MORE_FRAG));
				next_type_ = ip6_->ip6_ctlun.ip6_un1.ip6_un1_nxt;
			}
        }
	}
	else
	{
		throw packet_parsing_error("Not IPv6 packet. Skipping.");
	}
}

u_int8_t ipv6::get_next_type()
{
	return next_type_;
}

std::map<uint32_t, ip_fragments> ipv6::fragments_;
