#include "tcp.h"
#include <netinet/in.h>
#include "error.h"

tcp::tcp(dns_utils::memory_block &buffer)
{
	if (buffer.length >= sizeof(tcphdr))
	{
		tcp_ = reinterpret_cast<tcphdr*>(buffer.ptr); // pointer to the TCP header       
		uint8_t size = tcp_->doff * 4;
		buffer.length -= size;
		buffer.ptr += size;
		fragments_[ntohl(tcp_->ack_seq)].assembly_data(buffer, ntohl(tcp_->seq), tcp_->ack && tcp_->psh);
		if (ntohs(tcp_->source) != 53)
		{
			throw packet_parsing_error("Not DNS packet. Skipping.");
		}

	}
	else
	{
		throw packet_parsing_error("Not ipv4 packet. Skipping.");
	}
}

std::map<uint32_t, tcp_fragments> tcp::fragments_;
