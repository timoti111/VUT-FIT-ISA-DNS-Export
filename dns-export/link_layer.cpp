#include "link_layer.h"
#include "dns_utils.h"
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include "error.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "dns.h"
#include "statistics.h"

void link_layer::parse_next_layers(dns_utils::memory_block buffer, uint16_t next_type)
{
    auto upper_layers = true;
	while (upper_layers)
	{
		switch (next_type)
		{
		case IPv4:
		case ETHERTYPE_IP:
		{
			ipv4 ipv4_(buffer);
			next_type = ipv4_.get_next_type();
			break;
		}
		case IPv6:
		case ETHERTYPE_IPV6:
		{
			ipv6 ipv6_(buffer);
			next_type = ipv6_.get_next_type();
			break;
		}
		case TCP:
		{
			tcp tcp_(buffer);
			next_type = 0;
			break;
		}
		case UDP:
		{
            if (ntohs(*reinterpret_cast<uint16_t*>(buffer.ptr)) != 53) // skip packet if source port is not 53
			{
				throw packet_parsing_error("Not DNS packet. Skipping.");
			}
			buffer.length -= 8;
			buffer.ptr += 8;
			next_type = 0;
			break;
		}
		default:
		{
			dns dns_(buffer);
			if (dns_.header.flags.qr == 0 || dns_.header.an_count == 0)
			{
				throw dns_parsing_error("DNS packet is not response. Skipping packet.");
			}
			if (dns_.answers.size() != 0)
			{
				statistics::get_instance().add(dns_.answers.records);
			}
			upper_layers = false;
			break;
		}
		}
	}
}

void link_layer::parse_packet(const unsigned char* buffer, const long length, const int link_type, const int packet_num)
{
	try
	{
	    uint16_t size_link = 0;
	    uint16_t next_type = 0;
	    dns_utils::memory_block whole_buffer{ const_cast<unsigned char*>(buffer), length };
        switch(link_type)
	    {
	    case DLT_EN10MB:
		    size_link = ETHER_HDR_LEN;
		    next_type = ntohs(*reinterpret_cast<uint16_t*>(whole_buffer.ptr + ETHER_HDR_LEN - 2));
		    break;
	    case DLT_LINUX_SLL:
		    size_link = 16;
	        next_type = ntohs(*reinterpret_cast<uint16_t*>(whole_buffer.ptr + 14));
		    break;
	    case DLT_IPV4:
		    next_type = IPv4;
		    break;
	    case DLT_IPV6:
		    next_type = IPv6;
		    break;
	    default:
		    throw packet_parsing_error("Unknown link type protocol. Skipping packet!");
	    }

	    whole_buffer.length -= size_link;
	    whole_buffer.ptr += size_link;
	    parse_next_layers(whole_buffer, next_type);
	}
	catch (dns_parsing_error& e)
	{
		/*std::cerr << "Packet number: " << packet_num << " Packet len: " << length << std::endl;
		std::cerr << "\t" << e.what() << std::endl;*/
	}
	catch (packet_parsing_error& e)
	{
		std::cerr << "Packet number: " << packet_num << " Packet len: " << length << std::endl;
		std::cerr << "\t" << e.what() << std::endl;
	}
}
