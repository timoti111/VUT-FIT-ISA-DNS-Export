/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief packet_parser class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "protocols/dns/dns.h"
#include "../utils/utils.h"
#include "../utils/exceptions.h"
#include <net/ethernet.h>
#include "protocols/ip/ipv4.h"
#include "protocols/ip/ipv6.h"
#include "packet_parser.h"
#include <pcap/pcap.h>
#include "../statistics/statistics.h"
#include "protocols/tcp/tcp.h"
#include <iostream>

void packet_parser::parse_next_layers(memory_block& buffer, uint32_t next_type)
{
    auto packet_parsed = false;
    while (!packet_parsed)
    {
        switch (next_type)
        {
            case IPv4: case ETHERTYPE_IP:
            {
                ipv4 ipv4_(buffer);
                next_type = ipv4_.get_next_type();
                break;
            }
            case IPv6: case ETHERTYPE_IPV6:
            {
                ipv6 ipv6_(buffer);
                next_type = ipv6_.get_next_type();
                break;
            }
            case TCP:
            {
                tcp tcp_(buffer);
                next_type = 0xffffffff;
                break;
            }
            case UDP:
            {
                if (ntohs(*buffer.get_ptr<uint16_t>()) != 53) // skip packet if source port is not 53
                {
                    throw packet_parsing_error("Not port 53. Skipping.");
                }
                buffer += 8;
                next_type = 0xffffffff;
                break;
            }
            default:
            {
                if (next_type != 0xffffffff)
                {
                    throw packet_parsing_error("Unknown packet type.");
                }
                dns dns_(buffer);
                if (dns_.header.flags.qr == 0 || dns_.header.an_count == 0)
                {
                    throw dns_parsing_error("DNS packet is not response. Skipping packet.");
                }
                if (dns_.answers.size() != 0)
                {
                    statistics::get_instance().add(dns_.answers.records);
                }
                packet_parsed = true;
                break;
            }
        }
    }
}

packet_parser::packet_parser(const uint8_t* buffer, const uint32_t length, const int link_type,
                             const uint32_t packet_num)
{
    try
    {
        uint32_t next_type;
        memory_block whole_buffer{const_cast<uint8_t*>(buffer), length};
        switch (link_type)
        {
            case DLT_EN10MB:
                next_type = ntohs(whole_buffer.get_ptr_and_add<ether_header>()->ether_type);
                break;
            case DLT_LINUX_SLL:
                whole_buffer += 14;
                next_type = ntohs(*whole_buffer.get_ptr_and_add<uint16_t>());
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
        parse_next_layers(whole_buffer, next_type);
    }
    catch (dns_parsing_error& e)
    {
        std::cerr << "Packet number: " << packet_num << " Packet len: " << length << std::endl;
        std::cerr << "\t" << e.what() << std::endl;
    }
    catch (packet_parsing_error& e)
    {
        std::cerr << "Packet number: " << packet_num << " Packet len: " << length << std::endl;
        std::cerr << "\t" << e.what() << std::endl;
    }
    catch (memory_error& e)
    {
        std::cerr << "Packet number: " << packet_num << " Packet len: " << length << std::endl;
        std::cerr << "\t" << e.what() << std::endl;
    }
    catch (other_error& e)
    {
        std::cerr << "Packet number: " << packet_num << " Packet len: " << length << std::endl;
        std::cerr << "\t" << e.what() << std::endl;
    }
}
