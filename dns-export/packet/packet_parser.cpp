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

/**
 * @brief Tries to parse all lower layers of packet and if gets to topmost layer tries to parse it as DNS data.
 * @param buffer Actual pointer to memory of packet.
 * @param next_type Type of actual layer data.
 */
void packet_parser::parse_next_layers(memory_block& buffer, uint16_t next_type)
{
    auto topmost_layer = false;
    while (!topmost_layer)
    {
        switch (next_type)
        {
            case IPv4: case ETHERTYPE_IP:
            {
                ipv4 ipv4_(buffer);
                next_type = ipv4_.get_next_type();
                break;
            }
            case IPv6: case ETHERTYPE_IPV6: case 0: case 43: case 44: case 50: case 51: case 59: case 60:  case 135:
            {
                ipv6 ipv6_(buffer, next_type);
                next_type = ipv6_.get_next_type();
                break;
            }
            case TCP:
            {
                tcp tcp_(buffer);
                topmost_layer = true;
                break;
            }
            case UDP:
            {
                if (ntohs(*buffer.get_ptr<uint16_t>()) != 53) // skip packet if source port is not 53
                {
                    throw packet_parsing_error("Not port 53. Skipping.");
                }
                buffer += 8;
                topmost_layer = true;
                break;
            }
            default:
            {
                throw packet_parsing_error("Unknown packet type.");
            }
        }
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
}

/**
 * @brief Tries to parse packet. Supports 4 link types.
 * @param whole_buffer Actual pointer to memory of packet.
 * @param link_type Type of link layer data.
 */
packet_parser::packet_parser(memory_block& whole_buffer, const int link_type)
{
    uint16_t next_type;
    switch (link_type)
    {
        case DLT_RAW:
        {
            uint8_t type = *whole_buffer.get_ptr<uint8_t>() >> 4;
            switch (type)
            {
                case 4:
                    next_type = IPv4;
                    break;
                case 6:
                    next_type = IPv6;
                    break;
                default:
                    throw packet_parsing_error("Unknown link type protocol. Skipping packet!");
            }
            break;
        }
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
