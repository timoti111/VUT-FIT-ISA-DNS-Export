/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief tcp class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "../../../utils/exceptions.h"
#include <netinet/in.h>
#include "tcp.h"
#include <sstream>

/**
 * @brief Parses TCP packet. If segmented, collects segment and skips for now until packet can be assembled.
 * @param buffer Actual pointer to memory of packet.
 */
tcp::tcp(memory_block& buffer)
{
    std::stringstream packet_identification;
    tcp_ = buffer.get_ptr<tcphdr>();
    const uint8_t size = tcp_->doff * 4;
    buffer += size;
    if (ntohs(tcp_->source) != 53)
    {
        throw packet_parsing_error("Not port 53. Skipping.");
    }
    packet_identification << ntohs(tcp_->source) << "_" << ntohs(tcp_->dest) << "_" << ntohl(tcp_->ack_seq);
    segmented_packets_[packet_identification.str()].assembly_data(buffer, ntohl(tcp_->seq), tcp_->ack && tcp_->psh);
}

std::map<std::string, tcp_segments> tcp::segmented_packets_;
