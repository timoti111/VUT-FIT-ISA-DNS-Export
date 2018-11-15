/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief tcp class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "exceptions.h"
#include <netinet/in.h>
#include "tcp.h"

tcp::tcp(utils::memory_block& buffer)
{
    tcp_ = buffer.get_ptr<tcphdr>();
    const uint8_t size = tcp_->doff * 4;
    buffer += size;
    fragmented_packets_[ntohl(tcp_->ack_seq)].assembly_data(buffer, ntohl(tcp_->seq), tcp_->ack && tcp_->psh);
    if (ntohs(tcp_->source) != 53)
    {
        throw packet_parsing_error("Not port 53. Skipping.");
    }
}

std::map<uint32_t, tcp_fragments> tcp::fragmented_packets_;
