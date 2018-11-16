/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_packet_capture class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <pcap.h>
#include <string>

/**
 * @brief Class which uses pcap library for capturing packets.
 */
class dns_packet_capture
{
    const int snap_len_ = 1518; // specifies the snapshot length to be set on the handle
    char err_buf_[PCAP_ERRBUF_SIZE]{}; // error buffer for pcap
    pcap_t* handle_{}; // packet capture handle
    int link_type_{}; // type of header on link layer
    int next_packet() const;
public:
    dns_packet_capture() = default;
    ~dns_packet_capture();
    void set_capture_device(const std::string& device);
    void set_pcap_file(const std::string& file);
    void start_capture();
};
