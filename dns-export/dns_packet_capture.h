//
// Created by timot on 05.10.2018.
//
#pragma once
#include <pcap/pcap.h>
#include <string>

class dns_packet_capture
{
    const int snap_len_ = 1518;
    const char* dev_ = nullptr;
    char err_buf_[PCAP_ERRBUF_SIZE]{}; /* error buffer */
    pcap_t* handle_ = nullptr; /* packet capture handle */
    int link_type_{};
	static int next_packet(pcap_t* session, int link_type);
public:
    dns_packet_capture() = default;
	~dns_packet_capture();
    void set_capture_device(const std::string& device);
    void set_pcap_file(const std::string& file);
    void start_capture();
};
