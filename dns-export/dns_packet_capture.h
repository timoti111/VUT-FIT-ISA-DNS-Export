//
// Created by timot on 05.10.2018.
//
#pragma once
#include <pcap/pcap.h>
#include <string>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

class dns_packet_capture
{
    /* default snap length (maximum bytes per packet to capture) */
    const int snap_len_ = 1518;
    const char* dev_ = nullptr;
    const struct tcphdr* my_tcp_{}; // pointer to the beginning of TCP header
    const struct udphdr* my_udp_{}; // pointer to the beginning of UDP header
    struct pcap_pkthdr header_{};
    char err_buf_[PCAP_ERRBUF_SIZE]{}; /* error buffer */
    pcap_t* handle_ = nullptr; /* packet capture handle */
    int link_type_{};
    std::string filter_exp_ = "source port 53"; /* filter expression [3] */
    struct bpf_program fp_{}; /* compiled filter program (expression) */
    bpf_u_int32 mask_{}; /* subnet mask */
    bpf_u_int32 net_{}; /* ip */
    int num_packets_ = 10; /* number of packets to capture */
public:
    dns_packet_capture() = default;
    void set_capture_device(const std::string& device);
    void set_pcap_file(const std::string& file);
    void start_capture();
    int next_packet(pcap_t* session, int link_type);
};
