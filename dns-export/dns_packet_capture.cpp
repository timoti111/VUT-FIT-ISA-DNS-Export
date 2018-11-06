//
// Created by timot on 05.10.2018.
//
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include "dns_packet_capture.h"
#include "dns_packet.h"
#include <iostream>
#include <exception>
#include <stdexcept>
#include <cstring>
#include "error.h"

void dns_packet_capture::set_capture_device(const std::string& device)
{
    //dev_ = device.c_str();
    dev_ = pcap_lookupdev(err_buf_);
    if (dev_ == nullptr)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", err_buf_);
    }
    handle_ = pcap_open_live(dev_, snap_len_, 1, 1000, err_buf_);
    if (handle_ == nullptr)
    {
		throw packet_capture_error("Couldn't open device");
    }
}

void dns_packet_capture::set_pcap_file(const std::string& file)
{
    handle_ = pcap_open_offline(file.c_str(), err_buf_);
    if (handle_ == nullptr)
    {
		throw packet_capture_error("Couldn't open file");
    }
}

void dns_packet_capture::start_capture()
{
    if (handle_ == nullptr)
    {
        // TODO error
        return;
    }
    link_type_ = pcap_datalink(handle_); // TODO skontrolovat pri offline
    if (link_type_ != DLT_EN10MB/* && link_type != DLT_LINUX_SLL &&
        link_type != DLT_IPV4 && link_type != DLT_IPV6*/)
    {
		throw packet_capture_error("Device is not ethernet");
    }
    if (pcap_lookupnet(dev_, &net_, &mask_, err_buf_) == PCAP_ERROR)
    {
        // TODO error
        //        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
        //                dev, errbuf);
        net_ = 0;
        mask_ = 0;
    }
    if (pcap_compile(handle_, &fp_, filter_exp_.c_str(), 0, net_) == PCAP_ERROR)
    {
		//throw packet_capture_error("Couldn't compile filter");
    }
    if (pcap_setfilter(handle_, &fp_) == PCAP_ERROR)
    {

		//throw packet_capture_error("Couldn't set filter");
    }
    while (!next_packet(handle_, link_type_))
    {
    }
    pcap_freecode(&fp_);
    pcap_close(handle_);
} /**
 * Get the next packet and dissect it.
 *
 * \param[in] session   pcap session
 * \param[in] link_type pcap link type
 * \return 0 on success, 1 on error
 */
int dns_packet_capture::next_packet(pcap_t* session, int link_type)
{
    struct pcap_pkthdr* packet_hdr = nullptr;
    const unsigned char* packet_data = nullptr;
    static auto n = 0;
    const auto i = pcap_next_ex(session, &packet_hdr, &packet_data);
    if (i < 0)
    {
        return 1;
    }
    if (i == 0)
    {
        return 0;
    }
    if (!packet_hdr || !packet_data)
    {
        return 1; //error
    }
    if (packet_hdr->caplen > packet_hdr->len)
    {
        return 1; //error
    }
    n++;
    const auto eptr = (struct ether_header *)packet_data;
    unsigned size_internet = 0;
    u_int8_t ip_next_hdr_type = 0;
    struct ip* my_ip;
    struct ip6_hdr* my_ip6;
    switch (ntohs(eptr->ether_type))
    {
        case ETHERTYPE_IP: // IPv4 packet
            my_ip = (struct ip*)(packet_data + ETHER_HDR_LEN); // skip Ethernet header
            size_internet = my_ip->ip_hl * 4; // length of IP header
            ip_next_hdr_type = my_ip->ip_p;
            break;
        case ETHERTYPE_IPV6: // IPv6
            my_ip6 = (struct ip6_hdr*)(packet_data + ETHER_HDR_LEN); // skip Ethernet header
            size_internet = 40;
            ip_next_hdr_type = my_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            break;
        default:
            printf("Not supported network layer protocol %d\n", ntohs(eptr->ether_type));
            return 0;
    }
    uint16_t size_transport = 0;
    uint16_t size_application = 0;
    switch (ip_next_hdr_type)
    {
        case 6: // TCP protocol
            my_tcp_ = (struct tcphdr *)(packet_data + ETHER_HDR_LEN + size_internet); // pointer to the TCP header
            memcpy(&size_application, packet_data + ETHER_HDR_LEN + size_internet + my_tcp_->doff * 4, 2);
            size_application = ntohs(size_application);
            if (my_tcp_->ack && my_tcp_->psh && ntohs(my_tcp_->seq) != 1)
                size_transport = my_tcp_->doff * 4 + 2;
            else
                return 0;
            break;
        case 17: // UDP protocol
            my_udp_ = (struct udphdr *)(packet_data + ETHER_HDR_LEN + size_internet);
            size_transport = 8;
            size_application = ntohs(my_udp_->len) - 8;
            break;
        default:
            printf("Not supported transport layer protocol type %d\n", ip_next_hdr_type);
            return 0;
    }
    const int size_pcap_application = (packet_hdr->caplen < packet_hdr->len ? packet_hdr->caplen : packet_hdr->len) -
        ETHER_HDR_LEN - size_internet - size_transport;
    if (size_pcap_application != size_application)
        return 0;
    try
    {
        dns_packet response(packet_data + ETHER_HDR_LEN + size_internet + size_transport, size_application);
        if (response.header.flags.qr == 0 || response.header.an_count == 0)
            return 0;
        if (response.answers.size() != 0)
        {
            std::cout << "Packet number: " << n << " Packet caplen: " << packet_hdr->caplen << " Packet len: " <<
                packet_hdr->len << std::endl;
            std::cout << response.answers;
            std::cout << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cout << "Packet number: " << n << " Packet caplen: " << packet_hdr->caplen << " Packet len: " << packet_hdr
            ->len << std::endl;
        std::cout << "Exception: " << std::endl;
        std::cout << e.what() << std::endl;
        std::cout << std::endl;
    }
    return 0;
}
