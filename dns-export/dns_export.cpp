//
// Created by timot on 05.10.2018.
//
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include "dns_packet_capture.h"
#include "dns_export.h"

dns_export::dns_export()
{
    this->interface_ = "";
    this->pcap_file_ = "";
    this->timeout_ = 60;
    this->dest_ipv4_.sin_family = AF_INET;
    this->dest_ipv4_.sin_port = htons(514);
    this->dest_ipv6_.sin6_family = AF_INET6;
    this->dest_ipv6_.sin6_port = htons(514);
}

void dns_export::set_pcap_file(const std::string& pcap_file)
{
    this->pcap_file_ = pcap_file;
}

void dns_export::set_interface(const std::string& interface)
{
    this->interface_ = interface;
}

void dns_export::set_syslog_server(const std::string& server)
{
    auto s = inet_pton(AF_INET, server.c_str(), &(this->dest_ipv4_.sin_addr.s_addr));
    if (s <= 0)
    {
        s = inet_pton(AF_INET6, server.c_str(), &(this->dest_ipv6_.sin6_addr.__in6_u));
        if (s <= 0)
        {
            struct hostent* hostent;
            if ((hostent = gethostbyname(server.c_str())) == nullptr)
            {
                //error
            }
            switch (hostent->h_addrtype)
            {
                case AF_INET:
                    memcpy(&(this->dest_ipv4_.sin_addr.s_addr), hostent->h_addr_list[0],
                           static_cast<size_t>(hostent->h_length));
                    break;
                case AF_INET6:
                    memcpy(&(this->dest_ipv6_.sin6_addr.__in6_u), hostent->h_addr_list[0],
                           static_cast<size_t>(hostent->h_length));
                    break;
                default: //error
                    break;
            }
        }
    }
}

void dns_export::set_timeout(const std::string& timeout)
{
    char* end;
    this->timeout_ = strtoul(timeout.c_str(), &end, 10); // convert string to int
    if (*end != '\0')
    {
        //error
    }
}

void dns_export::start() const
{
    if (!interface_.empty() && pcap_file_.empty())
    {
        dns_packet_capture dns_packet_capture1;
        dns_packet_capture1.set_capture_device(interface_);
        dns_packet_capture1.start_capture();
    }
    else if (!pcap_file_.empty() && interface_.empty())
    {
        dns_packet_capture dns_packet_capture1;
        dns_packet_capture1.set_pcap_file(pcap_file_);
        dns_packet_capture1.start_capture();
    }
    else
    {
        //error
    }
}
