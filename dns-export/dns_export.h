//
// Created by timot on 05.10.2018.
//
#pragma once
#include <netinet/in.h>
#include <string>
#include <thread>
#include "dns_packet_capture.h"

class dns_export
{
    dns_packet_capture dns_packet_capture_{};
    struct sockaddr_in dest_ipv4_{};
    struct sockaddr_in6 dest_ipv6_{};
    std::thread* stat_thread_{};
    long long timeout_;
    bool syslog_set_{};
    bool interface_{};
    static void signal_handler(int signum);
    static void thread_handler(long long time, bool syslog_set);
    static void print_or_send_stats(bool syslog_set);
public:
    dns_export() : timeout_(60)
    {
    }

    void set_pcap_file(const std::string& pcap_file);
    void set_interface(const std::string& interface);
    void set_syslog_server(const std::string& server);
    void set_timeout(const std::string& timeout);
    void start();
    std::thread start_stat_thread();
};
