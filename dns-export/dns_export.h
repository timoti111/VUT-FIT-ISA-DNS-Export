//
// Created by timot on 05.10.2018.
//
#pragma once
#include <string>
#include <netinet/in.h>
#include <thread>

class dns_export
{
    struct sockaddr_in dest_ipv4_{};
    struct sockaddr_in6 dest_ipv6_{}; 
	std::thread * stat_thread_;
    long long timeout_;
    std::string interface_{};
    std::string pcap_file_{};
    bool syslog_set_;
    static void signal_handler(int signum);
    static void thread_handler(long long time, bool syslog_set);
public:
    dns_export();
    void set_pcap_file(const std::string& pcap_file);
    void set_interface(const std::string& interface);
    void set_syslog_server(const std::string& server);
    void set_timeout(const std::string& timeout);
    void start() const;
	std::thread start_stat_thread();
};
