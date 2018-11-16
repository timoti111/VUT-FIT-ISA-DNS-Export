/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_export class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include <csignal>
#include "dns_export.h"
#include "utils/exceptions.h"
#include <iostream>
#include "statistics/statistics.h"
#include "syslog/syslog.h"
#include <thread>

void dns_export::set_pcap_file(const std::string& pcap_file)
{
    dns_packet_capture_.set_pcap_file(pcap_file);
    interface_ = false;
}

void dns_export::set_interface(const std::string& interface)
{
    dns_packet_capture_.set_capture_device(interface);
    interface_ = true;
}

void dns_export::set_syslog_server(const std::string& server)
{
    syslog::get_instance().set_syslog_server(server);
    syslog_set_ = true;
}

/**
 * @brief 
 * @param timeout 
 */
void dns_export::set_timeout(const std::string& timeout)
{
    char* end;
    this->timeout_ = strtoll(timeout.c_str(), &end, 10); // convert string to int
    if (*end != '\0' || timeout_ < 0)
    {
        throw other_error("Timeout parameter error\n");
    }
}

void dns_export::start()
{
    dns_packet_capture_.start_capture();
    print_or_send_stats(syslog_set_);
}

std::thread dns_export::start_stat_thread()
{
    return std::thread([=]
    {
        thread_handler(timeout_, syslog_set_);
    });
}

void dns_export::signal_handler(int signum)
{
    if (!statistics::get_instance().empty())
    {
        std::cout << statistics::get_instance() << std::endl;
    }
}

void dns_export::thread_handler(const long long time, const bool syslog_set)
{
    signal(SIGUSR1, signal_handler);
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(time));
        print_or_send_stats(syslog_set);
        if (!syslog_set && !statistics::get_instance().empty())
        {
            std::cout << std::endl;
        }
    }
}

void dns_export::print_or_send_stats(const bool syslog_set)
{
    if (syslog_set)
    {
        syslog::get_instance().send_stats(statistics::get_instance());
    }
    else
    {
        std::cout << statistics::get_instance();
    }
}
