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

/**
 * @brief Sets capturing packets from file.
 * @param pcap_file File name.
 */
void dns_export::set_pcap_file(const std::string& pcap_file)
{
    dns_packet_capture_.set_pcap_file(pcap_file);
    interface_ = false;
}

/**
 * @brief Sets capturing packets from interface.
 * @param interface Interface name.
 */
void dns_export::set_interface(const std::string& interface)
{
    dns_packet_capture_.set_capture_device(interface);
    interface_ = true;
}

/**
 * @brief Sets Syslog server to which packets will be sent.
 * @param server IP Address in literal representation.
 */
void dns_export::set_syslog_server(const std::string& server)
{
    syslog::get_instance().set_syslog_server(server);
    syslog_set_ = true;
}

/**
 * @brief Sets timeout for sending statistics to Syslog server or to writing to console.
 * @param timeout Number in seconds.
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

/**
 * @brief If capturing from interface starts thread for working with statistics and starts capturing of packets.
 */
void dns_export::start()
{
    if (interface_)
    {
        sigemptyset(&signal_set_);
        sigaddset(&signal_set_, SIGUSR1);
        pthread_sigmask(SIG_BLOCK, &signal_set_, nullptr);
        start_signal_thread();
        start_syslog_thread();
    }
    dns_packet_capture_.start_capture();
    print_or_send_stats(syslog_set_);
}

/**
 * @brief Starts thread for sending or printing statistics after set timeout.
 */
void dns_export::start_syslog_thread()
{
    auto syslog_thread = std::thread(syslog_handler, &signal_set_, timeout_, syslog_set_);
    syslog_thread.detach();
}

/**
 * @brief Second thread program which is printing or sending statistics.
 * @param time Sleeping time before sending or printing statistics.
 * @param syslog_set If Syslog is used sends to server else prints to console.
 */
void dns_export::syslog_handler(const sigset_t* signal_set, const long long time, const bool syslog_set)
{
    pthread_sigmask(SIG_BLOCK, signal_set, nullptr);
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(time));
        print_or_send_stats(syslog_set);
    }
}

/**
 * @brief Prints or sends statistics based on syslog_set.
 * @param syslog_set If Syslog is used sends to server else prints to console.
 */
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

/**
 * @brief Starts thread for signal handling.
 */
void dns_export::start_signal_thread()
{
    auto signal_thread = std::thread(signal_handler, &signal_set_);
    signal_thread.detach();
}

/**
 * @brief Signal handler which prints statistics to stdout after receiving SIGUSR1 signal.
 */
void dns_export::signal_handler(const sigset_t* signal_set)
{
    pthread_sigmask(SIG_BLOCK, signal_set, nullptr);
    while (true)
    {
        auto signum = sigwaitinfo(signal_set, nullptr);
        if (signum == SIGUSR1)
        {
            std::cout << statistics::get_instance();
        }
    }
}
