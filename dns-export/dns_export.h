/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_export class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <netinet/in.h>
#include <string>
#include <thread>
#include "utils/dns_packet_capture.h"

class dns_export
{
    dns_packet_capture dns_packet_capture_{}; // Class for capturing packets
    long long timeout_; // Timeout for sending statistics to Syslog server or to writing to console
    bool syslog_set_{}; // If Syslog server is set it is true else it is false
    bool interface_{}; // True if capturing from interface. False if capturing from file
    sigset_t signal_set_{}; // In constructor SIGUSR1 signal is added to this set
    void start_syslog_thread();
    static void syslog_handler(const sigset_t* signal_set, long long time, bool syslog_set);
    static void print_or_send_stats(bool syslog_set);
    void start_signal_thread();
    static void signal_handler(const sigset_t* signal_set);
public:
    /**
     * @brief Sets default value of 60 seconds as timeout.
     */
    dns_export() : timeout_(60)
    {
    }

    void set_pcap_file(const std::string& pcap_file);
    void set_interface(const std::string& interface);
    void set_syslog_server(const std::string& server);
    void set_timeout(const std::string& timeout);
    void start();
};
