/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief syslog class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <netinet/in.h>
#include "../statistics/statistics.h"

/**
 * @brief Singleton class for sending syslog messages.
 */
class syslog
{
    sockaddr_storage dest_{}; // destination server for syslog message
    void send_message(const std::string& cs) const;
    static std::string generate_timestamp();
    static std::string get_hostname();
    static std::string generate_message(int prival, int socket, const std::string& name, const std::string& msg);
    syslog();
public:
    static syslog& get_instance();
    syslog(syslog const&) = delete; // deleted copy constructor
    void operator=(syslog const&) = delete; // deleted copy operator
    void send_stats(statistics& stats) const;
    void set_syslog_server(const std::string& server);
    static std::string generate_ip_address(int socket);
};
