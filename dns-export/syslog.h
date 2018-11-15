#pragma once
#include <netinet/in.h>
#include "statistics.h"

class syslog
{
    sockaddr_storage dest_{};
    void send_stat(const std::string& cs) const;
    static std::string generate_timestamp();
    static std::string generate_hostname();
    static std::string generate_message(int prival, int socket, const std::string& name, const std::string& msg);
    syslog(); // Constructor? (the {} brackets) are needed here.
public:
    static syslog& get_instance();
    syslog(syslog const&) = delete;
    void operator=(syslog const&) = delete;
    void send_stats(statistics& stats) const;
    void set_syslog_server(const std::string& server);
    static std::string generate_ip_address(int socket);
};
