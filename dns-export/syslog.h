#pragma once
#include "statistics.h"
#include <netinet/in.h>

class syslog
{
	sockaddr_storage dest_ {};
	void send_stat(const std::string& cs);
    static std::string generate_timestamp();
    std::string generate_hostname();
    std::string generate_message(int prival, int socket, std::string name, std::string msg);
    syslog(); // Constructor? (the {} brackets) are needed here.
public:
	static syslog& get_instance();
	syslog(syslog const&) = delete;
	void operator=(syslog const&) = delete;
	void send_stats(statistics& stats);
	void set_syslog_server(const std::string& server);
	std::string generate_ip_address(int socket);
};

