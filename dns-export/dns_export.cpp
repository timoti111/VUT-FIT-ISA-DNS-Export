//
// Created by timot on 05.10.2018.
//
#include <arpa/inet.h>
#include <netdb.h>
#include "dns_packet_capture.h"
#include "dns_export.h"
#include <iostream>
#include "error.h"

#include <thread>
#include <csignal>
#include "statistics.h"
#include "syslog.h"

dns_export::dns_export()
{
	this->syslog_set_ = false;
    this->interface_ = "";
    this->pcap_file_ = "";
    this->timeout_ = 60;
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
	syslog::get_instance().set_syslog_server(server);
	syslog_set_ = true;
}

void dns_export::set_timeout(const std::string& timeout)
{
    char* end;
    this->timeout_ = strtoll(timeout.c_str(), &end, 10); // convert string to int
    if (*end != '\0')
    {
		throw  other_error("Timeout parameter error\n");
    }
}

void dns_export::start() const
{
	//
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
        
        if (syslog_set_)
		{
			syslog::get_instance().send_stats(statistics::get_instance());
		}
		else
		{
			std::cout << statistics::get_instance();
		}
    }
    else
    {
        //error
    }
}

std::thread dns_export::start_stat_thread()
{
	return std::thread( [=] { thread_handler(timeout_, syslog_set_); } );
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
		if (syslog_set)
		{
			syslog::get_instance().send_stats(statistics::get_instance());
		}
		else
		{
			if (!statistics::get_instance().empty())
			{
				std::cout << statistics::get_instance() << std::endl;
			}
		}
	}
}
