#include "syslog.h"
#include "error.h"
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>

void syslog::send_stat(const std::string& cs)
{
	auto sock = socket(dest_.ss_family, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries
	if (connect(sock, reinterpret_cast<const sockaddr*>(&dest_), dest_.ss_family == AF_INET ? static_cast<socklen_t>(sizeof(sockaddr_in)) : static_cast<socklen_t>(sizeof(sockaddr_in6))) != 0)
	{
		throw other_error("Error connecting to server!");
	}
	auto message = generate_message(134, sock, "dns-export", cs);
	if (send(sock, message.c_str(), message.length(), 0) < 0)
	{
		throw other_error("Error sending message!");
	}
	close(sock);
}

std::string syslog::generate_timestamp()
{
	char date_time[20];
	struct tm time{};
	timeval curTime;
	gettimeofday(&curTime, nullptr);
    const auto ms = curTime.tv_usec / 1000;
	localtime_r(&curTime.tv_sec, &time);
	strftime(date_time, 20, "%Y-%m-%dT%X", &time);
	std::stringstream stream;
	stream << date_time << "." << std::setfill('0') << std::setw(3) << ms << "Z";
	return stream.str();
}

std::string syslog::generate_hostname()
{
    char hostname[256];
    if (gethostname(hostname, 256))
    {
        throw other_error("Can't get ip address or hostname for syslog message");
    }
    return hostname;
}

std::string syslog::generate_ip_address(const int socket)
{    
	sockaddr_storage address{};
	socklen_t addresslen = sizeof(address);

	if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &addresslen))
	{
		return generate_hostname();
	}

	char address_str[INET6_ADDRSTRLEN];
	memset(address_str, 0, INET6_ADDRSTRLEN);
	const void* addr_ptr;
    if (address.ss_family == AF_INET)
    {
		addr_ptr = &reinterpret_cast<sockaddr_in*>(&address)->sin_addr;
    }
    else
    {
		addr_ptr = &reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr;
    }
	const auto ptr = inet_ntop(address.ss_family, addr_ptr, address_str, INET6_ADDRSTRLEN);
	if (ptr == address_str)
	{
		return address_str;
	}
    return generate_hostname();
}

std::string syslog::generate_message(const int prival, const int socket, const std::string name, const std::string msg)
{
    static auto hostname = generate_ip_address(socket);
	std::stringstream stream;
	stream << "<" << prival << ">1 ";
	stream << generate_timestamp() << " ";
	stream <<  hostname << " ";
	stream << name << " - - - ";
	stream << msg;
	return stream.str();
}

syslog::syslog()
{
	memset(&dest_, 0, sizeof(sockaddr_storage));
	reinterpret_cast<sockaddr_in*>(&dest_)->sin_port = htons(514);
}

syslog& syslog::get_instance()
{
	static syslog instance; // Guaranteed to be destroyed.
	// Instantiated on first use.
	return instance;
}

void syslog::send_stats(statistics& stats)
{
    auto statistics = stats.get_map();
    for (auto stat : statistics)
    {
		std::stringstream stream;
		stream << stat.first << " " << stat.second;
		send_stat(stream.str());
    }
}

void syslog::set_syslog_server(const std::string& server)
{
	auto s = inet_pton(AF_INET, server.c_str(), &reinterpret_cast<sockaddr_in*>(&dest_)->sin_addr.s_addr);
	if (s <= 0)
	{
		s = inet_pton(AF_INET6, server.c_str(), &reinterpret_cast<sockaddr_in6*>(&dest_)->sin6_addr.__in6_u);
		if (s <= 0)
		{
		    auto hostent = gethostbyname(server.c_str());
			if (hostent == nullptr)
			{
				throw  other_error("Syslog server parameter error");
			}
			switch (hostent->h_addrtype)
			{
			case AF_INET:
				memcpy(&reinterpret_cast<sockaddr_in*>(&dest_)->sin_addr.s_addr, hostent->h_addr_list[0],
					static_cast<size_t>(hostent->h_length));
				dest_.ss_family = AF_INET;
				break;
			case AF_INET6:
				memcpy(&reinterpret_cast<sockaddr_in6*>(&dest_)->sin6_addr.__in6_u, hostent->h_addr_list[0],
					static_cast<size_t>(hostent->h_length));
				dest_.ss_family = AF_INET6;
				break;
			default:
				throw  other_error("Syslog server parameter error");
			}
		}
		else
		{
			dest_.ss_family = AF_INET6;
		}
	}
	else
	{
		dest_.ss_family = AF_INET;
	}
}
