/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief syslog class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include <cstring>
#include "../utils/exceptions.h"
#include <arpa/inet.h>
#include <iomanip>
#include <netdb.h>
#include <sstream>
#include "syslog.h"
#include <sys/time.h>
#include <unistd.h>

/**
 * @brief Generates message and sends it to server defined in dest_.
 * @param text Reference to text to be sent.
 */
void syslog::send_message(const std::string& text) const
{
    const auto sock = socket(dest_.ss_family, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries
    if (connect(sock, reinterpret_cast<const sockaddr*>(&dest_),
                dest_.ss_family == AF_INET ?
                    static_cast<socklen_t>(sizeof(sockaddr_in)) :
                    static_cast<socklen_t>(sizeof(sockaddr_in6))) != 0)
    {
        throw other_error("Error connecting to server!");
    }
    auto message = generate_message(134, sock, "dns-export", text);
    if (send(sock, message.c_str(), message.length(), 0) < 0)
    {
        throw other_error("Error sending message!");
    }
    close(sock);
}

/**
 * @brief Generates syslog compatible timestamp from actual time of generation.
 * @return String with timestamp.
 */
std::string syslog::generate_timestamp()
{
    char date_time[20];
    struct tm time{};
    timeval cur_time{};
    gettimeofday(&cur_time, nullptr);
    const auto ms = cur_time.tv_usec / 1000;
    localtime_r(&cur_time.tv_sec, &time);
    strftime(date_time, 20, "%Y-%m-%dT%X", &time);
    std::stringstream stream;
    stream << date_time << "." << std::setfill('0') << std::setw(3) << ms << "Z";
    return stream.str();
}

/**
 * @brief Gets hostname.
 * @return String with hostname if can find hostname else returns "-".
 */
std::string syslog::get_hostname()
{
    char hostname[256];
    if (gethostname(hostname, 256))
    {
        return "-";
    }
    return hostname;
}

/**
 * @brief Tries to get IP address from socket. If unsuccessful returns hostname.
 * @param socket Socket to which data is sent.
 * @return Priority: 1. IP address, 2. Hostname, 3. "-"
 */
std::string syslog::generate_ip_address(const int socket)
{
    sockaddr_storage address{};
    socklen_t address_len = sizeof(address);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &address_len))
    {
        return get_hostname();
    }
    const void* address_ptr;
    if (address.ss_family == AF_INET)
    {
        address_ptr = &reinterpret_cast<sockaddr_in*>(&address)->sin_addr;
    }
    else
    {
        address_ptr = &reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr;
    }
    try
    {
        return utils::bin_address_to_string(address_ptr, address.ss_family);
    }
    catch (...)
    {
        return get_hostname();
    }
}

/**
 * @brief Generates string format of message.
 * @param prival Facility and Severity. See RFC5424 for more info.
 * @param socket Socket from which IP address, hostname or "-" is generated.
 * @param name Reference to program name.
 * @param msg Reference to information message
 * @return Formatted message. See RFC5424 for more info. 
 */
std::string syslog::generate_message(const int prival, const int socket, const std::string& name,
                                     const std::string& msg)
{
    static auto hostname = generate_ip_address(socket);
    std::stringstream stream;
    stream << "<" << prival << ">1 ";
    stream << generate_timestamp() << " ";
    stream << hostname << " ";
    stream << name << " - - - ";
    stream << msg;
    return stream.str();
}

/**
 * @brief Hidden constructor so class can't be instantiated. Sets destination port to 514 (Syslog).
 */
syslog::syslog()
{
    memset(&dest_, 0, sizeof(sockaddr_storage));
    reinterpret_cast<sockaddr_in*>(&dest_)->sin_port = htons(514);
}

/**
 * @brief Singleton method for returning only one instance of this class.
 * @return Returns only one and same instance of statistics class every time method is called.
 */
syslog& syslog::get_instance()
{
    static syslog instance;
    return instance;
}

/**
 * @brief Gets statistics and sends them to server in dest_ structure.
 * @param stats 
 */
void syslog::send_stats(statistics& stats) const
{
    auto statistics = stats.get_map();
    for (auto& stat : statistics)
    {
        std::stringstream stream;
        stream << stat.first << " " << stat.second;
        send_message(stream.str());
    }
}

/**
 * @brief Tries to parse IP address and convert it to binary representation into dest_ structure.
 * @param server String representation of IP address.
 */
void syslog::set_syslog_server(const std::string& server)
{
    auto s = inet_pton(AF_INET, server.c_str(), &reinterpret_cast<sockaddr_in*>(&dest_)->sin_addr.s_addr);
    if (s <= 0)
    {
        s = inet_pton(AF_INET6, server.c_str(), &reinterpret_cast<sockaddr_in6*>(&dest_)->sin6_addr.__in6_u);
        if (s <= 0)
        {
            const auto hostent = gethostbyname(server.c_str());
            if (hostent == nullptr)
            {
                throw other_error("Syslog server parameter error");
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
                    throw other_error("Syslog server parameter error");
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
