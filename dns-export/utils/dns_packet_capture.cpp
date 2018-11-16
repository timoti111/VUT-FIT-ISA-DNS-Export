/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_packet_capture class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_packet_capture.h"
#include "exceptions.h"
#include "../packet/packet_parser.h"
#include <sstream>

/**
 * @brief Destructor which closes handle_ if it is used.
 */
dns_packet_capture::~dns_packet_capture()
{
    if (handle_ != nullptr)
    {
        pcap_close(handle_);
    }
}

/**
 * @brief Sets destination of capturing to network device.
 * @param device String name of device.
 */
void dns_packet_capture::set_capture_device(const std::string& device)
{
    handle_ = pcap_open_live(device.c_str(), snap_len_, 1, 1000, err_buf_);
    if (handle_ == nullptr)
    {
        std::stringstream stream;
        stream << "Device " << device << " doesn't exist.";
        throw packet_capture_error(stream.str());
    }
}

/**
 * @brief Sets destination of capturing to file.
 * @param file File with packets.
 */
void dns_packet_capture::set_pcap_file(const std::string& file)
{
    handle_ = pcap_open_offline(file.c_str(), err_buf_);
    if (handle_ == nullptr)
    {
        std::stringstream stream;
        stream << "Couldn't open file " << file << ".";
        throw packet_capture_error(stream.str());
    }
}

/**
 * @brief Starts capture process if possible. If network device is set process is infinite.
 */
void dns_packet_capture::start_capture()
{
    if (handle_ == nullptr)
    {
        throw packet_capture_error("Handle is null.");
    }
    link_type_ = pcap_datalink(handle_);
    if (link_type_ != DLT_EN10MB && link_type_ != DLT_LINUX_SLL && link_type_ != DLT_IPV4 && link_type_ != DLT_IPV6)
    {
        throw packet_capture_error("Device is not ethernet.");
    }
    while (!next_packet());
}

/**
 * @brief Gets next packet from device or file and parses it.
 * @return 0 if successful 1 if no packets from file are available.
 */
int dns_packet_capture::next_packet() const
{
    struct pcap_pkthdr* packet_hdr = nullptr;
    const unsigned char* packet_data = nullptr;
    static auto n = 0;
    const auto i = pcap_next_ex(handle_, &packet_hdr, &packet_data);
    if (i == PCAP_ERROR_BREAK)
    {
        return 1;
    }
    if (i == PCAP_ERROR)
    {
        std::stringstream stream;
        stream << "Pcap error: " << pcap_geterr(handle_) << ".";
        throw packet_capture_error(stream.str());
    }
    if (i == 0)
    {
        return 0;
    }
    if (!packet_hdr || !packet_data)
    {
        throw packet_capture_error("Pcap returns null data.");
    }
    if (packet_hdr->caplen > packet_hdr->len)
    {
        throw packet_capture_error("Pcap returns corrupted packet.");
    }
    packet_parser(packet_data, packet_hdr->caplen, link_type_, ++n);
    return 0;
}
