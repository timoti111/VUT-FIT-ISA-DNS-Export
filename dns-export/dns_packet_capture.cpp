#include "dns_packet_capture.h"
#include "error.h"
#include "link_layer.h"
#include <sstream>

dns_packet_capture::~dns_packet_capture()
{
	if (handle_ != nullptr)
	{
		pcap_close(handle_);
	}
}

void dns_packet_capture::set_capture_device(const std::string& device)
{
    dev_ = device.c_str();
    handle_ = pcap_open_live(dev_, snap_len_, 1, 1000, err_buf_);
    if (handle_ == nullptr)
    {
		std::stringstream stream;
		stream << "Device " << device << " doesn't exist.";
        throw packet_capture_error(stream.str());
    }
}

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

void dns_packet_capture::start_capture()
{
    if (handle_ == nullptr)
    {
		throw packet_capture_error("Handle is null.");
    }
    link_type_ = pcap_datalink(handle_);
    if (link_type_ != DLT_EN10MB && link_type_ != DLT_LINUX_SLL &&
		link_type_ != DLT_IPV4 && link_type_ != DLT_IPV6)
    {
        throw packet_capture_error("Device is not ethernet.");
    }
    while (!next_packet(handle_, link_type_))
    {
    }
}

int dns_packet_capture::next_packet(pcap_t* session, int link_type)
{
	struct pcap_pkthdr* packet_hdr = nullptr;
	const unsigned char* packet_data = nullptr;
	static auto n = 0;
	const auto i = pcap_next_ex(session, &packet_hdr, &packet_data);
	if (i == PCAP_ERROR_BREAK)
	{
		return 1;
	}
	if (i == PCAP_ERROR)
	{
		std::stringstream stream;
		stream << "Pcap error: " << pcap_geterr(session) << ".";
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
	link_layer::parse_packet(packet_data, packet_hdr->caplen, link_type, ++n);
	return 0;
}
