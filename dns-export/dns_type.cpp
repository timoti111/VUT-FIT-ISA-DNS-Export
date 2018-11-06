#include "dns_type.h"
#include "error.h"
#include <netinet/in.h>
#include <iomanip>
#include "base64.h"
#include <cstring>
#include <bitset>

dns_type::dns_type(const uint16_t type, dns_utils::memory_block& read_head, dns_utils::memory_block& whole_buffer,
                   const uint16_t rd_length)
{
    const auto start_cap = read_head.length;
    this->type_ = get_type_name(type);
    switch (type)
    {
        case type_a::num:
            type_a_.address = dns_utils::mem_to_vector(read_head, rd_length);
            str_ = type_a_.to_string();
            break;
        case type_aaaa::num:
            type_aaaa_.address = dns_utils::mem_to_vector(read_head, rd_length);
            str_ = type_aaaa_.to_string();
            break;
        case type_cname::num:
            type_cname_.cname.data = dns_utils::parse_name(read_head, whole_buffer);
            str_ = type_cname_.to_string();
            break;
        case type_ptr::num:
            type_ptr_.ptrdname.data = dns_utils::parse_name(read_head, whole_buffer);
            str_ = type_ptr_.to_string();
            break;
        case type_mx::num:
            type_mx_.preference = dns_utils::mem_to_uint16(read_head);
            type_mx_.exchange.data = dns_utils::parse_name(read_head, whole_buffer);
            str_ = type_mx_.to_string();
            break;
        case type_ns::num:
            type_ns_.nsdname.data = dns_utils::parse_name(read_head, whole_buffer);
            str_ = type_ns_.to_string();
            break;
        case type_soa::num:
            type_soa_.mname.data = dns_utils::parse_name(read_head, whole_buffer);
            type_soa_.rname.data = dns_utils::parse_name(read_head, whole_buffer);
            type_soa_.serial = dns_utils::mem_to_uint32(read_head);
            type_soa_.refresh = dns_utils::mem_to_uint32(read_head);
            type_soa_.retry = dns_utils::mem_to_uint32(read_head);
            type_soa_.expire = dns_utils::mem_to_uint32(read_head);
            type_soa_.minimum = dns_utils::mem_to_uint32(read_head);
            str_ = type_soa_.to_string();
            break;
        case type_txt::num:
            type_txt_.txt_data = dns_utils::mem_to_string(read_head, rd_length);
            str_ = type_txt_.to_string();
            break;
        case type_spf::num:
            type_spf_.spf_data = dns_utils::mem_to_string(read_head, rd_length);
            str_ = type_spf_.to_string();
            break;
        case type_dnskey::num:
            type_dnskey_.flags = dns_utils::mem_to_uint16(read_head);
            type_dnskey_.protocol = dns_utils::mem_to_uint8(read_head);
            type_dnskey_.algorithm = dns_utils::mem_to_uint8(read_head);
            type_dnskey_.public_key = dns_utils::
                mem_to_vector(read_head, rd_length - (start_cap - read_head.length));
            str_ = type_dnskey_.to_string();
            break;
        case type_rrsig::num:
            type_rrsig_.type_covered = dns_utils::mem_to_uint16(read_head);
            type_rrsig_.algorithm = dns_utils::mem_to_uint8(read_head);
            type_rrsig_.labels = dns_utils::mem_to_uint8(read_head);
            type_rrsig_.original_ttl = dns_utils::mem_to_uint32(read_head);
            type_rrsig_.signature_expiration = dns_utils::mem_to_uint32(read_head);
            type_rrsig_.signature_inception = dns_utils::mem_to_uint32(read_head);
            type_rrsig_.key_tag = dns_utils::mem_to_uint16(read_head);
            type_rrsig_.signers_name.data = dns_utils::parse_name(read_head, whole_buffer);
            type_rrsig_.signature = dns_utils::mem_to_vector(read_head, rd_length - (start_cap - read_head.length));
            str_ = type_rrsig_.to_string();
            break;
        case type_nsec::num:
			type_nsec_.next_domain_name.data = dns_utils::parse_name(read_head, whole_buffer);
			type_nsec_.type_bit_maps = dns_utils::mem_to_vector(read_head, rd_length - (start_cap - read_head.length));
            str_ = type_nsec_.to_string();
            break;
        case type_ds::num:
            type_ds_.key_tag = dns_utils::mem_to_uint16(read_head);
            type_ds_.algorithm = dns_utils::mem_to_uint8(read_head);
            type_ds_.digest_type = dns_utils::mem_to_uint8(read_head);
            type_ds_.digest = dns_utils::mem_to_vector(read_head, rd_length - (start_cap - read_head.length));
            str_ = type_ds_.to_string();
            break;
        default:
            str_ = "";
            break;
    }
    const auto unread_length = rd_length - (start_cap - read_head.length);
    read_head.ptr += unread_length;
    read_head.length -= unread_length;
}

std::string dns_type::get_type() const
{
    return type_;
}

std::string dns_type::to_string() const
{
    return str_;
}

std::ostream& operator<<(std::ostream& stream, dns_type& obj)
{
    return stream << obj.to_string();
}

std::string dns_type::get_type_name(const uint16_t type)
{
    switch (type)
    {
        case type_a::num:
            return "A";
        case type_aaaa::num:
            return "AAAA";
        case type_cname::num:
            return "CNAME";
        case type_ptr::num:
            return "PTR";
        case type_mx::num:
            return "MX";
        case type_ns::num:
            return "NS";
        case type_soa::num:
            return "SOA";
        case type_txt::num:
            return "TXT";
        case type_spf::num:
            return "SPF";
        case type_dnskey::num:
            return "DNSKEY";
        case type_rrsig::num:
            return "RRSIG";
        case type_nsec::num:
            return "NSEC";
        case type_ds::num:
            return "DS";
        case 255:
            return "ANY";
        default:
			std::stringstream stream;
			stream << "TYPE" << type;
            return stream.str();
    }
}

std::string dns_type::domain_name::to_string() const
{
    return dns_utils::label_to_string(data);
}

std::string dns_type::type_a::to_string() const
{
    return dns_utils::addr_to_string(address);
}

std::string dns_type::type_aaaa::to_string() const
{
    return dns_utils::addr_to_string(address);
}

std::string dns_type::type_cname::to_string() const
{
    return cname.to_string();
}

std::string dns_type::type_ptr::to_string() const
{
    return ptrdname.to_string();
}

std::string dns_type::type_mx::to_string() const
{
    std::stringstream stream;
    stream << preference << " " << exchange.to_string();
    return stream.str();
}

std::string dns_type::type_ns::to_string() const
{
    return nsdname.to_string();
}

std::string dns_type::type_soa::to_string() const
{
    std::stringstream stream;
    stream << mname.to_string() << " " << rname.to_string() << " " << serial << " " << refresh << " " << retry << " " <<
        expire << " " << minimum;
    return stream.str();
}

std::string dns_type::type_txt::to_string() const
{
    return txt_data;
}

std::string dns_type::type_spf::to_string() const
{
    return spf_data;
}

std::string dns_type::type_dnskey::to_string() const
{
    std::stringstream stream;
    stream << flags << " " << static_cast<uint16_t>(protocol) << " " << static_cast<uint16_t>(algorithm) << " ( " <<
        base64_encode((unsigned char *)public_key.data(), public_key.size()) << " )";
    return stream.str();
}

std::string dns_type::type_rrsig::to_string() const
{
    std::stringstream stream;
    stream << get_type_name(type_covered) << " " << static_cast<uint16_t>(algorithm) << " " << static_cast<uint16_t>(labels) << " " <<
        original_ttl << " " << signature_expiration << " ( " << signature_inception << " " << key_tag << " " <<
        signers_name.to_string() << " " << base64_encode((unsigned char *)signature.data(), signature.size()) << " )";
    return stream.str();
}

std::string dns_type::type_nsec::parse_type_bit_maps()  const
{
	std::string ret;
    if (type_bit_maps.size() > 1)
    {
		uint16_t length;
		memcpy(&length, type_bit_maps.data(), sizeof(uint16_t));
		length = ntohs(length);
        if (length + 2 != type_bit_maps.size())
        {
			throw dns_parsing_error("Error: parse_type_bit_maps");
        }
		auto types = std::vector<uint8_t>(type_bit_maps.begin() + 2, type_bit_maps.end());
		uint32_t type_num = 0;
		std::stringstream stream;
        for (auto byte : types)
        {
			for (auto i = 7; i >= 0; i--)
			{
				if (byte >> i & 1)
				{
					stream << get_type_name(type_num) << " ";
				}
				type_num++;
			}
        }
		ret = stream.str();
        if (!ret.empty())
		    ret.pop_back();
    }
	return ret;
}

std::string dns_type::type_nsec::to_string() const
{
	std::stringstream stream;
	stream << next_domain_name.to_string() << " " << parse_type_bit_maps();
	return stream.str();
}

std::string dns_type::type_ds::to_string() const
{
    std::stringstream stream;
    stream << key_tag << " " << static_cast<uint16_t>(algorithm) << " " << static_cast<uint16_t>(digest_type) << " ( " <<
        dns_utils::vec_to_hexstring(digest) << " )";
    return stream.str();
}
