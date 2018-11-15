/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief dns_type class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "base64.h"
#include "dns_type.h"
#include "exceptions.h"
#include <netinet/in.h>
#include <sstream>

dns_type::dns_type(const uint16_t type, utils::memory_block& read_head, utils::memory_block& whole_buffer,
                   const uint16_t rd_length) : type_(get_type_name(type))
{
    uint64_t remaining_length = 0;
    const auto start_cap = read_head.size();
    switch (type)
    {
        case type_a::num:
            type_a_.address = utils::addr_to_string(read_head, rd_length);
            str_ = type_a_.to_string();
            break;
        case type_aaaa::num:
            type_aaaa_.address = utils::addr_to_string(read_head, rd_length);
            str_ = type_aaaa_.to_string();
            break;
        case type_cname::num:
            type_cname_.cname = utils::parse_name(read_head, whole_buffer);
            str_ = type_cname_.to_string();
            break;
        case type_ptr::num:
            type_ptr_.ptrdname = utils::parse_name(read_head, whole_buffer);
            str_ = type_ptr_.to_string();
            break;
        case type_mx::num:
            type_mx_.preference = ntohs(*read_head.get_ptr_and_add<uint16_t>());
            type_mx_.exchange = utils::parse_name(read_head, whole_buffer);
            str_ = type_mx_.to_string();
            break;
        case type_ns::num:
            type_ns_.nsdname = utils::parse_name(read_head, whole_buffer);
            str_ = type_ns_.to_string();
            break;
        case type_soa::num:
            type_soa_.mname = utils::parse_name(read_head, whole_buffer);
            type_soa_.rname = utils::parse_name(read_head, whole_buffer);
            type_soa_.serial = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.refresh = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.retry = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.expire = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.minimum = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            str_ = type_soa_.to_string();
            break;
        case type_txt::num:
            type_txt_.txt_data = utils::mem_to_string(read_head, rd_length);
            str_ = type_txt_.to_string();
            break;
        case type_spf::num:
            type_spf_.spf_data = utils::mem_to_string(read_head, rd_length);
            str_ = type_spf_.to_string();
            break;
        case type_dnskey::num:
            type_dnskey_.flags = ntohs(*read_head.get_ptr_and_add<uint16_t>());
            type_dnskey_.protocol = *read_head.get_ptr_and_add<uint8_t>();
            type_dnskey_.algorithm = *read_head.get_ptr_and_add<uint8_t>();
            remaining_length = rd_length - (start_cap - read_head.size());
            read_head += remaining_length;
            type_dnskey_.public_key = base64_encode(read_head.begin() - remaining_length, remaining_length);
            str_ = type_dnskey_.to_string();
            break;
        case type_rrsig::num:
            type_rrsig_.type_covered = ntohs(*read_head.get_ptr_and_add<uint16_t>());
            type_rrsig_.algorithm = *read_head.get_ptr_and_add<uint8_t>();
            type_rrsig_.labels = *read_head.get_ptr_and_add<uint8_t>();
            type_rrsig_.original_ttl = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_rrsig_.signature_expiration = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_rrsig_.signature_inception = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_rrsig_.key_tag = ntohs(*read_head.get_ptr_and_add<uint16_t>());
            type_rrsig_.signers_name = utils::parse_name(read_head, whole_buffer);
            remaining_length = rd_length - (start_cap - read_head.size());
            read_head += remaining_length;
            type_rrsig_.signature = base64_encode(read_head.begin() - remaining_length, remaining_length);
            str_ = type_rrsig_.to_string();
            break;
        case type_nsec::num:
            type_nsec_.next_domain_name = utils::parse_name(read_head, whole_buffer);
            type_nsec_.type_bit_maps = type_nsec::parse_type_bit_maps(
                read_head, rd_length - (start_cap - read_head.size()));
            str_ = type_nsec_.to_string();
            break;
        case type_ds::num:
            type_ds_.key_tag = ntohs(*read_head.get_ptr_and_add<uint16_t>());
            type_ds_.algorithm = *read_head.get_ptr_and_add<uint8_t>();
            type_ds_.digest_type = *read_head.get_ptr_and_add<uint8_t>();
            type_ds_.digest = utils::mem_to_hexstring(read_head, rd_length - (start_cap - read_head.size()));
            str_ = type_ds_.to_string();
            break;
        default:
            str_ = "";
            break;
    }
    const auto unread_length = rd_length - (start_cap - read_head.size());
    read_head += unread_length;
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

std::string dns_type::type_a::to_string() const
{
    return address;
}

std::string dns_type::type_aaaa::to_string() const
{
    return address;
}

std::string dns_type::type_cname::to_string() const
{
    return cname;
}

std::string dns_type::type_ptr::to_string() const
{
    return ptrdname;
}

std::string dns_type::type_mx::to_string() const
{
    std::stringstream stream;
    stream << "\"" << preference << " " << exchange << "\"";
    return stream.str();
}

std::string dns_type::type_ns::to_string() const
{
    return nsdname;
}

std::string dns_type::type_soa::to_string() const
{
    std::stringstream stream;
    stream << "\"" << mname << " " << rname << " " << serial << " " << refresh << " " << retry
        << " " << expire << " " << minimum << "\"";
    return stream.str();
}

std::string dns_type::type_txt::to_string() const
{
    std::stringstream stream;
    stream << "\"" << txt_data << "\"";
    return stream.str();
}

std::string dns_type::type_spf::to_string() const
{
    std::stringstream stream;
    stream << "\"" << spf_data << "\"";
    return stream.str();
}

std::string dns_type::type_dnskey::to_string() const
{
    std::stringstream stream;
    stream << "\"" << flags << " " << static_cast<uint16_t>(protocol) << " " << static_cast<uint16_t>(algorithm)
        << " ( " << public_key << " )\"";
    return stream.str();
}

std::string dns_type::type_rrsig::to_string() const
{
    std::stringstream stream;
    stream << "\"" << get_type_name(type_covered) << " " << static_cast<uint16_t>(algorithm) << " "
        << static_cast<uint16_t>(labels) << " " << original_ttl << " " << signature_expiration << " ( "
        << signature_inception << " " << key_tag << " " << signers_name << " " << signature << " )\"";
    return stream.str();
}

std::string dns_type::type_nsec::parse_type_bit_maps(utils::memory_block& mem, const uint64_t length)
{
    const auto map_length = ntohs(*mem.get_ptr_and_add<uint16_t>());
    if (map_length + 2 != length)
    {
        throw dns_parsing_error("Error: parse_type_bit_maps");
    }
    uint32_t type_num = 0;
    std::stringstream stream;
    for (auto i = 0; i < map_length; i++)
    {
        const auto next_byte = *mem.get_ptr_and_add<uint8_t>();
        for (auto rotate = 7; rotate >= 0; rotate--)
        {
            if (next_byte >> rotate & 1)
            {
                stream << get_type_name(type_num) << " ";
            }
            type_num++;
        }
    }
    auto ret = stream.str();
    if (!ret.empty())
        ret.pop_back();
    return ret;
}

std::string dns_type::type_nsec::to_string() const
{
    std::stringstream stream;
    stream << "\"" << next_domain_name << " " << type_bit_maps << "\"";
    return stream.str();
}

std::string dns_type::type_ds::to_string() const
{
    std::stringstream stream;
    stream << "\"" << key_tag << " " << static_cast<uint16_t>(algorithm) << " " << static_cast<uint16_t>(digest_type)
        << " ( " << digest << " )\"";
    return stream.str();
}
