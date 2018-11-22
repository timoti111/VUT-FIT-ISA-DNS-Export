/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_type class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "../../../utils/base64.h" // https://github.com/ReneNyffenegger/cpp-base64
#include "dns_type.h"
#include "../../../utils/exceptions.h"
#include <netinet/in.h>
#include <sstream>

/**
 * @brief Parses one DNS type which is defined. Skips unknown types.
 * @param type Numeric representation of type.
 * @param read_head Actual position in whole packet buffer.
 * @param whole_buffer Whole packet buffer.
 * @param rd_length Length of data in type.
 */
dns_type::dns_type(const uint16_t type, memory_block& read_head, memory_block& whole_buffer,
                   const uint16_t rd_length) : type_(get_type_name(type))
{
    int64_t remaining_length = 0;
    const auto start_cap = read_head.size();
    switch (type)
    {
        case type_a::num:
            type_a_.address = utils::bin_address_to_string(read_head, rd_length);
            str_ = type_a_.to_string();
            break;
        case type_aaaa::num:
            type_aaaa_.address = utils::bin_address_to_string(read_head, rd_length);
            str_ = type_aaaa_.to_string();
            break;
        case type_cname::num:
            type_cname_.cname = utils::parse_label_name(read_head, whole_buffer);
            str_ = type_cname_.to_string();
            break;
        case type_ptr::num:
            type_ptr_.ptrdname = utils::parse_label_name(read_head, whole_buffer);
            str_ = type_ptr_.to_string();
            break;
        case type_mx::num:
            type_mx_.preference = ntohs(*read_head.get_ptr_and_add<uint16_t>());
            type_mx_.exchange = utils::parse_label_name(read_head, whole_buffer);
            str_ = type_mx_.to_string();
            break;
        case type_ns::num:
            type_ns_.nsdname = utils::parse_label_name(read_head, whole_buffer);
            str_ = type_ns_.to_string();
            break;
        case type_soa::num:
            type_soa_.mname = utils::parse_label_name(read_head, whole_buffer);
            type_soa_.rname = utils::parse_label_name(read_head, whole_buffer);
            type_soa_.serial = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.refresh = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.retry = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.expire = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            type_soa_.minimum = ntohl(*read_head.get_ptr_and_add<uint32_t>());
            str_ = type_soa_.to_string();
            break;
        case type_txt::num:
            type_txt_.txt_data = type_txt::parse_txt_data(read_head, rd_length);
            str_ = type_txt_.to_string();
            break;
        case type_spf::num:
            type_spf_.spf_data = type_txt::parse_txt_data(read_head, rd_length);
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
            type_rrsig_.signers_name = utils::parse_label_name(read_head, whole_buffer);
            remaining_length = rd_length - (start_cap - read_head.size());
            read_head += remaining_length;
            type_rrsig_.signature = base64_encode(read_head.begin() - remaining_length, remaining_length);
            str_ = type_rrsig_.to_string();
            break;
        case type_nsec::num:
            type_nsec_.next_domain_name = utils::parse_label_name(read_head, whole_buffer);
            type_nsec_.type_bit_maps = type_nsec::parse_type_bit_maps(
                read_head, rd_length - (start_cap - read_head.size()));
            str_ = type_nsec_.to_string();
            break;
        case type_ds::num:
            type_ds_.key_tag = ntohs(*read_head.get_ptr_and_add<uint16_t>());
            type_ds_.algorithm = *read_head.get_ptr_and_add<uint8_t>();
            type_ds_.digest_type = *read_head.get_ptr_and_add<uint8_t>();
            type_ds_.digest = utils::mem_to_hex_string(read_head, rd_length - (start_cap - read_head.size()));
            str_ = type_ds_.to_string();
            break;
        default:
            str_ = "";
            break;
    }
    const auto unread_length = rd_length - (start_cap - read_head.size());
    read_head += unread_length;
}

/**
 * @brief Returns literal type of actual data.
 * @return Literal type of actual data.
 */
std::string dns_type::get_type() const
{
    return type_;
}

/**
 * @brief Returns literal representation of actual data.
 * @return Literal representation of actual data.
 */
std::string dns_type::to_string() const
{
    return str_;
}

/**
 * @brief Allows this class to be appended to stream via << operator.
 * @param stream Stream.
 * @param obj Statistics object.
 * @return To stream.
 */
std::ostream& operator<<(std::ostream& stream, dns_type& obj)
{
    return stream << obj.to_string();
}

/**
 * @brief Converts numeric representation of type to literal.
 * @param type Numeric representation of type.
 * @return Literal representation of type. If type is unknown returns TYPExx format.
 */
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

/**
 * @brief Returns literal representation of A type.
 * @return Literal representation of A type.
 */
std::string dns_type::type_a::to_string() const
{
    return address;
}

/**
 * @brief Returns literal representation of AAAA type.
 * @return Literal representation of AAAA type.
 */
std::string dns_type::type_aaaa::to_string() const
{
    return address;
}

/**
 * @brief Returns literal representation of CNAME type.
 * @return Literal representation of CNAME type.
 */
std::string dns_type::type_cname::to_string() const
{
    return cname;
}

/**
 * @brief Returns literal representation of PTR type.
 * @return Literal representation of PTR type.
 */
std::string dns_type::type_ptr::to_string() const
{
    return ptrdname;
}

/**
 * @brief Returns literal representation of MX type.
 * @return Literal representation of MX type.
 */
std::string dns_type::type_mx::to_string() const
{
    std::stringstream stream;
    stream << "\"" << preference << " " << exchange << "\"";
    return stream.str();
}

/**
 * @brief Returns literal representation of NS type.
 * @return Literal representation of NS type.
 */
std::string dns_type::type_ns::to_string() const
{
    return nsdname;
}

/**
 * @brief Returns literal representation of SOA type.
 * @return Literal representation of SOA type.
 */
std::string dns_type::type_soa::to_string() const
{
    std::stringstream stream;
    stream << "\"" << mname << " " << rname << " " << serial << " " << refresh << " " << retry
        << " " << expire << " " << minimum << "\"";
    return stream.str();
}

/**
 * @brief Parses TXT type data.
 * @param mem Actual pointer to memory.
 * @param length Length of data to parse.
 * @return TXT data in string.
 */
std::string dns_type::type_txt::parse_txt_data(memory_block& mem, int64_t length)
{
    std::stringstream stream;
    while (length > 0)
    {
        auto len = *mem.get_ptr_and_add<uint8_t>();
        stream << utils::mem_to_string(mem, len);
        length -= 1 + len;
        if (length > 0)
        {
            stream << " ";
        }
    }
    return stream.str();
}

/**
 * @brief Returns literal representation of TXT type.
 * @return Literal representation of TXT type.
 */
std::string dns_type::type_txt::to_string() const
{
    std::stringstream stream;
    stream << "\"" << txt_data << "\"";
    return stream.str();
}

/**
 * @brief Returns literal representation of SPF type.
 * @return Literal representation of SPF type.
 */
std::string dns_type::type_spf::to_string() const
{
    std::stringstream stream;
    stream << "\"" << spf_data << "\"";
    return stream.str();
}

/**
 * @brief Returns literal representation of DNSKEYA type.
 * @return Literal representation of DNSKEY type.
 */
std::string dns_type::type_dnskey::to_string() const
{
    std::stringstream stream;
    stream << "\"" << flags << " " << static_cast<uint16_t>(protocol) << " " << static_cast<uint16_t>(algorithm)
        << " " << public_key << "\"";
    return stream.str();
}

/**
 * @brief Returns literal representation of RRSIG type.
 * @return Literal representation of RRSIG type.
 */
std::string dns_type::type_rrsig::to_string() const
{
    std::stringstream stream;
    stream << "\"" << get_type_name(type_covered) << " " << static_cast<uint16_t>(algorithm) << " "
        << static_cast<uint16_t>(labels) << " " << original_ttl << " " << signature_expiration << " "
        << signature_inception << " " << key_tag << " " << signers_name << " " << signature << "\"";
    return stream.str();
}

/**
 * @brief For more information see RFC4034 section 4.1.2.
 * @param mem Actual pointer to memory.
 * @param length Length of data to parse.
 * @return RR set types.
 */
std::string dns_type::type_nsec::parse_type_bit_maps(memory_block& mem, int64_t length)
{
    std::stringstream stream;
    while (length > 1)
    {
        uint32_t type_num = *mem.get_ptr_and_add<uint8_t>() * 256;
        const auto map_length = *mem.get_ptr_and_add<uint8_t>();
        length -= map_length + 2;
        if (length < 0)
        {
            throw dns_parsing_error("Corrupted packet");
        }
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
    }
    auto ret = stream.str();
    if (!ret.empty())
        ret.pop_back();
    return ret;
}

/**
 * @brief Returns literal representation of NSEC type.
 * @return Literal representation of NSEC type.
 */
std::string dns_type::type_nsec::to_string() const
{
    std::stringstream stream;
    stream << "\"" << next_domain_name << " " << type_bit_maps << "\"";
    return stream.str();
}

/**
 * @brief Returns literal representation of DS type.
 * @return Literal representation of DS type.
 */
std::string dns_type::type_ds::to_string() const
{
    std::stringstream stream;
    stream << "\"" << key_tag << " " << static_cast<uint16_t>(algorithm) << " " << static_cast<uint16_t>(digest_type)
        << " " << digest << "\"";
    return stream.str();
}
