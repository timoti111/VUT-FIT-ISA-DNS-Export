#pragma once
#include "dns_utils.h"
#include <sstream>

class dns_type
{
    struct domain_name
    {
        std::vector<unsigned char> data;
        std::string to_string() const;
    };

    struct type_a
    {
        static const uint16_t num = 1;
        std::vector<unsigned char> address;
        std::string to_string() const;
    } type_a_;

    struct type_aaaa
    {
        static const uint16_t num = 28;
        std::vector<unsigned char> address;
        std::string to_string() const;
    } type_aaaa_;

    struct type_cname
    {
        static const uint16_t num = 5;
        domain_name cname;
        std::string to_string() const;
    } type_cname_;

    struct type_ptr
    {
        static const uint16_t num = 12;
        domain_name ptrdname;
        std::string to_string() const;
    } type_ptr_;

    struct type_mx
    {
        static const uint16_t num = 15;
        uint16_t preference;
        domain_name exchange;
        std::string to_string() const;
    } type_mx_{};

    struct type_ns
    {
        static const uint16_t num = 2;
        domain_name nsdname;
        std::string to_string() const;
    } type_ns_;

    struct type_soa
    {
        static const uint16_t num = 6;
        domain_name mname;
        domain_name rname;
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
        std::string to_string() const;
    } type_soa_{};

    struct type_txt
    {
        static const uint16_t num = 16;
        std::string txt_data;
        std::string to_string() const;
    } type_txt_{};

    struct type_spf
    {
        static const uint16_t num = 99;
        std::string spf_data;
        std::string to_string() const;
    } type_spf_{};

    struct type_dnskey
    {
        static const uint16_t num = 48;
        uint16_t flags;
        uint8_t protocol;
        uint8_t algorithm;
        std::vector<unsigned char> public_key;
        std::string to_string() const;
    } type_dnskey_{};

    struct type_rrsig
    {
        static const uint16_t num = 46;
        uint16_t type_covered;
        uint8_t algorithm;
        uint8_t labels;
        uint32_t original_ttl;
        uint32_t signature_expiration;
        uint32_t signature_inception;
        uint16_t key_tag;
        domain_name signers_name;
        std::vector<unsigned char> signature;
        std::string to_string() const;
    } type_rrsig_{};

    struct type_nsec
    {
        static const uint16_t num = 47;
        domain_name next_domain_name;
        std::vector<unsigned char> type_bit_maps;
		std::string parse_type_bit_maps() const;
        std::string to_string() const;
    } type_nsec_;

    struct type_ds
    {
        static const uint16_t num = 43;
        uint16_t key_tag;
        uint8_t algorithm;
        uint8_t digest_type;
        std::vector<unsigned char> digest;
        std::string to_string() const;
    } type_ds_{};

    std::string str_{};
    std::string type_{};
public:
    dns_type() = default;
    dns_type(uint16_t type, dns_utils::memory_block& read_head, dns_utils::memory_block& whole_buffer,
             uint16_t rd_length);
    std::string get_type() const;
    std::string to_string() const;
    friend std::ostream& operator<<(std::ostream& stream, dns_type& obj);
    static std::string get_type_name(uint16_t type);
};
