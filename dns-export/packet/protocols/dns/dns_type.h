/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_type class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "../../../utils/utils.h"

/**
 * @brief Class representing DNS type.
 */
class dns_type
{
    // For more info about these DNS types see RFC1035, RFC 3596, RFC4034

    /**
     * @brief Structure representing A DNS type.
     */
    struct type_a
    {
        static const uint16_t num = 1;
        std::string address{};
        std::string to_string() const;
    } type_a_{};

    /**
     * @brief Structure representing AAAA DNS type.
     */
    struct type_aaaa
    {
        static const uint16_t num = 28;
        std::string address{};
        std::string to_string() const;
    } type_aaaa_{};

    /**
     * @brief Structure representing CNAME DNS type.
     */
    struct type_cname
    {
        static const uint16_t num = 5;
        std::string cname{};
        std::string to_string() const;
    } type_cname_{};

    /**
     * @brief Structure representing PTR DNS type.
     */
    struct type_ptr
    {
        static const uint16_t num = 12;
        std::string ptrdname{};
        std::string to_string() const;
    } type_ptr_{};

    /**
     * @brief Structure representing MX DNS type.
     */
    struct type_mx
    {
        static const uint16_t num = 15;
        uint16_t preference{};
        std::string exchange{};
        std::string to_string() const;
    } type_mx_{};

    /**
     * @brief Structure representing NS DNS type.
     */
    struct type_ns
    {
        static const uint16_t num = 2;
        std::string nsdname{};
        std::string to_string() const;
    } type_ns_;

    /**
     * @brief Structure representing SOA DNS type.
     */
    struct type_soa
    {
        static const uint16_t num = 6;
        std::string mname{};
        std::string rname{};
        uint32_t serial{};
        uint32_t refresh{};
        uint32_t retry{};
        uint32_t expire{};
        uint32_t minimum{};
        std::string to_string() const;
    } type_soa_{};

    /**
     * @brief Structure representing TXT DNS type.
     */
    struct type_txt
    {
        static const uint16_t num = 16;
        std::string txt_data{};
        std::string to_string() const;
    } type_txt_{};

    /**
     * @brief Structure representing SPF DNS type.
     */
    struct type_spf
    {
        static const uint16_t num = 99;
        std::string spf_data{};
        std::string to_string() const;
    } type_spf_{};

    /**
     * @brief Structure representing DNSKEY DNS type.
     */
    struct type_dnskey
    {
        static const uint16_t num = 48;
        uint16_t flags{};
        uint8_t protocol{};
        uint8_t algorithm{};
        std::string public_key{};
        std::string to_string() const;
    } type_dnskey_{};

    /**
     * @brief Structure representing RRSIG DNS type.
     */
    struct type_rrsig
    {
        static const uint16_t num = 46;
        uint16_t type_covered{};
        uint8_t algorithm{};
        uint8_t labels{};
        uint32_t original_ttl{};
        uint32_t signature_expiration{};
        uint32_t signature_inception{};
        uint16_t key_tag{};
        std::string signers_name{};
        std::string signature{};
        std::string to_string() const;
    } type_rrsig_{};

    /**
     * @brief Structure representing NSEC DNS type.
     */
    struct type_nsec
    {
        static const uint16_t num = 47;
        std::string next_domain_name{};
        std::string type_bit_maps{};
        static std::string parse_type_bit_maps(memory_block& mem, const uint64_t length);
        std::string to_string() const;
    } type_nsec_{};

    /**
     * @brief Structure representing DS DNS type.
     */
    struct type_ds
    {
        static const uint16_t num = 43;
        uint16_t key_tag{};
        uint8_t algorithm{};
        uint8_t digest_type{};
        std::string digest{};
        std::string to_string() const;
    } type_ds_{};

    std::string str_{}; // String representation of data from type.
    std::string type_{}; // String representation of type.
public:
    dns_type() = default;
    dns_type(uint16_t type, memory_block& read_head, memory_block& whole_buffer,
             uint16_t rd_length);
    std::string get_type() const;
    std::string to_string() const;
    friend std::ostream& operator<<(std::ostream& stream, dns_type& obj);
    static std::string get_type_name(uint16_t type);
};
