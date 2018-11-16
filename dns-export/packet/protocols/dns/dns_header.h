/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_header class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "../../../utils/utils.h"

/**
 * @brief Class representing DNS Header section
 */
class dns_header
{
    uint16_t flags_{}; // temporary memory where flags will be stored and then converted to structure flags
public:
    // for more info about DNS Header items see RFC1035
    uint16_t id{};
    #pragma pack(push, 1)
    struct flags
    {
        uint16_t qr : 1;
        uint16_t op_code : 4;
        uint16_t aa : 1;
        uint16_t tc : 1;
        uint16_t rd : 1;
        uint16_t ra : 1;
        uint16_t z : 3;
        uint16_t r_code : 4;
    } flags{};
    #pragma pack(pop)
    uint16_t qd_count{};
    uint16_t an_count{};
    uint16_t ns_count{};
    uint16_t ar_count{};
    dns_header() = default;
    explicit dns_header(memory_block& read_head);
};
