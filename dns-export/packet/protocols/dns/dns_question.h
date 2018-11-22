/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_question class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "../../../utils/utils.h"
#include <string>

/**
 * @brief Class representing one DNS question.
 */
class dns_question
{
public:
    // for more info about DNS Question items see RFC1035
    std::string q_name{};
    uint16_t q_type{};
    uint16_t q_class{};
    dns_question() = default;
    explicit dns_question(memory_block& read_head, memory_block& whole_buffer);
};
