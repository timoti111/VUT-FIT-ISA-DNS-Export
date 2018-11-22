/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_questions class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <cstdint>
#include "dns_question.h"
#include "../../../utils/utils.h"
#include <vector>

/**
 * @brief Class representing more questions in message. See Question section in RFC1035.
 */
class dns_questions
{
public:
    std::vector<dns_question> questions{}; // vector of questions
    dns_questions() = default;
    dns_questions(memory_block& read_head, memory_block& whole_buffer, uint16_t count);
    dns_question operator[](size_t index);
    size_t size() const;
};
