/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_questions class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_questions.h"

/**
 * @brief This constructor reads data from buffer and represents it as more DNS questions.
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so records can be decompressed
 * @param count number of records to be parsed
 */
dns_questions::dns_questions(memory_block& read_head, memory_block& whole_buffer,
                         const uint16_t count)
{
    for (uint16_t i = 0; i < count; i++)
    {
        dns_question query(read_head, whole_buffer);
        questions.push_back(query);
    }
}

/**
 * @brief Operator for accessing specific record
 * @param index index of record to be returned
 * @return Resource record
 */
dns_question dns_questions::operator[](const size_t index)
{
    return questions[index];
}

/**
 * @brief Returns number of questions
 * @return number of records
 */
size_t dns_questions::size() const
{
    return questions.size();
}
