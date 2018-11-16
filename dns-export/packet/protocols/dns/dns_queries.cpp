/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief dns_queries class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_queries.h"

/**
 * @brief This constructor reads data from buffer and represents it as more DNS questions.
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so records can be decompressed
 * @param count number of records to be parsed
 */
dns_queries::dns_queries(memory_block& read_head, memory_block& whole_buffer,
                         const uint16_t count)
{
    for (uint16_t i = 0; i < count; i++)
    {
        dns_query query(read_head, whole_buffer);
        questions.push_back(query);
    }
}

/**
 * @brief Operator for accessing specific record
 * @param index index of record to be returned
 * @return Resource record
 */
dns_query dns_queries::operator[](const size_t index)
{
    return questions[index];
}

/**
 * @brief Returns number of Resource records
 * @return number of records
 */
size_t dns_queries::size() const
{
    return questions.size();
}
