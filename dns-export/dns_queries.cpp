/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSResourceRecords class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_queries.h"
#include <sstream>

/**
 * This constructor reads data from buffer and represents it as more DNS Resource Records
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so records can be decompressed
 * @param count number of records to be parsed
 */
dns_queries::dns_queries(dns_utils::memory_block& read_head, dns_utils::memory_block& whole_buffer,
                         const uint16_t count)
{
    for (uint16_t i = 0; i < count; i++)
    {
        dns_query query(read_head, whole_buffer);
        questions.push_back(query);
    }
} /**
 * Operator for accessing specific record
 * @param index index of record to be returned
 * @return Resource record
 */
dns_query dns_queries::operator[](const size_t index)
{
    return questions[index];
} /**
 * Returns number of Resource records
 * @return number of records
 */
size_t dns_queries::size() const
{
    return questions.size();
}

std::string dns_queries::to_string()
{
    std::stringstream stream;
    for (auto element : questions)
    {
        stream << element << std::endl;
    }
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, dns_queries& obj)
{
    return stream << obj.to_string();
}
