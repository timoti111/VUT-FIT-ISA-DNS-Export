/**
 * Project: Export of DNS informations over Syslog protocol
 *
 * @brief dns_resource_records class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "dns_resource_records.h"
#include "utils.h"
#include <sstream>

/**
 * This constructor reads data from buffer and represents it as more DNS Resource Records
 * @param read_head reference to memory where read head is currently
 * @param whole_buffer pointer to whole buffer so records can be decompressed
 * @param count number of records to be parsed
 */
dns_resource_records::dns_resource_records(utils::memory_block& read_head, utils::memory_block& whole_buffer,
                                           const uint16_t count)
{
    for (uint16_t i = 0; i < count; i++)
    {
        dns_resource_record record(read_head, whole_buffer);
        if (record.r_data.get_type().find("TYPE") == std::string::npos)
            records.push_back(record);
    }
}

/**
 * Operator for accessing specific record
 * @param index index of record to be returned
 * @return Resource record
 */
dns_resource_record dns_resource_records::operator[](const size_t index)
{
    return records[index];
}

/**
 * Returns number of Resource records
 * @return number of records
 */
size_t dns_resource_records::size() const
{
    return records.size();
}

std::string dns_resource_records::to_string()
{
    std::stringstream stream;
    for (auto& element : records)
    {
        stream << element << std::endl;
    }
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, dns_resource_records& obj)
{
    return stream << obj.to_string();
}
