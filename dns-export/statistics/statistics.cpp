/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief statistics class source file
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include <sstream>
#include "statistics.h"

/**
 * @brief Singleton method for returning only one instance of this class.
 * @return Returns only one and same instance of statistics class every time method is called.
 */
statistics& statistics::get_instance()
{
    static statistics instance;
    return instance;
}

/**
 * @brief Locks mutex, appends string representation of something to as key map. If key exists increments value for key. Unlocks mutex.
 * @param stat Reference to string representation of something.
 */
void statistics::add(const std::string& stat)
{
    std::lock_guard<std::mutex> lock(mutex_);
    stats_[stat]++;
}

/**
 * @brief Locks mutex, appends every answer in dns_answers to map as string and unlocks mutex.
 * @param dns_answers Reference to vector of DNS resource records.
 */
void statistics::add(const std::vector<dns_resource_record>& dns_answers)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto element : dns_answers)
    {
        stats_[element.to_string()]++;
    }
}

/**
 * @brief Locks mutex, returns map and unlocks mutex.
 * @return Returns copy of stats_ map.
 */
std::map<std::string, unsigned long> statistics::get_map()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return std::map<std::string, unsigned long>(stats_);
}

/**
 * @brief Locks mutex, checks if map is empty and unlocks mutex.
 * @return Returns true if map is empty else returns false.
 */
bool statistics::empty()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.empty();
}

/**
 * @brief Locks mutex, converts map to string representation and unlocks mutex
 * @return 
 */
std::string statistics::to_string()
{
    std::stringstream stream;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& element : stats_)
    {
        stream << element.first << " " << element.second << std::endl;
    }
    return stream.str();
}

/**
 * @brief Allows this class to be appended to stream via << operator.
 * @param stream Stream.
 * @param obj Statistics object.
 * @return To stream.
 */
std::ostream& operator<<(std::ostream& stream, statistics& obj)
{
    return stream << obj.to_string();
}
