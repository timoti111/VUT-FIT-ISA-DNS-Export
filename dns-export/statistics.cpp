#include "statistics.h"
#include <sstream>

statistics::statistics()
{
}

statistics& statistics::get_instance()
{
    static statistics instance; // Guaranteed to be destroyed.
    // Instantiated on first use.
    return instance;
}

void statistics::add(const std::string& stat)
{
	std::lock_guard<std::mutex> lock(mutex_);
    stats_[stat]++;
}

void statistics::add(const std::vector<dns_resource_record>& stats)
{
	std::lock_guard<std::mutex> lock(mutex_);
    for (auto element : stats)
    {
		stats_[element.to_string()]++;
    }
}

std::map<std::string, unsigned long> statistics::get_map()
{
	std::lock_guard<std::mutex> lock(mutex_);
	return std::map<std::string, unsigned long>(stats_);
}

bool statistics::empty()
{
	std::lock_guard<std::mutex> lock(mutex_);
	return stats_.empty();
}

std::string statistics::to_string()
{
    std::stringstream stream;
	std::lock_guard<std::mutex> lock(mutex_);
    for (auto element : stats_)
    {
        stream << element.first << " " << element.second << std::endl;
    }
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, statistics& obj)
{
    return stream << obj.to_string();
}
