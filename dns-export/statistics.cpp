#include "statistics.h"
#include <sstream>

statistics& statistics::get_instance()
{
    static statistics instance; // Guaranteed to be destroyed.
    // Instantiated on first use.
    return instance;
}

void statistics::add(std::string stat)
{
    if (this->find(stat) == this->end())
        this->insert(std::make_pair(stat, 0));
    (*this)[stat]++;
}

void statistics::add(std::vector<dns_resource_record>& stat)
{
    for (auto element : stat)
    {
        this->add(element.to_string());
    }
}

std::string statistics::to_string()
{
    std::stringstream stream;
    for (auto element : *this)
    {
        stream << element.first << " " << element.second << std::endl;
    }
    return stream.str();
}

std::ostream& operator<<(std::ostream& stream, statistics& obj)
{
    return stream << obj.to_string();
}
