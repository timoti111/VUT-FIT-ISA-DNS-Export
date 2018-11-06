#pragma once
#include <map>
#include "dns_resource_record.h"

class statistics : public std::map<std::string, unsigned long>
{
    statistics()
    {
    } // Constructor? (the {} brackets) are needed here.
public:
    static statistics& get_instance();
    statistics(statistics const&) = delete;
    void operator=(statistics const&) = delete;
    void add(std::string stat);
    void add(std::vector<dns_resource_record>& stat);
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, statistics& obj);
};
