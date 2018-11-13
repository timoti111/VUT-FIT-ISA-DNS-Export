#pragma once
#include <map>
#include "dns_resource_record.h"
#include <mutex>

class statistics
{
	std::mutex mutex_;
	std::map<std::string, unsigned long> stats_;
    statistics(); // Constructor? (the {} brackets) are needed here.
public:
    static statistics& get_instance();
    statistics(statistics const&) = delete;
    void operator=(statistics const&) = delete;
    void add(const std::string& stat);
    void add(const std::vector<dns_resource_record>& stat);
	std::map<std::string, unsigned long> get_map();
	bool empty();
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, statistics& obj);
};
