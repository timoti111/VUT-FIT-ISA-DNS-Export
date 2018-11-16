/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief statistics class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "../packet/protocols/dns/dns_resource_record.h"
#include <map>
#include <mutex>
#include <vector>

/**
 * @brief Singleton class for collecting and printing statistics. Can be accessed from more threads.
 */
class statistics
{
    std::mutex mutex_{}; // mutex for accessing stats_ map from more threads
    std::map<std::string, unsigned long> stats_{}; // map of string representations of dns answers and count

    /**
     * @brief Hidden constructor so class can't be instantiated.
     */
    statistics()
    {
    };

public:
    static statistics& get_instance();
    statistics(statistics const&) = delete; // deleted copy constructor
    void operator=(statistics const&) = delete; // deleted copy operator
    void add(const std::string& stat);
    void add(const std::vector<dns_resource_record>& stat);
    std::map<std::string, unsigned long> get_map();
    bool empty();
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& stream, statistics& obj);
};
