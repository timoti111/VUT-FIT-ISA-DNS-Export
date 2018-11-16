/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief Header with custom made exceptions
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <stdexcept>

/**
 * @brief Exception thrown when something is bad with arguments.
 */
class argument_parsing_error : public std::runtime_error
{
public:
    explicit argument_parsing_error(const std::string& arg) : runtime_error(arg)
    {
    }
};

/**
 * @brief Exception thrown when error happen while capturing packets in pcap library.
 */
class packet_capture_error : public std::runtime_error
{
public:
    explicit packet_capture_error(const std::string& arg) : runtime_error(arg)
    {
    }
};

/**
 * @brief Exception thrown when error happen while parsing non-application layer.
 */
class packet_parsing_error : public std::runtime_error
{
public:
    explicit packet_parsing_error(const std::string& arg) : runtime_error(arg)
    {
    }
};

/**
 * @brief Exception thrown when application layer is not in dns format.
 */
class dns_parsing_error : public std::runtime_error
{
public:
    explicit dns_parsing_error(const std::string& arg) : runtime_error(arg)
    {
    }
};


/**
 * @brief Exception thrown when trying to access unaccessible memory.
 */
class memory_error : public std::runtime_error
{
public:
    explicit memory_error(const std::string& arg) : runtime_error(arg)
    {
    }
};

/**
 * @brief Exception thrown when something other happen except above exceptions.
 */
class other_error : public std::runtime_error
{
public:
    explicit other_error(const std::string& arg) : runtime_error(arg)
    {
    }
};
