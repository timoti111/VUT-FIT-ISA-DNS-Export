/**
 * Project: DNS Lookup nastroj
 *
 * @brief Error class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <stdexcept>

class my_exception : std::runtime_error
{
    const char* file_;
    const int line_;
    const char* func_;
    const char* info_;
public:
    my_exception(const char* msg, const char* file, const int line, const char* func, const char* info = "") :
        std::runtime_error(msg), file_(file), line_(line), func_(func), info_(info)
    {
    }

    const char* get_file() const;
    int get_line() const;
    const char* get_func() const;
    const char* get_info() const;
};

class dns_parsing_error : public std::runtime_error
{
public:
    explicit dns_parsing_error(const std::string& arg) : runtime_error(arg)
    {
    }
};

class argument_parsing_error : public std::runtime_error
{
public:
    explicit argument_parsing_error(const std::string& arg) : runtime_error(arg)
    {
    }
};

class packet_capture_error : public std::runtime_error
{
public:
    explicit packet_capture_error(const std::string& arg) : runtime_error(arg)
    {
    }
};
