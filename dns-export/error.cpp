/**
 * Project: DNS Lookup nastroj
 *
 * @brief Error class source
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "error.h"

const char* my_exception::get_file() const
{
    return file_;
}

int my_exception::get_line() const
{
    return line_;
}

const char* my_exception::get_func() const
{
    return func_;
}

const char* my_exception::get_info() const
{
    return info_;
}
