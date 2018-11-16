/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief utils class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <string>
#include "memory_block.h"

/**
 * @brief Class with helpful utilities.
 */
class utils
{
public:
    static std::string parse_label_name(memory_block& read_head, memory_block& whole_buffer);
    static std::string bin_address_to_string(const void* address_ptr, int address_family);
    static std::string bin_address_to_string(memory_block& data, int64_t length);
    static std::string mem_to_string(memory_block& mem, int64_t length);
    static std::string mem_to_hex_string(memory_block& mem, int64_t length);
};
