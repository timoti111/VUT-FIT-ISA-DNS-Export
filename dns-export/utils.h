/**
 * Project: DNS Lookup nastroj
 *
 * @brief DNSUtils class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include <iostream>
#include <string>
#include "exceptions.h"

/**
 * Class with helpful utilities for DNS data
 */
class utils
{
    struct hex_char_struct
    {
        uint8_t c;

        explicit hex_char_struct(const uint8_t c) : c(c)
        {
        }
    };

    static hex_char_struct hex(uint8_t c);
    friend std::ostream& operator<<(std::ostream& o, const hex_char_struct& hs);
public:
    struct memory_block
    {
    private:
        uint8_t* ptr_;
        int64_t length_;
    public:
        memory_block(uint8_t* ptr, int64_t length);
        uint8_t* begin() const;
        uint8_t* end() const;
        int64_t size() const;
        memory_block operator+(int64_t rhs) const;
        memory_block& operator+=(int64_t rhs);
        memory_block& operator++();
        memory_block operator++(int);
        template <typename T>
        T* get_ptr();
        template <typename T>
        T* get_ptr_and_add();
    };

    static std::string parse_name(memory_block& read_head, memory_block& whole_buffer);
    static std::string addr_to_string(const void* address_ptr, int address_family);
    static std::string addr_to_string(memory_block& data, int64_t length);
    static std::string mem_to_string(memory_block& mem, int64_t length);
    static std::string mem_to_hexstring(memory_block& mem, int64_t length);
};

template <typename T>
T* utils::memory_block::get_ptr()
{
    if (sizeof(T) > length_)
    {
        throw memory_error("Can't access memory.");
    }
    return reinterpret_cast<T*>(ptr_);
}

template <typename T>
T* utils::memory_block::get_ptr_and_add()
{
    if (sizeof(T) > length_)
    {
        throw memory_error("Can't access memory.");
    }
    T* ret = reinterpret_cast<T*>(ptr_);
    *this += sizeof(T);
    return ret;
}
