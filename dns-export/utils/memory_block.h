/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief memory_block class header
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#pragma once
#include "exceptions.h"
#include <cstdint>

/**
 * @brief Class which represents safe pointer with basic operators for memory access.
 */
class memory_block
{
    uint8_t* ptr_; // pointer to memory
    int64_t length_; // available length of memory
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

/**
 * @brief Returns pointer to type T. 
 * @tparam T Length will be checked if there is enough memory for pointer representation as type T.
 * @return Pointer to type T from actual position in memory.
 */
template <typename T>
T* memory_block::get_ptr()
{
    if (sizeof(T) > length_)
    {
        throw memory_error("Can't access memory.");
    }
    return reinterpret_cast<T*>(ptr_);
}

/**
 * @brief Returns pointer to type T and shortens memory block from front by size of T.
 * @tparam T Length will be checked if there is enough memory for pointer representation as type T.
 * @return Pointer to type T from actual position in memory.
 */
template <typename T>
T* memory_block::get_ptr_and_add()
{
    if (sizeof(T) > length_)
    {
        throw memory_error("Can't access memory.");
    }
    T* ret = reinterpret_cast<T*>(ptr_);
    *this += sizeof(T);
    return ret;
}
