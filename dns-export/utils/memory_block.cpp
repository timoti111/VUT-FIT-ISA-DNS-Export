/**
 * Project: Export of DNS information over Syslog protocol
 *
 * @brief memory_block class source code
 * @author Timotej Halas <xhalas10@stud.fit.vutbr.cz>
 */
#include "memory_block.h"

/**
 * @brief Constructs memory block object.
 * @param ptr Pointer to first byte in memory block.
 * @param length Length of accessible memory.
 */
memory_block::memory_block(uint8_t* ptr, const int64_t length)
{
    if (length < 0)
    {
        throw memory_error("Memory error");
    }
    this->ptr_ = ptr;
    this->length_ = length;
}

/**
 * @brief Returns pointer to first byte in memory block.
 * @return Pointer to first byte in memory block.
 */
uint8_t* memory_block::begin() const
{
    return ptr_;
}

/**
 * @brief Returns pointer to byte beyond last byte in memory block.
 * @return Pointer to byte beyond last byte in memory block.
 */
uint8_t* memory_block::end() const
{
    return ptr_ + length_;
}

/**
 * @brief Returns length of memory block.
 * @return Length of memory block.
 */
int64_t memory_block::size() const
{
    return length_;
}

/**
 * @brief Returns new memory block pointing to ptr_ + rhs.
 * @param rhs How much to increase ptr_.
 * @return Returns new memory block pointing to ptr_ + rhs.
 */
memory_block memory_block::operator+(const int64_t rhs) const
{
    if (rhs > length_ || rhs < 0)
    {
        throw memory_error("Memory error");
    }
    return {ptr_ + rhs, length_ - rhs};
}

/**
 * @brief Increases ptr_ by rhs.
 * @param rhs How much to increase ptr_.
 * @return Returns memory block pointing to ptr_ + rhs.
 */
memory_block& memory_block::operator+=(const int64_t rhs)
{
    *this = *this + rhs;
    return *this;
}

/**
 * @brief Prefix ++ operator. Same as memory_block += 1.
 * @return Returns memory block pointing to ptr_ + 1.
 */
memory_block& memory_block::operator++()
{
    return *this += 1;
}

/**
 * @brief Postfix ++ operator. Returns copied actual memory block and points actual memory block to  ptr_ + 1.
 * @return Returns copied actual memory block.
 */
memory_block memory_block::operator++(int)
{
    const auto result(*this);
    ++(*this);
    return result;
}
