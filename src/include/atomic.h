/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_ATOMIC_H_
#define MINK_ATOMIC_H_

#include <string.h>

namespace mink {

/**
 * Atomic type
 */
    template <typename T> class Atomic {
    private:
        T value; /**< atomically protected variable */

    public:
        /**
         * Default constructor
         */
        Atomic() {
            memset(&value, 0, sizeof(T));
        }

        /*
         * Atomic GET operation (FETCH and ADD 0)
         * @return	Current value
         *
         */
        T get() { return __sync_fetch_and_add(&value, 0); }

        /*
         * Atomic ADD operation
         *
         * @param[in]	increment	Increment by increment
         * @return	Value after this operation
         *
         */
        T add_fetch(T increment) { return __sync_add_and_fetch(&value, increment); }

        /*
         * Atomic ADD operation
         *
         * @param[in]	increment	Increment by increment
         * @return	Value before this operation
         *
         */
        T fetch_add(T increment) { return __sync_fetch_and_add(&value, increment); }

        /*
         * Atomic bitwise AND operation
         *
         * @param[in]	_value	Bitwise AND by _value
         * @return	Value before this operation
         *
         */
        T fetch_and(T _value) { return __sync_fetch_and_and(&value, _value); }

        /*
         * Atomic bitwise AND operation
         *
         * @param[in]	_value	Bitwise AND by _value
         * @return	Value after this operation
         *
         */
        T and_fetch(T _value) { return __sync_and_and_fetch(&value, _value); }

        /*
         * Atomic SUB operation
         *
         * @param[in]	decrement	Decrement by decrement
         * @return	Value before this operation
         *
         */
        T fetch_sub(T decrement) { return __sync_fetch_and_sub(&value, decrement); }

        /*
         * Atomic SUB operation
         *
         * @param[in]	decrement	Decrement by decrement
         * @return	Value after this operation
         *
         */
        T sub_fetch(T decrement) { return __sync_sub_and_fetch(&value, decrement); }

        /*
         * Atomic CAS (compare and swap) operation
         * 	- if the current value is old_val, replace it with new_val
         *
         * @param[in]	old_val		Expected value
         * @param[in]	new_val		New value
         * @return	Value before this operation
         *
         */
        T comp_swap(T old_val, T new_val) {
            return __sync_val_compare_and_swap(&value, old_val, new_val);
        }

        /*
         * Atomic exchange operation
         *
         * @param[in]	new_val		New value
         * @return	Value before this operation
         *
         */
        T set(T new_val) { return __sync_lock_test_and_set(&value, new_val); }
    };

}  // namespace mink

#endif /* MINK_ATOMIC_H_ */
