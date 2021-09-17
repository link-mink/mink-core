/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef RING_H_
#define RING_H_

#include <pthread.h>
#include <boost/circular_buffer.hpp>

namespace mink {
    /**
     * Ring buffer based on boost::circular_buffer
     * @param[in]   TYPE    data type
     * @param[in]   THSAFE  thread safety flag
     */
    template <typename TYPE, bool THSAFE = true> class RingBuffer {
    public:
        /**
         * Default constructor
         */
        RingBuffer() {
            if (THSAFE) pthread_spin_init(&slock, 0);
        }
        RingBuffer(const RingBuffer &o) = delete;
        RingBuffer &operator=(const RingBuffer &o) = delete;

        /**
         * Destructor
         */
        ~RingBuffer() {
            if (THSAFE) pthread_spin_destroy(&slock);
        }

        /**
         * pop from queue
         * @param[out]  out output pointer for popped data
         * @return  true if pooped or false if empty
         */
        bool pop(TYPE* out) {
            lock();
            if (!buffer.empty()) {
                TYPE tmp = buffer.front();
                buffer.pop_front();
                unlock();
                *out = tmp;
                return true;
            }
            unlock();
            return false;
        }

        /**
         * push to queue
         * @param[in]   data    data tu push
         * @return  true if pushed or false if full
         */
        bool push(TYPE data) {
            lock();
            if (!buffer.full()) {
                buffer.push_back(data);
                unlock();
                return true;
            }
            unlock();
            return false;
        }

        /**
         * Set max queue capacity
         * @param[in]   capacity    queue capacity
         */
        void set_capacity(unsigned int capacity) { buffer.set_capacity(capacity); }

    private:
        /**
         * Lock operation
         */
        void lock() {
            if (THSAFE) pthread_spin_lock(&slock);
        }

        /**
         * Unlock operation
         */
        void unlock() {
            if (THSAFE) pthread_spin_unlock(&slock);
        }

        boost::circular_buffer<TYPE> buffer;
        pthread_spinlock_t slock;
    };

}  // namespace mink

#endif /* RING_H_ */
