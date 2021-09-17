/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef SPSCQ_H_
#define SPSCQ_H_

// gcc memory barrier
#define gcc_mb() __asm__ __volatile__("" : : : "memory")

#include <stdlib.h>
#include <cmath>
#include <iostream>

namespace lockfree {
class QitemBase {
   public:
    int type;
};

template <typename T, int TYPE>
class QItem : public QitemBase {
   public:
    QItem() { type = TYPE; }
    T data;
};

template <typename T>
class SpscQ {
   public:
    typedef struct {
        uint64_t shadow_head;
        char __cacheline_padding_1[56];
        volatile uint64_t head;
        char __cacheline_padding_2[56];
        volatile uint64_t tail;
        char __cacheline_padding_3[56];
        uint64_t shadow_tail;
        char __cacheline_padding_4[56];
        T** items;

    } spsc_queue_t;

    SpscQ() = default;
    SpscQ(const SpscQ &o) = delete;
    SpscQ &operator=(const SpscQ &o) = delete;

    ~SpscQ() {
        if (spsc != nullptr) {
            delete[] spsc->items;
            free(spsc);
        }
    }

    /* qsize will be pow of 2 */
    void init(int qsize) {
        // min qsize = 256
        if (qsize < 256) qsize = 256;
        QSIZE = (int)pow((double)2, (int)ceil(log10(qsize + 1) / log10(2)));
        QUEUE_ITEMS_MASK = QSIZE - 1;
        CACHE_LINE_LEN = 64;
        QUEUE_WATERMARK = 256; /* pow of 2 */
        QUEUE_WATERMARK_MASK = QUEUE_WATERMARK - 1;

        spsc = new_spsc();
        spsc->items = new T*[QSIZE];
    }

    inline int size() const {
        if (spsc->head >= spsc->tail)
            return spsc->head - spsc->tail;
        else
            return QSIZE - (spsc->tail - spsc->head);
    }

    inline int pop(T** item) {
        uint32_t next_tail;

        next_tail = (spsc->shadow_tail + 1) & QUEUE_ITEMS_MASK;
        if (next_tail != spsc->head) {
            *item = spsc->items[next_tail];
            spsc->shadow_tail = next_tail;
            if ((spsc->shadow_tail & QUEUE_WATERMARK_MASK) == 0) {
                gcc_mb();
                spsc->tail = spsc->shadow_tail;
            }
            return 0;
        }
        return 1;
    }

    inline int push(uint8_t flush_item, T* item) {
        uint32_t next_head;
        next_head = (spsc->shadow_head + 1) & QUEUE_ITEMS_MASK;
        if (spsc->tail != next_head) {
            spsc->items[spsc->shadow_head] = item;

            spsc->shadow_head = next_head;
            if (flush_item || (spsc->shadow_head & QUEUE_WATERMARK_MASK) == 0) {
                gcc_mb();
                spsc->head = spsc->shadow_head;
            }
            return 0;
        }
        return 1;
    }

   private:
    spsc_queue_t* new_spsc() {
        SpscQ<T>::spsc_queue_t* tmp_spsc =
            (SpscQ<T>::spsc_queue_t*)calloc(1, sizeof(SpscQ<T>::spsc_queue_t));
        if (tmp_spsc == nullptr) return nullptr;
        tmp_spsc->tail = tmp_spsc->shadow_tail = QSIZE - 1;
        tmp_spsc->head = tmp_spsc->shadow_head = 0;
        return tmp_spsc;
    }

    spsc_queue_t* spsc = nullptr;
    int QUEUE_ITEMS_MASK = 0;
    int CACHE_LINE_LEN = 0;
    int QUEUE_WATERMARK = 0;
    int QUEUE_WATERMARK_MASK = 0;
    int QSIZE = 0;
};

}  // namespace lockfree

#endif /* SPSCQ_H_ */
