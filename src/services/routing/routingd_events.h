/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef ROUTINGD_EVENTS_H_
#define ROUTINGD_EVENTS_H_

#include <atomic.h>
#include <mink_config.h>
#include <gdt.h>

class HbeatMissed : public gdt::GDTCallbackMethod {
public:
    explicit HbeatMissed(mink::Atomic<uint8_t> *_activity_flag);
    void run(gdt::GDTCallbackArgs *args) override;

    mink::Atomic<uint8_t> *activity_flag;
};

class HbeatRecv : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;
};

class HbeatCleanup : public gdt::GDTCallbackMethod {
public:
    HbeatCleanup(HbeatRecv *_recv, HbeatMissed *_missed);
    void run(gdt::GDTCallbackArgs *args) override;

    HbeatMissed *missed;
    HbeatRecv *recv;
};

#endif /* ROUTINGD_EVENTS_H_ */
