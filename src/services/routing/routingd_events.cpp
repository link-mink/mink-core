/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "routing.h"
#ifdef MINK_ENABLE_CONFIGD
#include "routingd_events.h"

HbeatMissed::HbeatMissed(mink::Atomic<uint8_t> *_activity_flag) {
    activity_flag = _activity_flag;
}

void HbeatMissed::run(gdt::GDTCallbackArgs *args) {
    auto hi = (gdt::HeartbeatInfo *)args->get_arg(gdt::GDT_CB_INPUT_ARGS, 
                                                  gdt::GDT_CB_ARG_HBEAT_INFO);
    // set activity flag to false
    activity_flag->comp_swap(true, false);
    // stop heartbeat
    gdt::stop_heartbeat(hi);
    // display warning
    mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                              "GDT HBEAT not received, closing connection to [%s]...",
                              hi->target_daemon_id);
}

void HbeatRecv::run(gdt::GDTCallbackArgs *args) {
    // do nothing
}

HbeatCleanup::HbeatCleanup(HbeatRecv *_recv, HbeatMissed *_missed) : missed(_missed),
                                                                     recv(_recv) {}

void HbeatCleanup::run(gdt::GDTCallbackArgs *args) {
    delete recv;
    delete missed;
    delete this;

    // get routingd pointer
    auto routingd = static_cast<RoutingdDescriptor *>(mink::CURRENT_DAEMON);
    // init config until connected
    while (!mink::DaemonDescriptor::DAEMON_TERMINATED &&
           routingd->init_config(false) != 0) {
        sleep(5);
    }
}
#endif
