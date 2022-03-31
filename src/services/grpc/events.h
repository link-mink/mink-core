/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef GRPCD_EVENTS_H
#define GRPCD_EVENTS_H

#include <mink_pkg_config.h>
#include <gdt_utils.h>

// ncurses grpc fix
#undef OK

// fwd
#ifdef MINK_ENABLE_CONFIGD
class EVHbeatRecv;
class EVHbeatMissed;
class EVHbeatCleanup;
#endif
class EVSrvcMsgDone;
class EVSrvcMsgErr;
class EVSrvcMsgRX;
class EVSrvcMsgRecv;
class EVSrvcMsgSent;

#ifdef MINK_ENABLE_CONFIGD
class EVHbeatMissed : public gdt::GDTCallbackMethod {
public:
    explicit EVHbeatMissed(mink::Atomic<uint8_t> *_activity_flag);
    void run(gdt::GDTCallbackArgs *args) override;

    mink::Atomic<uint8_t> *activity_flag;
};

// HBEAT received
class EVHbeatRecv : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;
};

// HBEAT cleanup
class EVHbeatCleanup : public gdt::GDTCallbackMethod {
public:
    EVHbeatCleanup(EVHbeatRecv *_recv, EVHbeatMissed *_missed);
    void run(gdt::GDTCallbackArgs *args) override;

    EVHbeatMissed *missed;
    EVHbeatRecv *recv;
};
#endif

// Outbound service message sent
class EVSrvcMsgSent: public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs* args) override;
};


// Inbound service message received
class EVSrvcMsgRecv : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;

    EVSrvcMsgSent srvc_msg_sent;
};

// Service message error
class EVSrvcMsgErr : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;
};

// Param stream last fragment
class EVParamStreamLast : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;
};


// Param stream next fragment
class EVParamStreamNext : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;
};


// New Param stream
class EVParamStreamNew : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;

    EVParamStreamNext prm_strm_next;
    EVParamStreamLast prm_strm_last;
};


// New inbound service message started
class EVSrvcMsgRX : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args) override;

    EVSrvcMsgErr msg_err;
    EVSrvcMsgRecv msg_recv;
    EVParamStreamNew prm_strm_new;
};


#endif /* ifndef GRPCD_EVENTS_H */
