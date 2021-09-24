/*
 *            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * Copyright (C) 2021  Damir Franusic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HTTPD_EVENTS_H
#define HTTPD_EVENTS_H 

#include <gdt_utils.h>

// ncurses grpc fix
#undef OK

// fwd
class EVHbeatRecv;
class EVHbeatMissed;
class EVHbeatCleanup;
class EVSrvcMsgDone;
class EVSrvcMsgErr;
class EVSrvcMsgRX;
class EVSrvcMsgRecv;
class EVSrvcMsgSent;

class EVHbeatMissed : public gdt::GDTCallbackMethod {
public:
    EVHbeatMissed(mink::Atomic<uint8_t> *_activity_flag);
    void run(gdt::GDTCallbackArgs *args);

    mink::Atomic<uint8_t> *activity_flag;
};

// HBEAT received
class EVHbeatRecv : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args);
};

// HBEAT cleanup
class EVHbeatCleanup : public gdt::GDTCallbackMethod {
public:
    EVHbeatCleanup(EVHbeatRecv *_recv, EVHbeatMissed *_missed);
    void run(gdt::GDTCallbackArgs *args);

    EVHbeatMissed *missed;
    EVHbeatRecv *recv;
};

// Outbound service message sent
class EVSrvcMsgSent: public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs* args);
};


// Inbound service message received
class EVSrvcMsgRecv : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args);

    EVSrvcMsgSent srvc_msg_sent;
};

// Service message error
class EVSrvcMsgErr : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args);
};

// Param stream last fragment
class EVParamStreamLast : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args);
};


// Param stream next fragment
class EVParamStreamNext : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args);
};


// New Param stream
class EVParamStreamNew : public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs *args);

    EVParamStreamNext prm_strm_next;
    EVParamStreamLast prm_strm_last;
};


// New inbound service message started
class EVSrvcMsgRX : public gdt::GDTCallbackMethod {
private:
    EVSrvcMsgRecv msg_recv;

public:
    void run(gdt::GDTCallbackArgs *args);

    EVSrvcMsgErr msg_err;
    EVParamStreamNew prm_strm_new;
};


#endif /* ifndef HTTPD_EVENTS_H */
