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

#ifndef HTTP_H
#define HTTP_H

#include <grpcpp/impl/codegen/status_code_enum.h>
#include <grpcpp/grpcpp.h>
#include <gdt.grpc.pb.h>
#include <atomic.h>
#include <mink_config.h>
#include <config_gdt.h>
#include <daemon.h>
#include <mink_utils.h>
#include <gdt.h>
#include <gdt_stats.h>
#include <gdt_utils.h>
#include <sstream>
#include "events.h"
#include "gdtgrpc.h"

// daemon name and description
#define DAEMON_TYPE             "grpcd"
#define DAEMON_DESCRIPTION      "MINK gRPC daemon"
#define DAEMON_CFG_NODE         "mink grpc"

// types
typedef std::vector<std::string *> rtrd_lst_t;
typedef mink_utils::VariantParamMap<uint32_t> pmap_t;

// grpc payload (correlation)
struct GrpcPayload {
    mink_utils::Guid guid;
    RPCBase *cdata;
};

// routing daemon descriptor definition
class GrpcdDescriptor : public mink::DaemonDescriptor {
public:
    // constructor
    GrpcdDescriptor(const char *_type, const char *_desc);
    // destructor
    ~GrpcdDescriptor();

    void process_args(int argc, char **argv);
    void print_help();
    void init_gdt();
    int init_grpc();
    int init_cfg(bool _proc_cfg);
    void init();
    void process_cfg();
    void terminate();
    void cmap_process_timeout();

    // config daemons
    std::vector<std::string *> rtrd_lst;
    // gdt session
    gdt::GDTSession *gdts;
    // gdt client
    gdt::GDTClient *rtrd_gdtc;
    // gdt service message manager
    gdt::ServiceMsgManager* gdtsmm;
    // idt map
    gdt::ParamIdTypeMap idt_map;
    // GDT stats
    gdt::GDTStatsSession *gdt_stats;
    // cfgd activity flag
    mink::Atomic<uint8_t> cfgd_active;
    // config
    config::Config *config;
    // current cfg id
    unsigned char cfgd_id[16];
    // config auth user id
    config::UserId cfgd_uid;
    // config gdt client
    gdt::GDTClient *cfgd_gdtc;
    // hbeat
    gdt::HeartbeatInfo *hbeat;
    // srvc msg handler
    EVSrvcMsgRX ev_srvcm_rx;
    // srvc msg tx handler
    EVSrvcMsgSent ev_srvcm_tx;
    // GDT port
    int gdt_port;
    // grpc port
    int grpc_port;
    // extra options
    pmap_t dparams;
    // correlation map
    mink_utils::CorrelationMap<GrpcPayload*> cmap;
    // grpc payload pool
    memory::Pool<GrpcPayload, true> cpool;
 
 
};


#endif /* ifndef HTTP_H
 */
