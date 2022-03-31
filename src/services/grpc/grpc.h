/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_GRPC_H
#define MINK_GRPC_H

#include <mink_pkg_config.h>
#ifdef MINK_ENABLE_CONFIGD
#include <mink_config.h>
#include <config_gdt.h>
#endif
#include <atomic.h>
#include <daemon.h>
#include <mink_utils.h>
#include <gdt.h>
#include <gdt_stats.h>
#include <gdt_utils.h>
#include <sstream>
#include "events.h"
#include "gdtgrpc.h"
#include <grpcpp/impl/codegen/status_code_enum.h>
#include <grpcpp/grpcpp.h>
#include <gdt.grpc.pb.h>

// daemon name and description
constexpr const char *DAEMON_TYPE = "grpcd";
constexpr const char *DAEMON_DESCRIPTION =  "MINK gRPC daemon";
constexpr const char *DAEMON_CFG_NODE = "mink grpc";

// types
using rtrd_lst_t = std::vector<std::string *>;
using pmap_t = mink_utils::VariantParamMap<uint32_t>;

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
    ~GrpcdDescriptor() override;

    void process_args(int argc, char **argv) override;
    void print_help() override;
    void init_gdt();
    int init_grpc() const;
    void init();
    void terminate() override;
    void cmap_process_timeout();

    // config daemons
    std::vector<std::string *> rtrd_lst;
    // gdt session
    gdt::GDTSession *gdts = nullptr;
    // gdt client
    gdt::GDTClient *rtrd_gdtc = nullptr;
    // gdt service message manager
    gdt::ServiceMsgManager* gdtsmm = nullptr;
    // idt map
    gdt::ParamIdTypeMap idt_map;
    // GDT stats
    gdt::GDTStatsSession *gdt_stats = nullptr;
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

#ifdef MINK_ENABLE_CONFIGD
    int init_cfg(bool _proc_cfg);
    void process_cfg();

    // cfgd activity flag
    mink::Atomic<uint8_t> cfgd_active;
    // config
    config::Config *config = nullptr;
    // current cfg id
    std::string cfgd_id;
    // config auth user id
    config::UserId cfgd_uid;
    // config gdt client
    gdt::GDTClient *cfgd_gdtc = nullptr;
    // hbeat
    gdt::HeartbeatInfo *hbeat = nullptr;


#endif
};


#endif /* ifndef MINK_GRPC_H */
