/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef ROUTING_H_
#define ROUTING_H_

#include <mink_pkg_config.h>
#include "cfg_events.h"
#ifdef ENABLE_CONFIGD
#include <mink_config.h>
#include <config_gdt.h>
#endif
#include <atomic.h>
#include <regex>
#include <daemon.h>
#include <mink_utils.h>
#include <gdt.h>
#include <gdt_stats.h>
#include <gdt_utils.h>
#include <routingd_events.h>
#include <sstream>

// daemon name and description
constexpr const char *DAEMON_TYPE = "routingd";
constexpr const char *DAEMON_DESCRIPTION = "MINK Routing daemon";
constexpr const char *DAEMON_CFG_NODE  = "mink routing";

// routing daemon descriptor definition
class RoutingdDescriptor : public mink::DaemonDescriptor {
public:
    // constructor
    RoutingdDescriptor(const char *_type, const char *_desc);
    RoutingdDescriptor(const RoutingdDescriptor &o) = delete;
    RoutingdDescriptor &operator=(const RoutingdDescriptor &o) = delete;
    // destructor
    ~RoutingdDescriptor() override;

    void process_args(int argc, char **argv) override;
    void print_help() override;
    void init_gdt();
    void init();
    void terminate() override;

    // gdt session
    gdt::GDTSession *gdts;
    // GDT stats
    gdt::GDTStatsSession *gdt_stats;
    // GDT port
    int gdt_port;
    // local IP
    std::string local_ip;
    // if monitor
    bool if_monitor = false;
    // extra options
    mink_utils::VariantParamMap<uint32_t> extra_params;

#ifdef ENABLE_CONFIGD
    int init_config(bool _process_config = true);
    void process_config();

    // config daemons
    std::vector<std::string *> config_daemons;
    // cfgd activity flag
    mink::Atomic<uint8_t> cfgd_active;
    // config
    config::Config *config = nullptr;
    // current cfg id
    unsigned char cfgd_id[16];
    // config auth user id
    config::UserId cfgd_uid;
    // config gdt client
    gdt::GDTClient *cfgd_gdtc = nullptr;
    // hbeat
    gdt::HeartbeatInfo *hbeat = nullptr;
    // cfg events
    WRRConfigMod wrr_mod_handler;
#endif
};

#endif /* ROUTING_H_ */
