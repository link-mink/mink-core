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

#include "cfg_events.h"
#include <antlr_utils.h>
#include <atomic.h>
#include <regex>
#include <mink_config.h>
#include <config_gdt.h>
#include <daemon.h>
#include <mink_utils.h>
#include <gdt.h>
#include <gdt_stats.h>
#include <gdt_utils.h>
#include <routingd_events.h>
#include <sstream>

// daemon name and description
#define DAEMON_TYPE "routingd"
#define DAEMON_DESCRIPTION "MINK Routing daemon"
#define DAEMON_CFG_NODE "mink routing"

// routing daemon descriptor definition
class RoutingdDescriptor : public mink::DaemonDescriptor {
public:
    // constructor
    RoutingdDescriptor(const char *_type, const char *_desc);
    // destructor
    ~RoutingdDescriptor();

    void process_args(int argc, char **argv);
    void print_help();
    void init_gdt();
    int init_config(bool _process_config = true);
    void init();
    void process_config();
    void terminate();

    // config daemons
    std::vector<std::string *> config_daemons;
    // gdt session
    gdt::GDTSession *gdts;
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
    // GDT port
    int gdt_port;
    // extra options
    mink_utils::VariantParamMap<uint32_t> extra_params;
    // cfg events
    WRRConfigMod wrr_mod_handler;
};

#endif /* ROUTING_H_ */
