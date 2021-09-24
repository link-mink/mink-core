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

#ifndef SYSAGENT_H
#define SYSAGENT_H

#include <atomic.h>
#include <mink_config.h>
#include <config_gdt.h>
#include <daemon.h>
#include <mink_utils.h>
#include <mink_plugin.h>
#include <gdt.h>
#include <gdt_stats.h>
#include <gdt_utils.h>
#include <sstream>
#include "events.h"

// daemon name and description
#define DAEMON_TYPE             "sysagentd"
#define DAEMON_DESCRIPTION      "MINK System Agent daemon"
#define DAEMON_CFG_NODE         "mink sysagent"

// types
typedef std::vector<std::string *> rtrd_lst_t;
typedef mink_utils::VariantParamMap<uint32_t> pmap_t;

// daemon descriptor definition
class SysagentdDescriptor : public mink::DaemonDescriptor {
public:
    // constructor
    SysagentdDescriptor(const char *_type, const char *_desc);
    // destructor
    ~SysagentdDescriptor();

    void process_args(int argc, char **argv);
    void print_help();
    void init_gdt();
    int init_http();
    int init_cfg(bool _proc_cfg);
    void init_plugins(const char *pdir);
    void init();
    void process_cfg();
    void terminate();

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
    // GDT port
    int gdt_port;
    // plugin dir
    std::string plg_dir;
    // extra options
    pmap_t dparams;
    // plugin manager
    mink_utils::PluginManager plg_mngr;
};



#endif /* ifndef SYSAGENT_H */
