/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
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
constexpr const char *DAEMON_TYPE = "sysagentd";
constexpr const char *DAEMON_DESCRIPTION = "MINK System Agent daemon";
constexpr const char *DAEMON_CFG_NODE = "mink sysagent";

// types
using rtrd_lst_t = std::vector<std::string *>;
using pmap_t = mink_utils::VariantParamMap<uint32_t>;

// daemon descriptor definition
class SysagentdDescriptor : public mink::DaemonDescriptor {
public:
    // constructor
    SysagentdDescriptor(const char *_type, const char *_desc);
    // destructor
    ~SysagentdDescriptor() override;

    void process_args(int argc, char **argv) override;
    void print_help() override;
    void init_gdt();
    int init_http();
    int init_cfg(bool _proc_cfg) const;
    void init_plugins(const char *pdir);
    void init();
    void process_cfg();
    void terminate() override;

    // config daemons
    std::vector<std::string *> rtrd_lst;
    // gdt session
    gdt::GDTSession *gdts = nullptr;
    // gdt client
    gdt::GDTClient *rtrd_gdtc = nullptr;
    // gdt service message manager
    gdt::ServiceMsgManager *gdtsmm = nullptr;
    // idt map
    gdt::ParamIdTypeMap idt_map;
    // GDT stats
    gdt::GDTStatsSession *gdt_stats = nullptr;
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
