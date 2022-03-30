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

#include <mink_pkg_config.h>
#include <atomic.h>
#include <mink_config.h>
#include <vector>
#ifdef ENABLE_CONFIGD
#include <config_gdt.h>
#endif
#include <daemon.h>
#include <mink_utils.h>
#include <mink_plugin.h>
#include <gdt.h>
#include <gdt_stats.h>
#include <gdt_utils.h>
#include <mink_sqlite.h>
#include <sstream>
#include <nlohmann/json.hpp>
#include "events.h"

// daemon name and description
constexpr const char *DAEMON_TYPE = "sysagentd";
constexpr const char *DAEMON_DESCRIPTION = "MINK System Agent daemon";
constexpr const char *DAEMON_CFG_NODE = "mink sysagent";

// types
using rtrd_lst_t = std::vector<std::string *>;
using pmap_t = mink_utils::VariantParamMap<uint32_t>;
using json = nlohmann::basic_json<nlohmann::ordered_map>;

// plugins configuration
struct PluginsConfig {
    // data buffer
    std::vector<char> buff;
    // deserialised JSON data
    json cfg;
};

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
    void init_plugins(const char *pdir);
    void init();
    void terminate() override;
    // configd
#ifdef ENABLE_CONFIGD
    int init_cfg(bool _proc_cfg) const;

    // config auth user id
    config::UserId cfgd_uid;
    // cfgd activity flag
    mink::Atomic<uint8_t> cfgd_active;
    // config
    config::Config *config = nullptr;
    // current cfg id
    std::string cfgd_id;
    // config gdt client
    gdt::GDTClient *cfgd_gdtc = nullptr;
    // hbeat
    gdt::HeartbeatInfo *hbeat = nullptr;
#endif
    // routing daemons
    std::vector<std::string> rtrd_lst;
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
    // srvc msg handler
    EVSrvcMsgRX ev_srvcm_rx;
    // local IP
    std::string local_ip;
    // plugin dir
    std::string plg_dir;
    // extra options
    pmap_t dparams;
    // plugin manager
    mink_utils::PluginManager plg_mngr;
    // db manager
    mink_db::SqliteManager dbm;
};



#endif /* ifndef SYSAGENT_H */
