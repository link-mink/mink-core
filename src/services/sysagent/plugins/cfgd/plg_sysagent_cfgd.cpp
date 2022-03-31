/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "daemon.h"
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_pkg_config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <sysagent.h>

#ifdef MINK_ENABLE_CONFIGD
/********************************/
/* "firewall" cfg event handler */
/********************************/
class ev_cfg_mod_fwd : public config::CfgNtfCallback {
public:
    void run(config::ConfigItem *cfg,
             unsigned int mod_index,
             unsigned int mod_count){

        config::ConfigItem *r = cfg->children[0];
        //config::Config::print_config_tree(r, 0, false);
    }
};

/*******************************/
/* "network" cfg event handler */
/*******************************/
class ev_cfg_mod_net : public config::CfgNtfCallback {
public:
    void run(config::ConfigItem *cfg,
             unsigned int mod_index,
             unsigned int mod_count){

        config::ConfigItem *r = cfg->children[0];
        //config::Config::print_config_tree(r, 0, false);
    }
};

/***************/
/* Global vars */
/***************/
ev_cfg_mod_fwd cfgm_fwd;
ev_cfg_mod_net cfgm_net;

/**********************************/
/* init "firewall" config handler */
/**********************************/
void init_cfg_fwd(config::Config *cfg){
    // get node
    config::ConfigItem* r = (*cfg->get_definition_root())("firewall");

    // check if configuration exists
    if (!r){
        // configuration found
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                              "Configuration node does not exist!");
        return;
    }

    // setup config on chage events
    r->set_on_change_handler(&cfgm_fwd, true);
}

/*********************************/
/* init "network" config handler */
/*********************************/
void init_cfg_net(config::Config *cfg){
    // get node
    config::ConfigItem* r = (*cfg->get_definition_root())("network");

    // check if configuration exists
    if (!r){
        // configuration found
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                              "Configuration node does not exist!");
        return;
    }

    // setup config on chage events
    r->set_on_change_handler(&cfgm_net, true);
}
#endif


/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    // end of list marker
    -1
};

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
#ifdef MINK_ENABLE_CONFIGD
    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // cfgd id buffer
    char cfgd_id[16];
    memset(cfgd_id, 0, sizeof(cfgd_id));

    /************************************/
    /* notification request: "firewall" */
    /************************************/
    int r = config::notification_request(dd->config,
                                         dd->cfgd_gdtc,
                                         "firewall",
                                         nullptr,
                                         cfgd_id,
                                         &dd->cfgd_uid,
                                         nullptr);
    if(r){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "Error while requesting 'firewall' "
                                  "notifications from CFGD [%s]",
                                  cfgd_id);
        return 1;
    }
    mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                              "Registering notification request for node "
                              "path [firewall] with config daemon [%s]",
                              cfgd_id);
    init_cfg_fwd(dd->config);

    /***********************************/
    /* notification request: "network" */
    /***********************************/
    r = config::notification_request(dd->config,
                                     dd->cfgd_gdtc,
                                     "network",
                                     nullptr,
                                     cfgd_id,
                                     &dd->cfgd_uid,
                                     nullptr);
    if(r){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "Error while requesting 'network' "
                                  "notifications from CFGD [%s]",
                                  cfgd_id);
        return 1;

    }
    mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                              "Registering notification request for node "
                              "path [network] with config daemon [%s]",
                              cfgd_id);
    init_cfg_net(dd->config);

#endif
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/*************************/
/* local command handler */
/*************************/
extern "C" int run_local(mink_utils::PluginManager *pm,
                         mink_utils::PluginDescriptor *pd,
                         int cmd_id,
                         mink_utils::PluginInputData &p_id){
    // sanity/type check
    if (!p_id.data())
        return -1;

    // UNIX socket local interface
    if(p_id.type() == mink_utils::PLG_DT_JSON_RPC){
        return 0;
    }

    // plugin2plugin local interface
    if(p_id.type() == mink_utils::PLG_DT_SPECIFIC){

        return 0;
    }

    // unknown interface
    return -1;
}

/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm,
                   mink_utils::PluginDescriptor *pd,
                   int cmd_id,
                   mink_utils::PluginInputData &p_id){
    // sanity/type check
    if (!(p_id.data() && p_id.type() == mink_utils::PLG_DT_GDT))
        return 1;

    return 0;
}


