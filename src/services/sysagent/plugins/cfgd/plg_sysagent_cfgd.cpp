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
#include "mink_config.h"
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_pkg_config.h>
#include <utility>
#include <vector>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <sysagent.h>

/***********/
/* Aliases */
/***********/
using rule_d = std::pair<std::string, std::string>;
using plg2plg_data = std::vector<std::string>;

/*************************/
/* Global PLugin Manager */
/*************************/
mink_utils::PluginManager *PM = nullptr;

#ifdef MINK_ENABLE_CONFIGD
/********************************/
/* "firewall" cfg event handler */
/********************************/
class ev_cfg_mod_fwd : public config::CfgNtfCallback {
public:
    void run(config::ConfigItem *cfg,
             unsigned int mod_index,
             unsigned int mod_count){

        // rules map
        std::vector<rule_d> rls_lst;
        // "rich rule" string
        std::string rich_rule("rule ");
        // get first modified node (cfg is a "fake" root node) and
        // find the "real" root node
        auto *fw_r = MCFG_ROOT("firewall");
        // zones
        auto *z_lst = (*fw_r)("zones");
        // process zones
        MCFG_FOREACH(z_lst, {
            // get "rules" node for current zone
            auto rules = (*z_lst_C)("rules");
            // process rules for current zone
            MCFG_FOREACH(rules, {
                /*****************/
                /* "family" node */
                /*****************/
                auto r_family = (*rules_C)("family");
                // add to "rule" string if set
                if (!r_family->value.empty())
                    rich_rule += "family=\"" + r_family->value + "\" ";

                /*****************/
                /* "source" node */
                /*****************/
                auto r_src = (*rules_C)("source");
                auto r_src_addr = (*r_src)("address");
                auto r_src_mac = (*r_src)("mac");
                auto r_src_ipset = (*r_src)("ipset");
                // check if used
                if (!r_src_addr->value.empty() ||
                    !r_src_mac->value.empty() ||
                    !r_src_ipset->value.empty()) {

                    // add "source" prefix
                    rich_rule += "source ";
                    // add "address" to "rule" string if set
                    if (!r_src_addr->value.empty())
                        rich_rule += "address=\"" + r_src_addr->value + "\" ";
                    // add "mac" to "rule" string if set
                    if (!r_src_mac->value.empty())
                        rich_rule += "mac=\"" + r_src_mac->value + "\" ";
                    // add "ipset" to "rule" string if set
                    if (!r_src_ipset->value.empty())
                        rich_rule += "ipset=\"" + r_src_ipset->value + "\" ";
                }

                /**********************/
                /* "destination" node */
                /**********************/
                auto r_dst = (*rules_C)("destination");
                auto r_dst_addr = (*r_dst)("address");
                auto r_dst_mac = (*r_dst)("mac");
                auto r_dst_ipset = (*r_dst)("ipset");
                // check if used
                if (!r_dst_addr->value.empty() ||
                    !r_dst_mac->value.empty() ||
                    !r_dst_ipset->value.empty()) {

                    // add "destination" prefix
                    rich_rule += "destination ";
                    // add "address" to "rule" string if set
                    if (!r_dst_addr->value.empty())
                        rich_rule += "address=\"" + r_dst_addr->value + "\" ";
                    // add "mac" to "rule" string if set
                    if (!r_dst_mac->value.empty())
                        rich_rule += "mac=\"" + r_dst_mac->value + "\" ";
                    // add "ipset" to "rule" string if set
                    if (!r_dst_ipset->value.empty())
                        rich_rule += "ipset=\"" + r_dst_ipset->value + "\" ";
                }

                /******************/
                /* "element" node */
                /******************/
                auto e =  (*rules_C)("element");
                auto e_srvc = (*e)("service");
                auto e_port_port = (*e)("port port");
                auto e_port_proto = (*e)("port protocol");
                auto e_proto = (*e)("protocol");
                auto e_icmp_block = (*e)("icmp-block");
                auto e_masquerade = (*e)("masquerade");
                auto e_fwd_port_port = (*e)("forward-port port");
                auto e_fwd_port_proto = (*e)("forward-port protocol");
                auto e_fwd_port_to_port = (*e)("forward-port to-port");
                auto e_fwd_port_to_addr = (*e)("forward-port to-addr");
                auto e_src_port_port = (*e)("source-port port");
                auto e_src_port_proto = (*e)("source-port protocol");
                // add "service" to "rule" string if set
                if (!e_srvc->value.empty())
                    rich_rule += "service name=\"" + e_srvc->value + "\" ";
                // add "port" to "rule" string if set
                if (!e_port_port->value.empty() &&
                    !e_port_proto->value.empty()) {

                    rich_rule += "port port=\"" + e_port_port->value + "\" ";
                    rich_rule += "protocol=\"" + e_port_proto->value + "\" ";
                }
                // add "protocol" to "rule" string if set
                if (!e_proto->value.empty())
                    rich_rule += "protocol value=\"" + e_proto->value + "\" ";
                // add "icmp-block" to "rule" string if set
                if (!e_icmp_block->value.empty())
                    rich_rule += "icmp-block name=\"" + e_icmp_block->value + "\" ";
                // add "masquerade" to "rule" string if set
                if (!e_masquerade->value.empty())
                    rich_rule += "masquerade ";
                // add "forward-port" to "rule" string if set
                if (!e_fwd_port_port->value.empty() &&
                    !e_fwd_port_proto->value.empty() &&
                    !e_fwd_port_to_port->value.empty() &&
                    !e_fwd_port_to_addr->value.empty()) {

                    rich_rule += "forward-port port=\"" + e_fwd_port_port->value + "\" ";
                    rich_rule += "protocol=\"" + e_fwd_port_proto->value + "\" ";
                    rich_rule += "to-port=\"" + e_fwd_port_to_port->value + "\" ";
                    rich_rule += "to-addr=\"" + e_fwd_port_to_addr->value + "\" ";
                }
                // add "source-port" to "rule" string if set
                if (!e_src_port_port->value.empty() &&
                    !e_src_port_proto->value.empty()) {

                    rich_rule += "source-port port=\"" + e_src_port_port->value + "\" ";
                    rich_rule += "protocol=\"" + e_src_port_proto->value + "\" ";
                }

                /**************/
                /* "log" node */
                /**************/
                auto l = (*rules_C)("log");
                auto l_prfx = (*l)("prefix");
                auto l_lvl = (*l)("level");
                auto l_lmt = (*l)("limit");
                // enable "log"
                if (!l_lvl->value.empty()){
                    rich_rule += "log level=\"" + l_lvl->value + "\" ";
                    // add "prefix" if set
                    if (!l_prfx->value.empty())
                        rich_rule += "prefix=\"" + l_prfx->value + "\" ";
                    // add "limit" if set
                    if (!l_lmt->value.empty())
                        rich_rule += "limit value=\"" + l_lmt->value + "\" ";
                }
                /****************/
                /* "audit" node */
                /****************/
                auto a = (*rules_C)("audit");
                auto a_lmt = (*a)("limit");
                // enable "log"
                if (!a_lmt->value.empty()){
                    rich_rule += "audit limit level=\"" + a_lmt->value + "\" ";
                }
                /*****************/
                /* "action" node */
                /****************/
                auto act = (*rules_C)("action");
                if (!act->value.empty())
                    rich_rule += act->value;

                // add rule to rules list
                rls_lst.push_back(std::make_pair(z_lst_C->name, rich_rule));
            });

        });
        // reload firewalld rules
        PM->run(gdt_grpc::CMD_SYSD_FWLD_RELOAD,
                mink_utils::PluginInputData(mink_utils::PLG_DT_SPECIFIC, nullptr),
                true);

        // add rules
        std::all_of(rls_lst.cbegin(), rls_lst.cend(), [](const rule_d &r) {
            // add zone and rule data
            plg2plg_data rd;
            rd.push_back(r.first);
            rd.push_back(r.second);
            // add rule
            PM->run(gdt_grpc::CMD_SYSD_FWLD_ADD_RICH_RULE,
                    mink_utils::PluginInputData(mink_utils::PLG_DT_SPECIFIC, &rd),
                    true);

            return true;
        });
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

        // TODO
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
                              "CFG node 'firewall' does not exist!");
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
                              "CFG node 'network' does not exist!");
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
    // save plugin manager pointer
    PM = pm;
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


