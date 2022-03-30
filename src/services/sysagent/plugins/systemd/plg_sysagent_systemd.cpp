/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_pkg_config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <json_rpc.h>
#include <systemd/sd-bus.h>

/***********/
/* Aliases */
/***********/
using Jrpc = json_rpc::JsonRpc;

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_systemd.so";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_SYSD_FWLD_GET_ZONES,
    gdt_grpc::CMD_SYSD_FWLD_GET_RICH_RULES,
    gdt_grpc::CMD_SYSD_FWLD_ADD_RICH_RULE,
    gdt_grpc::CMD_SYSD_FWLD_DEL_RICH_RULE,
    // end of list marker
    -1
};

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/**************************************/
/* local CMD_SYSD_FWLD_GET_RICH_RULES */
/**************************************/
static void impl_local_fwd_get_rich_rules(json_rpc::JsonRpc &jrpc, json *j_d){
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *m = nullptr;
    sd_bus *bus = nullptr;
    std::string z;

    // process params
    jrpc.process_params([&z](int id, const std::string &s) {
        if (id == gdt_grpc::PT_SYSD_FWLD_ZONE) {
            z = s;
        }
        return true;
    });

    // connect
    int r = sd_bus_open_system(&bus);
    if (r < 0) {
        throw std::invalid_argument("cannot connect to sdbus");
    }
    // call method
    r = sd_bus_call_method(bus,
                           "org.fedoraproject.FirewallD1",          // service to contact
                            "/org/fedoraproject/FirewallD1",        // object path
                            "org.fedoraproject.FirewallD1.zone",    // interface name
                            "getRichRules",                         // method name
                            &err,                                   // object to return error in
                            &m,                                     // return message on success
                            "s",                                    // input signature
                            z.data());                              // zone

    // err
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'getRichRules'");
    }

    // result
    const char *res = nullptr;
    // Parse the response message
    r = sd_bus_message_enter_container(m, 'a', "s");
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'getRichRules'");
    }

    // read zones
    while ((r = sd_bus_message_read(m, "s", &res) > 0)) {
        (*j_d)[Jrpc::RESULT_].push_back(res);
    }

    // free
    sd_bus_error_free(&err);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);
}

/*************************************/
/* local CMD_SYSD_FWLD_ADD_RICH_RULE */
/*************************************/
static void impl_local_fwd_add_rich_rule(json_rpc::JsonRpc &jrpc, json *j_d){
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *m = nullptr;
    sd_bus *bus = nullptr;
    std::string z;
    std::string rule;
    int32_t t = 0;

    // process params
    jrpc.process_params([&z, &rule](int id, const std::string &s) {
        // zone
        if (id == gdt_grpc::PT_SYSD_FWLD_ZONE) {
            z = s;

        // rule
        } else if (id == gdt_grpc::PT_SYSD_FWLD_RULE) {
            rule = s;
        }
        return true;
    });

    // connect
    int r = sd_bus_open_system(&bus);
    if (r < 0) {
        throw std::invalid_argument("cannot connect to sdbus");
    }
    // call method
    r = sd_bus_call_method(bus,
                           "org.fedoraproject.FirewallD1",          // service to contact
                            "/org/fedoraproject/FirewallD1",        // object path
                            "org.fedoraproject.FirewallD1.zone",    // interface name
                            "addRichRule",                          // method name
                            &err,                                   // object to return error in
                            &m,                                     // return message on success
                            "ssi",                                  // input signature
                            z.data(),                               // zone
                            rule.data(),                            // rule
                            t);                                     // timeout

    // err
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'addRichRule'");
    }

    // result
    const char *res = nullptr;
    // Parse the response message
    r = sd_bus_message_read(m, "s", &res);
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'addRichRule'");
    }
    (*j_d)[Jrpc::RESULT_].push_back(res);

    // free
    sd_bus_error_free(&err);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);
}

/*************************************/
/* local CMD_SYSD_FWLD_DEL_RICH_RULE */
/*************************************/
static void impl_local_fwd_del_rich_rule(json_rpc::JsonRpc &jrpc, json *j_d){
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *m = nullptr;
    sd_bus *bus = nullptr;
    std::string z;
    std::string rule;
    int32_t t = 0;

    // process params
    jrpc.process_params([&z, &rule](int id, const std::string &s) {
        // zone
        if (id == gdt_grpc::PT_SYSD_FWLD_ZONE) {
            z = s;

        // rule
        } else if (id == gdt_grpc::PT_SYSD_FWLD_RULE) {
            rule = s;
        }
        return true;
    });

    // connect
    int r = sd_bus_open_system(&bus);
    if (r < 0) {
        throw std::invalid_argument("cannot connect to sdbus");
    }
    // call method
    r = sd_bus_call_method(bus,
                           "org.fedoraproject.FirewallD1",          // service to contact
                            "/org/fedoraproject/FirewallD1",        // object path
                            "org.fedoraproject.FirewallD1.zone",    // interface name
                            "removeRichRule",                       // method name
                            &err,                                   // object to return error in
                            &m,                                     // return message on success
                            "ss",                                   // input signature
                            z.data(),                               // zone
                            rule.data());                           // rule

    // err
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'removeRichRule'");
    }

    // result
    const char *res = nullptr;
    // Parse the response message
    r = sd_bus_message_read(m, "s", &res);
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'removeRichRule'");
    }
    (*j_d)[Jrpc::RESULT_].push_back(res);

    // free
    sd_bus_error_free(&err);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);
}



/*********************************/
/* local CMD_SYSD_FWLD_GET_ZONES */
/*********************************/
static void impl_local_fwd_get_zones(json_rpc::JsonRpc &jrpc, json *j_d){
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *m = nullptr;
    sd_bus *bus = nullptr;

    // connect
    int r = sd_bus_open_system(&bus);
    if (r < 0) {
        throw std::invalid_argument("cannot connect to sdbus");
    }
    // call method
    r = sd_bus_call_method(bus,
                           "org.fedoraproject.FirewallD1",          // service to contact
                            "/org/fedoraproject/FirewallD1",        // object path
                            "org.fedoraproject.FirewallD1.zone",    // interface name
                            "getZones",                             // method name
                            &err,                                   // object to return error in
                            &m,                                     // return message on success
                            nullptr);                               // input signature

    // err
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'getZones'");
    }

    // result
    const char *res = nullptr;
    // Parse the response message
    r = sd_bus_message_enter_container(m, 'a', "s");
    if (r < 0) {
        sd_bus_error_free(&err);
        sd_bus_message_unref(m);
        sd_bus_unref(bus);
        throw std::invalid_argument("failed to issue method call 'getZones'");
    }

    // read zones
    while ((r = sd_bus_message_read(m, "s", &res) > 0)) {
        (*j_d)[Jrpc::RESULT_].push_back(res);
    }

    // free
    sd_bus_error_free(&err);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);
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
        json *j_d = static_cast<json *>(p_id.data());
        int id = -1;
        int cmd_id = -1;
        try {
            // create json rpc parser
            Jrpc jrpc(*j_d);
            // verify
            jrpc.verify(true);
            // get method
            cmd_id = jrpc.get_method_id();
            // get JSON RPC id
            id = jrpc.get_id();
            // check command id
            switch (cmd_id) {
                case gdt_grpc::CMD_SYSD_FWLD_GET_ZONES:
                    impl_local_fwd_get_zones(jrpc, j_d);
                    break;

                case gdt_grpc::CMD_SYSD_FWLD_GET_RICH_RULES:
                    impl_local_fwd_get_rich_rules(jrpc, j_d);
                    break;

                case gdt_grpc::CMD_SYSD_FWLD_ADD_RICH_RULE:
                    impl_local_fwd_add_rich_rule(jrpc, j_d);
                    break;

                case gdt_grpc::CMD_SYSD_FWLD_DEL_RICH_RULE:
                    impl_local_fwd_del_rich_rule(jrpc, j_d);
                    break;

                default:
                    break;
            }

        } catch (std::exception &e) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_systemd: [%s]",
                                      e.what());
            auto j_err = Jrpc::gen_err(id, e.what());
            (*j_d)[Jrpc::ERROR_] = j_err[Jrpc::ERROR_];
        }

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


