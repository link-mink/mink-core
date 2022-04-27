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
#include <sysagent.h>
#include <json_rpc.h>
#include <MQTTClient.h>

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_mqtt.so";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_MQTT_PUBLISH,
    // end of list marker
    -1
};

/*******************/
/* MQTT connection */
/*******************/
class MQTT_conn {
public:
    MQTT_conn() = default;
    ~MQTT_conn() = default;

    int connect(const json &j_conn) {
        // get client id and address
        std::string s_addr = j_conn.at("address").get<std::string>();
        std::string s_c_id = j_conn.at("client_id").get<std::string>();

        // mqtt connection setup
        MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
        MQTTClient_create(&client_,
                          s_addr.c_str(),
                          s_c_id.c_str(),
                          MQTTCLIENT_PERSISTENCE_NONE,
                          nullptr);
        conn_opts.keepAliveInterval = 20;
        conn_opts.cleansession = 1;

        // connect
        if (MQTTClient_connect(client_, &conn_opts) != MQTTCLIENT_SUCCESS) {
            throw std::runtime_error("MQTT connection error");
        }

        // ok
        return 0;
    }

    int publish(const std::string &d, const std::string &t) {
        // setup mqtt payload
        MQTTClient_message pubmsg = MQTTClient_message_initializer;
        MQTTClient_deliveryToken token;
        pubmsg.payload = (void *)d.data();
        pubmsg.payloadlen = d.size();
        pubmsg.qos = 1;
        pubmsg.retained = 0;
        // publish
        MQTTClient_publishMessage(client_, t.c_str(), &pubmsg, &token);
        // wait for ACK
        int rc = MQTTClient_waitForCompletion(client_, token, 1000);
        // delivered
        if (rc == MQTTCLIENT_SUCCESS) return 0;
        // not delivered
        return 1;
    }

private:
    MQTTClient client_;
};

/***************************/
/* MQTT connection manager */
/***************************/
class MQTT_mngr {
public:
    MQTT_mngr() = default;
    ~MQTT_mngr() = default;
    MQTT_mngr(const MQTT_mngr &o) = delete;
    MQTT_mngr &operator=(const MQTT_mngr &o) = delete;

    MQTT_conn *add_conn(const json &j_conn) {
        std::string s_c = j_conn.at("address").get<std::string>();
        // connection label
        std::string s_lbl = j_conn.at("name").get<std::string>();
        // label should not be present
        if (conns_.find(s_lbl) != conns_.cend()) {
            throw std::invalid_argument("connection label should be unique");
        }
        // new TCP connection
        MQTT_conn *c = new MQTT_conn();
        // add to list
        return conns_.emplace(std::make_pair(s_lbl, c)).first->second;
    }

    void del_conn(const std::string &n) {
        auto it = conns_.find(n);
        if (it != conns_.end()) {
            delete it->second;
            conns_.erase(it);
        }
    }

    MQTT_conn *get_conn(const std::string &n) {
        auto it = conns_.find(n);
        if (it == conns_.end())
            return nullptr;
        else
            return it->second;
    }

private:
    std::map<std::string, MQTT_conn *> conns_;
};

/***************/
/* Global vars */
/***************/
MQTT_mngr mqtt_mngr;

/******************/
/* Get PLG config */
/******************/
json *plg_get_config(){
    // cfg pointer
    PluginsConfig *pcfg = nullptr;
    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // get config
    try {
        pcfg = static_cast<PluginsConfig *>(dd->dparams.get_pval<void *>(4));

    } catch (std::exception &e) {
        throw std::invalid_argument("configuration file missing");
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        throw std::invalid_argument("configuration missing");
    }

    return &*it;
}

/********************************/
/* Process static configuration */
/********************************/
static int process_cfg(mink_utils::PluginManager *pm) {
    json *pcfg = nullptr;
    // get config
    try {
        pcfg = plg_get_config();

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_mqtt: [%s]",
                                  e.what());
        return -1;
    }

    // process
    try {
        // get list of connections
        auto j_c_lst = pcfg->at("connections");
        // loop backends
        for(auto it_c = j_c_lst.begin(); it_c != j_c_lst.end(); ++ it_c) {
            // sanity check
            if(!it_c->is_object()){
                throw std::invalid_argument("connection != object");
            }
            // add connection
            MQTT_conn *c = mqtt_mngr.add_conn(*it_c);
            // connect
            if (c)
                c->connect(*it_c);

        }

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_mqtt: [%s]",
                                  e.what());
        return -3;
    }

    return 0;
}


/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    // process cfg
    if (process_cfg(pm)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_modbus: [cannot process plugin configuration]");
        return 1;
    }

    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}


/*************************************/
/* local CMD_MQTT_PUBLISH (standard) */
/*************************************/
static void impl_mqtt_publish(mink_utils::Plugin_data_std *data) {
    // sanity check
    if(!data || data->size() != 3){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                 "plg_mqtt: [CMD_MQTT_PUBLISH invalid data]");
        return;
    }

    try {
        // get connection
        MQTT_conn *c = mqtt_mngr.get_conn(data->at(0).cbegin()->second);
        if (!c) return;

        // publish
        c->publish(data->at(2).cbegin()->second,
                   data->at(1).cbegin()->second);

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_mqtt: [%s]",
                                  e.what());
    }


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
        // TODO
        return 0;
    }

    // plugin2plugin local interface (custom)
    if(p_id.type() == mink_utils::PLG_DT_SPECIFIC){
        return 0;
    }

    // plugin2plugin local interface (standard)
    if (p_id.type() == mink_utils::PLG_DT_STANDARD) {
        // plugin in/out data
        auto *plg_d = static_cast<mink_utils::Plugin_data_std *>(p_id.data());
        // check command id
        switch(cmd_id){
            case gdt_grpc::CMD_MQTT_PUBLISH:
                impl_mqtt_publish(plg_d);
                break;

            default:
                break;
        }
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


