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
#include <vector>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <sysagent.h>
#include <json_rpc.h>
#include <MQTTAsync.h>
#include <boost/signals2.hpp>

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

/***********/
/* SIGNALS */
/***********/
const std::string SIG_MQTT_RX = "mqtt:RX";

/*******************/
/* MQTT connection */
/*******************/
class MQTT_conn {
public:
    MQTT_conn(mink_utils::PluginManager *pm) : pm_(pm) {}
    ~MQTT_conn() = default;

    // connect to an MQTT server
    int connect(const json &j_conn) {
        // get client id and address
        std::string s_addr = j_conn.at("address").get<std::string>();
        std::string s_c_id = j_conn.at("client_id").get<std::string>();
        // username and password
        std::string s_usr = j_conn.at("username").get<std::string>();
        std::string s_pwd = j_conn.at("password").get<std::string>();

        // mqtt connection setup
        MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
        MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
        int rc = MQTTAsync_create(&client_,
                                  s_addr.c_str(),
                                  s_c_id.c_str(),
                                  MQTTCLIENT_PERSISTENCE_NONE, nullptr);
        if (rc != MQTTASYNC_SUCCESS) {
            throw std::runtime_error("cannot create MQTT client");
        }

        // set callbacks (RX)
        if (MQTTAsync_setCallbacks(client_,
                                   this,
                                   nullptr,
                                   on_rx,
                                   nullptr) != MQTTASYNC_SUCCESS) {
            throw std::runtime_error("cannot set MQTT client callbacks");
        }
        // connection options
        conn_opts.keepAliveInterval = 20;
        conn_opts.cleansession = 1;
        conn_opts.onSuccess = on_connect;;
        conn_opts.onFailure = nullptr;
        conn_opts.automaticReconnect = 1;
        conn_opts.context = this;
        conn_opts.username = s_usr.c_str();
        conn_opts.password = s_pwd.c_str();
        conn_opts.ssl = &ssl_opts;

        // connect
        if (MQTTAsync_connect(client_, &conn_opts) != MQTTASYNC_SUCCESS) {
            throw std::runtime_error("MQTT connection error");
        }

        // ok
        return 0;
    }

    // publish topic data
    int publish(const std::string &d, const std::string &t) {
        // setup mqtt payload
        MQTTAsync_message pubmsg = MQTTAsync_message_initializer;
        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
        opts.context = this;
        pubmsg.payload = (void *)d.data();
        pubmsg.payloadlen = d.size();
        pubmsg.qos = 1;
        pubmsg.retained = 0;
        // send
        if (MQTTAsync_sendMessage(client_,
                                  t.c_str(),
                                  &pubmsg,
                                  &opts) != MQTTASYNC_SUCCESS) {
            // error
            return 1;
        }
        // ok
        return 0;
    }

    // subscribe to a topic
    int subscribe(const std::string &t) {
        MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
        if (MQTTAsync_subscribe(client_,
                                t.c_str(),
                                1,
                                &opts) != MQTTASYNC_SUCCESS) {
            // error
            return 1;
        }
        // ok
        return 0;
    }

    // add to a list of subscribed topics
    void add_topic(const std::string &t) {
        topics_.push_back(t);
    }

    // get topics this connection is subscribed to
    std::vector<std::string> get_topics() {
        return topics_;
    }

private:
    // connection established
    static void on_connect(void *context, MQTTAsync_successData *response) {
        // get context
        MQTT_conn *conn = static_cast<MQTT_conn *>(context);
        // get topics
        auto lst = conn->get_topics();
        // subscribe to topics
        for (auto it = lst.cbegin(); it != lst.cend(); ++it) {
            conn->subscribe(*it);
        }
    }

    // topic data received
    static int on_rx(void *ctx, char *t, int t_sz, MQTTAsync_message *msg) {
        // get context
        MQTT_conn *conn = static_cast<MQTT_conn *>(ctx);
        // signal data
        std::string s(static_cast<char *>(msg->payload), msg->payloadlen);
        // process signal
        mink_utils::Plugin_data_std e_d;
        e_d.push_back({{"mqtt_topic", t}, {"mqtt_payload", s}});
        conn->pm_->process_signal(SIG_MQTT_RX, e_d);
        // cleanup
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(t);
        return 1;
    }

    // private members
    MQTTAsync client_;
    mink_utils::PluginManager *pm_;
    std::vector<std::string> topics_;
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

    MQTT_conn *add_conn(const json &j_conn, mink_utils::PluginManager *pm) {
        std::string s_c = j_conn.at("address").get<std::string>();
        // connection label
        std::string s_lbl = j_conn.at("name").get<std::string>();
        // label should not be present
        if (conns_.find(s_lbl) != conns_.cend()) {
            throw std::invalid_argument("connection label should be unique");
        }
        // new TCP connection
        MQTT_conn *c = new MQTT_conn(pm);
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
        for(auto it_c = j_c_lst.begin(); it_c != j_c_lst.end(); ++it_c) {
            // sanity check
            if(!it_c->is_object()){
                throw std::invalid_argument("connection != object");
            }
            // add connection
            MQTT_conn *c = mqtt_mngr.add_conn(*it_c, pm);
            if (!c)
                continue;

            // subscribe to topics (if defined)
            if (it_c->find("subscriptions") != it_c->cend()) {
                // topic list
                auto j_t_lst = it_c->at("subscriptions");
                for (auto it_t = j_t_lst.begin(); it_t != j_t_lst.end(); ++it_t) {
                    // subscribe to topic
                    c->add_topic(*it_t);
                }
            }

            mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                      "plg_mqtt: adding connection [%s]",
                                      it_c->at("name").get<std::string>().c_str());
            // connect
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
                                  "plg_mqtt: [cannot process plugin configuration]");
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


