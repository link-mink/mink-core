/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <exception>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_pkg_config.h>
#include <stdexcept>
#include <utility>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <sysagent.h>
#include <json_rpc.h>
#include <thread>
#include <chrono>
#include <regex>
#include <modbus/modbus.h>

/***********/
/* Aliases */
/***********/
using Jrpc = json_rpc::JsonRpc;

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_modbus.so";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_MODBUS_WRITE_BIT,
    gdt_grpc::CMD_MODBUS_READ_BITS,
    // end of list marker
    -1
};

/**************************/
/* MODBUS connection type */
/**************************/
enum Modbus_conn_t {
    MCT_UNKNOWN = 0,
    MCT_TCP     = 1,
    MCT_TCP_PI  = 2,
    MCT_RTU     = 3
};

/********************************/
/* MODBUS connection base class */
/********************************/
class Modbus_conn {
public:
    Modbus_conn() = default;
    virtual ~Modbus_conn() = default;

    virtual int connect(const json &j_conn) = 0;
    virtual int write_bit(int addr, int s) = 0;
    virtual std::vector<uint8_t> read_bits(int addr, int nb) = 0;

protected:
    Modbus_conn_t type_;
    modbus_t *ctx_;
};

/*************************/
/* MODBUS TCP connection */
/*************************/
class Modbus_conn_tcp : public Modbus_conn {
public:
    Modbus_conn_tcp() {
        type_ = MCT_TCP;
        ctx_ = nullptr;
    }
    ~Modbus_conn_tcp() {
        if (ctx_) {
            modbus_close(ctx_);
            modbus_free(ctx_);
        }
    }


    int connect(const json &j_conn) {
        // get backend type and args
        std::string s_c = j_conn.at("connection").get<std::string>();
        // check format
        auto sz = s_c.find_first_of(":");
        if ((sz == std::string::npos) || (sz >= s_c.size() - 1)) {
            throw std::invalid_argument("invalid parameter type");
        }
        // trim backend type
        s_c = s_c.substr(sz + 1);
        // ip and port
        std::regex r("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
        std::smatch rgxg;
        if (!std::regex_match(s_c, rgxg, r)) {
            throw std::invalid_argument("invalid backend arguments");
        }
        // create context
        ctx_ = modbus_new_tcp(rgxg[1].str().c_str(),
                              std::stoi(rgxg[2].str().c_str()));
        //modbus_set_debug(ctx, 1);

        // set error recovery
        int rm = MODBUS_ERROR_RECOVERY_LINK | MODBUS_ERROR_RECOVERY_PROTOCOL;
        modbus_set_error_recovery(ctx_,
                                  static_cast<modbus_error_recovery_mode>(rm));

        // get timeouts
        uint32_t old_response_to_sec;
        uint32_t old_response_to_usec;
        modbus_get_response_timeout(ctx_,
                                    &old_response_to_sec,
                                    &old_response_to_usec);

        // connect
        if (modbus_connect(ctx_) == -1) {
            modbus_free(ctx_);
            ctx_ = nullptr;
            throw std::runtime_error(modbus_strerror(errno));
        }

        return 0;
    }

    int write_bit(int addr, int s) {
        return !modbus_write_bit(ctx_, addr, s);
    }

    std::vector<uint8_t> read_bits(int addr, int nb) {
        // result buffer
        std::vector<uint8_t> res;
        res.resize(nb);

        // read bits
        if (modbus_read_bits(ctx_, addr, nb, res.data()) != nb) {
            throw std::runtime_error(modbus_strerror(errno));
        }

        return res;
    }
};


/*****************************/
/* MODBUS connection manager */
/*****************************/
class Modbus_mngr {
public:
    Modbus_mngr() = default;
    ~Modbus_mngr() = default;
    Modbus_mngr(const Modbus_mngr &o) = delete;
    Modbus_mngr &operator=(const Modbus_mngr &o) = delete;

    Modbus_conn *add_conn(const json &j_conn) {
        std::string s_c = j_conn.at("connection").get<std::string>();
        // connection label
        std::string s_lbl = j_conn.at("name").get<std::string>();
        // label should not be present
        if (conns_.find(s_lbl) != conns_.cend()) {
            throw std::invalid_argument("connection label should be unique");
        }

        // check format
        auto sz = s_c.find_first_of(":");
        if ((sz == std::string::npos) || (sz >= s_c.size() - 1)) {
            throw std::invalid_argument("invalid parameter type");
        }
        // get backend type
        auto s_bcknd = s_c.substr(0, sz);

        // tcp
        if (s_bcknd == "tcp") {
            // new TCP connection
            Modbus_conn *m_tcp = new Modbus_conn_tcp();
            // add to list
            return conns_.emplace(std::make_pair(s_lbl, m_tcp)).first->second;
        }
        return nullptr;
    }

    void del_conn(const std::string &n) {
        auto it = conns_.find(n);
        if (it != conns_.end()) {
            delete it->second;
            conns_.erase(it);
        }
    }

    Modbus_conn *get_conn(const std::string &n) {
        auto it = conns_.find(n);
        if (it == conns_.end())
            return nullptr;
        else
            return it->second;
    }

private:
    std::map<std::string, Modbus_conn *> conns_;
};

/***************/
/* Global vars */
/***************/
Modbus_mngr modbus_mngr;

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
                                  "plg_modbus: [%s]",
                                  e.what());
        return -1;
    }

    // process
    try {
        // get list of backends
        auto j_b_lst = pcfg->at("backends");
        // loop backends
        for(auto it_b = j_b_lst.begin(); it_b != j_b_lst.end(); ++ it_b) {
            // sanity check
            if(!it_b->is_object()){
                throw std::invalid_argument("backend != object");
            }
            // add connection
            Modbus_conn *mc = modbus_mngr.add_conn(*it_b);
            // connect
            if (mc)
                mc->connect(*it_b);
        }

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_modbus: [%s]",
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


/************************/
/* CMD_MODBUS_WRITE_BIT */
/************************/
static void do_write_bit(Modbus_conn *conn, int addr, int s) {
    conn->write_bit(addr, s);
}

/******************************/
/* local CMD_MODBUS_WRITE_BIT */
/******************************/
static void impl_local_write_bit(json_rpc::JsonRpc &jrpc, json *j_d) {
    int addr = 0;
    Modbus_conn *conn = nullptr;
    int bit = 0;

    // process params
    jrpc.process_params([&addr, &conn, &bit](int id, const std::string &s) {
        // address
        if (id == gdt_grpc::PT_MODBUS_ADDR) {
            addr = std::stoi(s);

        // bit
        } else if (id == gdt_grpc::PT_MODBUS_BITS) {
            bit = std::stoi(s);

        // connection label
        } else if (id == gdt_grpc::PT_MODBUS_CONNECTION) {
            conn = modbus_mngr.get_conn(s);
        }
        return true;
    });

    // run
    if (!conn) {
        throw std::invalid_argument("modbus connection is missing");
    }
    do_write_bit(conn, addr, bit);

}

/************************/
/* CMD_MODBUS_READ_BITS */
/************************/
static void do_read_bits(Modbus_conn *conn, int addr, int nb, json *j_d) {
    try{
        auto res = conn->read_bits(addr, nb);
        // generate result in method was called via JSON-RPC
        if (j_d) {
            (*j_d)[Jrpc::RESULT_].push_back(res);
        }

    } catch (std::exception &e) {
        throw std::invalid_argument(e.what());
    }
}

/******************************/
/* local CMD_MODBUS_READ_BITS */
/******************************/
static void impl_local_read_bits(json_rpc::JsonRpc &jrpc, json *j_d) {
    int addr = 0;
    Modbus_conn *conn = nullptr;
    int nb = 0;

    // process params
    jrpc.process_params([&addr, &conn, &nb](int id, const std::string &s) {
        // address
        if (id == gdt_grpc::PT_MODBUS_ADDR) {
            addr = std::stoi(s);

        // bit
        } else if (id == gdt_grpc::PT_MODBUS_NB) {
            nb = std::stoi(s);

        // connection label
        } else if (id == gdt_grpc::PT_MODBUS_CONNECTION) {
            conn = modbus_mngr.get_conn(s);
        }
        return true;
    });

    // run
    if (!conn) {
        throw std::invalid_argument("modbus connection is missing");
    }
    do_read_bits(conn, addr, nb, j_d);
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
                case gdt_grpc::CMD_MODBUS_WRITE_BIT:
                    impl_local_write_bit(jrpc, j_d);
                    break;

                case gdt_grpc::CMD_MODBUS_READ_BITS:
                    impl_local_read_bits(jrpc, j_d);
                    break;

                default:
                    break;
            }

        } catch (std::exception &e) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_modbus: [%s]",
                                      e.what());
            auto j_err = Jrpc::gen_err(id, e.what());
            (*j_d)[Jrpc::ERROR_] = j_err[Jrpc::ERROR_];
        }
        return 0;
    }

    // plugin2plugin local interface
    if(p_id.type() == mink_utils::PLG_DT_SPECIFIC){
        // TODO
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


