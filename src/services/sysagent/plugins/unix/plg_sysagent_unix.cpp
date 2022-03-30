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
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <exception>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_pkg_config.h>
#include <stdexcept>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <thread>
#include <sysagent.h>
#include <json_rpc.h>
#include <mink_err_codes.h>
#include <boost/bind/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/filesystem.hpp>

/***********/
/* Aliases */
/***********/
class session;
using bl = boost::asio::local::stream_protocol;
using session_ptr = boost::shared_ptr<session>;
using Jrpc = json_rpc::JsonRpc;
namespace bfs = boost::filesystem;

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    // end of list marker
    -1
};

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_unix.so";

/****************/
/* UNIX session */
/****************/
class session : public boost::enable_shared_from_this<session> {
public:
    session(boost::asio::io_context &io_context, mink_utils::PluginManager *pm)
        : socket_(io_context)
        , pm_(pm) {}

    bl::socket &socket() { return socket_; }

    void start() {
        socket_.async_read_some(boost::asio::buffer(data_),
                                boost::bind(&session::handle_read,
                                            shared_from_this(),
                                            pm_,
                                            boost::asio::placeholders::error,
                                            boost::asio::placeholders::bytes_transferred));
    }

    void handle_read(mink_utils::PluginManager *pm,
                     const boost::system::error_code &error,
                     size_t bytes_transferred) {
        if (error)
            return;

        // parse
        std::string rpc_data(data_.data(), bytes_transferred);
        json j = json::parse(rpc_data, nullptr, false);
        std::string rpl;
        // malformed
        if (j.is_discarded()){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "JSON RPC malformed = %s",
                                      rpc_data.c_str());

            rpl = json_rpc::JsonRpc::gen_err(mink::error::EC_JSON_MALFORMED).dump();
            rpl.append("\n");
            boost::asio::async_write(socket_,
                                     boost::asio::buffer(rpl),
                                     boost::bind(&session::handle_write,
                                                 shared_from_this(),
                                                 pm,
                                                 boost::asio::placeholders::error));
            return;

        // valid JSON RPC
        }else{
            int id = -1;
            int m = -1;
            try {
                // create json rpc parser
                json_rpc::JsonRpc jrpc(j);
                // verify
                jrpc.verify(true);
                // get id
                id = jrpc.get_id();
                // get method
                m = jrpc.get_method_id();
                if (m <= 0) {
                    throw std::invalid_argument("invalid JSON RPC method");
                }
                // run method
                pm->run(m,
                        mink_utils::PluginInputData(mink_utils::PLG_DT_JSON_RPC,
                                                    &j),
                        true);

                // generate empty json rpc reply
                auto j_res = json_rpc::JsonRpc::gen_response(id);
                // use "result" data
                if (j.find(Jrpc::RESULT_) != j.end())
                    j_res[Jrpc::RESULT_] = j[Jrpc::RESULT_];

                // or use "error" data
                else if (j.find(Jrpc::ERROR_) != j.end())
                    j_res[Jrpc::ERROR_] = j[Jrpc::ERROR_];

                // res string
                std::string s_res(j_res.dump() + "\n");
                // send response
                boost::asio::async_write(socket_,
                                         boost::asio::buffer(s_res, s_res.size()),
                                         boost::bind(&session::handle_write,
                                                     shared_from_this(),
                                                     pm,
                                                     boost::asio::placeholders::error));

            } catch (std::exception &e) {
                mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                          "JSON RPC error = [%s]",
                                          e.what());
                // generate JSON RPC error
                rpl = json_rpc::JsonRpc::gen_err(mink::error::EC_JSON_MALFORMED,
                                                 id,
                                                 e.what()).dump();
                rpl.append("\n");
                boost::asio::async_write(socket_,
                                         boost::asio::buffer(rpl),
                                         boost::bind(&session::handle_write,
                                                     shared_from_this(),
                                                     pm,
                                                     boost::asio::placeholders::error));
            }
        }
    }

    void handle_write(mink_utils::PluginManager *pm,
                      const boost::system::error_code &error) {
        if (error)
            return;

        socket_.async_read_some(boost::asio::buffer(data_),
                                boost::bind(&session::handle_read,
                                            shared_from_this(),
                                            pm,
                                            boost::asio::placeholders::error,
                                            boost::asio::placeholders::bytes_transferred));
    }

private:
    // The socket used to communicate with the client.
    bl::socket socket_;

    // Buffer used to store data received from the client.
    boost::array<char, 65536> data_;

    // plugin manager
    mink_utils::PluginManager *pm_;
};

/***************/
/* UNIX server */
/***************/
class server {
public:
    server(boost::asio::io_context &io_context,
           const std::string &file,
           mink_utils::PluginManager *pm)
        : io_context_(io_context)
        , acceptor_(io_context, bl::endpoint(file))
        , pm_(pm) {

        session_ptr new_session(new session(io_context_, pm));
        acceptor_.async_accept(new_session->socket(),
                               boost::bind(&server::handle_accept,
                                           this,
                                           new_session,
                                           pm_,
                                           boost::asio::placeholders::error));
    }

    void handle_accept(session_ptr new_session,
                       mink_utils::PluginManager *pm,
                       const boost::system::error_code &error) {
        if (!error) {
            new_session->start();
        }

        new_session.reset(new session(io_context_, pm));
        acceptor_.async_accept(new_session->socket(),
                               boost::bind(&server::handle_accept,
                                           this,
                                           new_session,
                                           pm,
                                           boost::asio::placeholders::error));
    }

private:
    boost::asio::io_context &io_context_;
    bl::acceptor acceptor_;
    mink_utils::PluginManager *pm_;
};

/**********************/
/* UNIX server thread */
/**********************/
static void thread_unix(const std::string &s_fp, mink_utils::PluginManager *pm){
    try {
        // remove old socket
        bfs::remove(s_fp);
        boost::asio::io_context io_ctx;
        server s(io_ctx, s_fp, pm);
        io_ctx.run();
    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_unix: [%s]", e.what());
    }
}

/********************************/
/* Process static configuration */
/********************************/
static int process_cfg(mink_utils::PluginManager *pm) {
    PluginsConfig *pcfg;
    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);

    // get config
    try {
        pcfg = static_cast<PluginsConfig *>(dd->dparams.get_pval<void *>(4));

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_unix: [configuration file missing]");
        return -1;
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_unix: [configuration missing]");
        return -2;
    }

    // process
    try {
        // get socket path
        auto j_sck = it->at("socket");
        // check type
        if (!j_sck.is_string()) {
            throw std::invalid_argument("group element != string");
        }
        // socket string
        std::string s_sck = j_sck.get<std::string>();

        // init unix server thread
        std::thread th(&thread_unix, s_sck, pm);
        th.detach();


    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_unix: [%s]", e.what());
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
                                  "plg_unix: [cannot process plugin configuration]");
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


