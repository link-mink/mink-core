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
#include <stdexcept>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <atomic>
#include <thread>
#include <lua.hpp>
#include <json_rpc.h>
#include <sysagent.h>

/***********/
/* Aliases */
/***********/
using Jrpc = json_rpc::JsonRpc;
namespace bfs = boost::filesystem;
namespace stdc = std::chrono;

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_lua.so";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_LUA_CALL,
    // end of list marker
    -1
};

/****************/
/* LUA ENV data */
/****************/
struct Lua_env_data {
    mink_utils::PluginManager *pm;
};

/**********************/
/* LUA ENV Descriptor */
/**********************/
struct Lua_env_d {
    // label
    std::string name;
    // in case of long running
    // envs, time between each
    // execution
    // 0 - one time execution
    uint64_t interval;
    // activity flag (used only
    // with long running envs)
    std::shared_ptr<std::atomic_bool> active;
    // path to lua script
    std::string path;
};

/*******************/
/* LUA ENV Manager */
/*******************/
class Lua_env_mngr {
public:
    Lua_env_mngr() = default;
    ~Lua_env_mngr() = default;
    Lua_env_mngr(const Lua_env_mngr &o) = delete;
    Lua_env_mngr &operator=(const Lua_env_mngr &o) = delete;

    Lua_env_d &get_envd(const std::string &n){
        // lock
        std::unique_lock<std::mutex> l(mtx_);
        auto it = envs_.find(n);
        if(it != envs_.end()) return it->second;
        // not found
        throw std::invalid_argument("env not found");
    }

    Lua_env_d &new_envd(const Lua_env_d &d){
        // lock
        std::unique_lock<std::mutex> l(mtx_);
        // find env
        auto it = envs_.find(d.name);
        // create new env
        if (it == envs_.end()){
            auto it2 = envs_.emplace(std::make_pair(d.name, d));
            return it2.first->second;

        // return existing env
        }else{
            return it->second;

        }
    }
    bool env_exists(const std::string &n){
        return envs_.find(n) != envs_.end();
    }

    void process_envs(const std::function<void(Lua_env_d &)> &f){
        // lock
        std::unique_lock<std::mutex> l(mtx_);
        for (auto it = envs_.begin(); it != envs_.end(); ++it)
            f(it->second);
    }

private:
    std::mutex mtx_;
    std::map<std::string, Lua_env_d> envs_;
};


/******************/
/* Signal handler */
/******************/
class Lua_signal_hndlr: public mink_utils::SignalHandler {
public:
    Lua_signal_hndlr(Lua_env_d &ed, mink_utils::PluginManager *pm)
        : ed_(ed)
        , pm_(pm) {

        // lua state
        L_ = luaL_newstate();
        if (!L_) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_lua: [cannot create Lua state]");
            throw std::invalid_argument("cannot create Lua state");
        }
        // init lua
        luaL_openlibs(L_);

         // load lua script
        std::string l;
        bfs::ifstream lua_s_fs(ed_.path);
        while (std::getline(lua_s_fs, l)) {
            lua_s_ += l + "\n";
        }

        // load lua script
        if(luaL_loadstring(L_, lua_s_.c_str())){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_lua: [cannot load Lua script]");
            lua_close(L_);
            throw std::invalid_argument("cannot load Lua script");
        }


    }

    void operator()(mink_utils::Plugin_data_std &d) const {
        // copy precompiled lua chunk (pcall removes it)
        lua_pushvalue(L_, -1);
        // push plugin manager pointer
        lua_pushlightuserdata(L_, pm_);
        // push data
        lua_pushlightuserdata(L_, &d);
        // run lua script
        if(lua_pcall(L_, 2, 1, 0)){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_lua: [%s]",
                                      lua_tostring(L_, -1));
        }
        // pop result or error message
        lua_pop(L_, 1);
    }

private:
    Lua_env_d ed_;
    mink_utils::PluginManager *pm_;
    std::string lua_s_;
    lua_State *L_;
};


/**********/
/* Global */
/**********/
Lua_env_mngr env_mngr;

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
                                  "plg_lua: [configuration file missing]");
        return -1;
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_lua: [LUA configuration missing]");
        return -2;
    }

    // get envs
    try {
        // get main handler (CMD_CALL)
        const auto j_cmd_c = (*it)["cmd_call"].get<std::string>();
        // create ENV descriptor
        Lua_env_d ed{"CMD_CALL",
                     0,
                     std::make_shared<std::atomic_bool>(true),
                     j_cmd_c
        };
        // add to list
        env_mngr.new_envd(ed);

        // get reference to envs
        const auto j_envs = (*it)["envs"].get_ref<const json::array_t &>();
        // iterate and verify envs
        for(auto it = j_envs.begin(); it != j_envs.end(); ++it){
            // check type
            if(!it->is_object()){
                throw std::invalid_argument("envs element != object");
            }
            // *******************************
            // *** Get ENV values (verify) ***
            // *******************************
            // get name
            auto j_name = (*it)["name"];
            // check for duplicate name
            if(env_mngr.env_exists(j_name.get<std::string>()))
                throw std::invalid_argument("env already exists");

            // get auto_start
            auto j_as = (*it)["auto_start"];
            // get interval
            auto j_intrvl = (*it)["interval"];
            // check interval range
            if(!j_intrvl.is_number_unsigned()){
                throw std::invalid_argument("invalid interval");
            }
            // get script file
            auto j_path = (*it)["path"];
            // check file size
            int sz = mink_utils::get_file_size(j_path.get<std::string>().c_str());
            if ((sz <= 0)) {
                throw std::invalid_argument("invalid path");
            }

            // create ENV descriptor
            Lua_env_d ed{
                j_name.get<std::string>(),
                j_intrvl.get<json::number_unsigned_t>(),
                std::make_shared<std::atomic_bool>(j_as.get<json::boolean_t>()),
                j_path.get<std::string>()
            };

            // check for event subscriptions
            if (it->find("events") == it->end()) continue;
            auto j_events = it->at("events");
            // loop events
            for(auto it_ev = j_events.begin(); it_ev != j_events.end(); ++it_ev){
                // register signal handlers
                pm->register_signal(it_ev->get<std::string>(),
                                    new Lua_signal_hndlr(ed, pm));
                mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                      "plg_lua: [attaching '%s' to '%s' event]",
                                      ed.path.c_str(),
                                      it_ev->get<std::string>().c_str());

            }

            // add to list
            env_mngr.new_envd(ed);
        }


    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_lua: [cannot start LUA environment: %s]",
                                  e.what());
        return -3;
    }

    return 0;
}
/*******************/
/* LUA Environment */
/*******************/
static void thread_lua_env(Lua_env_d *ed, mink_utils::PluginManager *pm){
    // lua state
    lua_State *L = luaL_newstate();
    if (!L) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_lua: [cannot create Lua state]");
        return;
    }
    // init lua
    luaL_openlibs(L);

    // load lua script
    std::string lua_s;
    std::string l;
    bfs::ifstream lua_s_fs(ed->path);
    while (std::getline(lua_s_fs, l)) {
        lua_s += l + "\n";
    }

    // load lua script
    if(luaL_loadstring(L, lua_s.c_str())){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_lua: [cannot load Lua script]");
        lua_close(L);
        return;
    }
    // run
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED && ed->active->load()){
        // copy precompiled lua chunk (pcall removes it)
        lua_pushvalue(L, -1);
        // push plugin manager pointer
        lua_pushlightuserdata(L, pm);
        // run lua script
        if(lua_pcall(L, 1, 1, 0)){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_lua: [%s]",
                                      lua_tostring(L, -1));
        }
        // pop result or error message
        lua_pop(L, 1);
        // next iteration
        std::this_thread::sleep_for(stdc::milliseconds(ed->interval));
    }
    // remove lua state
    lua_close(L);

}

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    // process cfg
    if (process_cfg(pm)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_lua: [cannot process plugin configuration]");
        return 1;
    }

    // create environments
    env_mngr.process_envs([pm](Lua_env_d &d){
        // check if ENV should auto-start
        if (d.interval > 0) {
            mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                      "plg_lua: [starting ENV (%s)]",
                                      d.name.c_str());

            std::thread th(&thread_lua_env, &d, pm);
            th.detach();
        }
    });

    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/*********************************/
/* local CMD_LUA_CALL (standard) */
/*********************************/
static void impl_lua_call(mink_utils::Plugin_data_std *data,
                          mink_utils::PluginManager *pm) {
    // sanity check
    if(!data || data->empty()){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_lua: [CMD_LUA_CALL invalid data]");
        return;
    }

    try {
        // get CMD_CALL env
        Lua_env_d &ed = env_mngr.get_envd("CMD_CALL");
         // lua state
        lua_State *L = luaL_newstate();
        if (!L) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_lua: [cannot create Lua state]");
            throw std::invalid_argument("cannot create Lua state");
        }
        // init lua
        luaL_openlibs(L);

         // load lua script
        std::string l;
        std::string lua_s;
        bfs::ifstream lua_s_fs(ed.path);
        while (std::getline(lua_s_fs, l)) {
            lua_s += l + "\n";
        }

        // load lua script
        if(luaL_loadstring(L, lua_s.c_str())){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_lua: [cannot load Lua script]");
            lua_close(L);
            throw std::invalid_argument("cannot load Lua script");
        }

        // copy precompiled lua chunk (pcall removes it)
        lua_pushvalue(L, -1);
        // push plugin manager pointer
        lua_pushlightuserdata(L, pm);
        // push data
        lua_pushlightuserdata(L, data);
        // run lua script
        if(lua_pcall(L, 2, 1, 0)){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_lua: [%s]",
                                      lua_tostring(L, -1));
        }
        // pop result or error message
        lua_pop(L, 1);
        // remove lua state
        lua_close(L);


    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_lua: [%s]",
                                  e.what());
    }
}
/**********************************/
/* local CMD_LUA_CALL (UNIX JRPC) */
/**********************************/
static void impl_lua_call(json *j,
                          mink_utils::PluginManager *pm) {

    // create standard plugin in/out data
    mink_utils::Plugin_data_std e_d;
    e_d.push_back({{"", j->dump()}});
    // call lua
    impl_lua_call(&e_d, pm);
    // return result
    if (e_d.size() > 1)
        (*j)[Jrpc::RESULT_] = e_d.at(1).cbegin()->second;
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
                case gdt_grpc::CMD_LUA_CALL:
                    impl_lua_call(j_d, pm);
                    break;

                default:
                    break;
            }

        } catch (std::exception &e) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_cgroup2: [%s]",
                                      e.what());
            auto j_err = Jrpc::gen_err(id, e.what());
            (*j_d)[Jrpc::ERROR_] = j_err[Jrpc::ERROR_];
        }
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
            case gdt_grpc::CMD_LUA_CALL:
                impl_lua_call(plg_d, pm);
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


