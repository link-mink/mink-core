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


