/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <dlfcn.h>
#include <mink_plugin.h>
#include <algorithm>

std::string const mink_utils::PLG_INIT_FN("init");
std::string const mink_utils::PLG_TERM_FN("terminate");
std::string const mink_utils::PLG_CMD_HNDLR("run");
std::string const mink_utils::PLG_CMD_HNDLR_LOCAL("run_local");
std::string const mink_utils::PLG_CMD_LST("COMMANDS");

mink_utils::PluginManager::~PluginManager(){
    // close plugins
    std::all_of(plgs.cbegin(), plgs.cend(), [this](PluginDescriptor *pd) {
        // terminate
        pd->termh(this, pd);
        // free mem
        dlclose(pd->handle);
        delete pd;
        return true;
    });
}

mink_utils::PluginManager::PluginManager(mink::DaemonDescriptor *_dd) : dd(_dd) {}


mink_utils::PluginDescriptor *mink_utils::PluginManager::load(const std::string &fpath){
    // open and resolve symbols now
    void *h = dlopen(fpath.c_str(), RTLD_NOW);
    if (!h)
        return nullptr;

    // success, check if plg is a valid plugin
    // check for init, term and cmd handler
    const int *reg_hooks = 
        reinterpret_cast<const int *>(dlsym(h, PLG_CMD_LST.c_str()));
    plg_init_t init =
        reinterpret_cast<plg_init_t>(dlsym(h, PLG_INIT_FN.c_str()));
    plg_term_t term =
        reinterpret_cast<plg_term_t>(dlsym(h, PLG_TERM_FN.c_str()));
    plg_cmd_hndlr_t cmdh =
        reinterpret_cast<plg_cmd_hndlr_t>(dlsym(h, PLG_CMD_HNDLR.c_str()));
    plg_cmd_hndlr_t cmdh_l =
        reinterpret_cast<plg_cmd_hndlr_t>(dlsym(h, PLG_CMD_HNDLR_LOCAL.c_str()));

    // first 4 must exist
    if (!(reg_hooks && init && term && cmdh)) {
        dlclose(h);
        return nullptr;
    }
    // check if all requested hooks are free
    const int *tmp_rh = reg_hooks;
    while (*tmp_rh != -1){
        if(hooks.find(*tmp_rh++) != hooks.end()){
            dlclose(h);
            return nullptr;
        }
    }
    // create descriptor
    auto pd = new mink_utils::PluginDescriptor();
    // set data
    pd->handle = h;
    pd->name = std::string(fpath);
    pd->type = 0;
    pd->cmdh = cmdh;
    pd->cmdh_l = cmdh_l;
    pd->termh = term;
    pd->data = nullptr;

    // attach hooks to plugin
    tmp_rh = reg_hooks;
    while (*tmp_rh != -1)
        hooks.insert(std::make_pair(*tmp_rh++, pd));
        
    // run init method
    if (!init(this, pd)) {
        // add to list
        plgs.push_back(pd);
    }

    // return descriptor
    return pd;
}

int mink_utils::PluginManager::unload(PluginDescriptor *pd){
    // TODO
    return 0;
}

int mink_utils::PluginManager::run(int cmd_id, void *data, bool is_local) {
    // plugin for cmd
    auto pd = hooks.find(cmd_id);
    if(pd == hooks.end()) return 1;
    // local
    if (is_local) {
        // handler implemented
        if (pd->second->cmdh_l) {
            return pd->second->cmdh_l(this, pd->second, cmd_id, data);

        // local handler not found
        } else {
            return -1;
        }
    }

    // remote
    return pd->second->cmdh(this, pd->second, cmd_id, data);

}

