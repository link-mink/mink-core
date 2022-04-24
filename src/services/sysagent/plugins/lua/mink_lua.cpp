/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <iostream>
#include <gdt.pb.enums_only.h>
#include <mink_plugin.h>
#include <json_rpc.h>
#include <vector>

/***********/
/* Aliases */
/***********/
using Jrpc = json_rpc::JsonRpc;

/************/
/* cmd_call */
/************/
extern "C" int mink_lua_cmd_call(void *md,
                                 int argc,
                                 const char **args,
                                 char ***out,
                                 int *out_sz) {
    // plugin manager
    mink_utils::PluginManager *pm = static_cast<mink_utils::PluginManager *>(md);
    // argument count check
    if (argc < 1) return -1;
    // get command id
    int cmd_id = Jrpc::get_method_id(args[0]);
    // cmd arguments
    mink_utils::Plugin_args cmd_args;
    for (int i = 1; i < argc; i++) {
        cmd_args.push_back(args[i]);
    }
    // run plugin method
    int r = pm->run(cmd_id,
            mink_utils::PluginInputData(mink_utils::PLG_DT_SPECIFIC, &cmd_args),
            true);
    // err check, create result
    if (!r) {
        *out_sz = cmd_args.size();
        *out = (char **)malloc(cmd_args.size() * sizeof(char **));
        for (size_t i = 0; i < cmd_args.size(); i++) {
            (*out)[i] = (char *)malloc(cmd_args[i].size() + 1);
            strcpy((*out)[i], cmd_args[i].c_str());
        }
    }
    // return status
    return r;
}
