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
#include <utility>
#include <vector>

/***********/
/* Aliases */
/***********/
using Jrpc = json_rpc::JsonRpc;

/*********/
/* Types */
/*********/
typedef struct {
    const char *key;
    const char *value;
} mink_cdata_column_t;

/*******************/
/* Free plugin res */
/*******************/
extern "C" void mink_lua_free_res(void *p) {
    delete static_cast<mink_utils::Plugin_data_std *>(p);
}

/**************************/
/* Create new plugin data */
/**************************/
extern "C" void *mink_lua_new_cmd_data() {
    return new mink_utils::Plugin_data_std();
}

/*****************************/
/* Get plugin data row count */
/*****************************/
extern "C" size_t mink_lua_cmd_data_sz(void *p) {
    // cast (unsafe) to standard plugin data type
    auto *d = static_cast<mink_utils::Plugin_data_std *>(p);
    // number of rows
    return d->size();
}

/**************************************************/
/* Get plugin data columns count for specific row */
/**************************************************/
extern "C" size_t mink_lua_cmd_data_row_sz(const int r, void *p) {
    // cast (unsafe) to standard plugin data type
    auto *d = static_cast<mink_utils::Plugin_data_std *>(p);
    // verify row index
    if (r >= d->size()) return 0;
    // return column count for rox index
    return d->at(r).size();
}

/********************************/
/* Get plugin data column value */
/********************************/
extern "C" mink_cdata_column_t mink_lua_cmd_data_get_column(const int r,
                                                            const int c,
                                                            void *p) {
    // get row count
    size_t rc = mink_lua_cmd_data_sz(p);
    // sanity check (rows)
    if (rc <= r) return mink_cdata_column_t{nullptr, nullptr};
    // cast (unsafe) to standard plugin data type
    auto *d = static_cast<mink_utils::Plugin_data_std *>(p);
    // get row
    auto row = d->cbegin() + r;
    // sanity check (columns)
    if (row->size() <= c) return mink_cdata_column_t{nullptr, nullptr};
    // get column
    auto column = row->cbegin();
    // advance to index c
    std::advance(column, c);
    // return column value
    return mink_cdata_column_t{column->first.c_str(), column->second.c_str()};
}

/***********/
/* Add row */
/***********/
extern "C" void mink_lua_cmd_data_add_rows(void *p, int sz) {
    // cast (unsafe) to standard plugin data type
    auto *d = static_cast<mink_utils::Plugin_data_std *>(p);
    // add rows
    for (int i = 0; i < sz; i++)
        d->push_back(std::map<std::string, std::string>());
}

/**************************************/
/* Add column value to a specific row */
/**************************************/
extern "C" void mink_lua_cmd_data_add_colum(const int r,
                                            const char *k,
                                            const char *v,
                                            void *p) {
    // get row count
    size_t rc = mink_lua_cmd_data_sz(p);
    // sanity check (rows)
    if (rc <= r) return;
    // cast (unsafe) to standard plugin data type
    auto *d = static_cast<mink_utils::Plugin_data_std *>(p);
    // get row
    auto row = d->begin() + r;
    // key shoud not be present
    if (row->find(k) != row->cend()) return;
    // add
    row->insert(std::make_pair(k, v));
}

/**********/
/* Signal */
/**********/
extern "C" char *mink_lua_signal(const char *s, const char *d, void *md) {
    // plugin manager
    mink_utils::PluginManager *pm = static_cast<mink_utils::PluginManager *>(md);
    // process signal
    mink_utils::Plugin_data_std e_d;
    e_d.push_back({{"", d}});
    return strdup(pm->process_signal(s, e_d).c_str());
}

/************/
/* cmd_call */
/************/
extern "C" int mink_lua_cmd_call(void *md,
                                 int argc,
                                 const char **args,
                                 void *out) {
    // plugin manager
    mink_utils::PluginManager *pm = static_cast<mink_utils::PluginManager *>(md);
    // argument count check
    if (argc < 1) return -1;
    // output check
    if (!out) return -2;
    // cmd data
    auto cmd_data = static_cast<mink_utils::Plugin_data_std *>(out);
    // get command id
    int cmd_id = Jrpc::get_method_id(args[0]);
    // cmd arguments
    for (int i = 1; i < argc; i++) {
        // column map
        std::map<std::string, std::string> cmap;
        // insert columns
        cmap.insert(std::make_pair("", args[i]));
        // add row
        cmd_data->push_back(cmap);
    }

    // run plugin method
    return pm->run(cmd_id,
                   mink_utils::PluginInputData(mink_utils::PLG_DT_STANDARD, cmd_data),
                   true);
}
