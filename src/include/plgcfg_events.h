/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef PLGCFG_EVENTS_H_
#define PLGCFG_EVENTS_H_

#include <gdt.h>
#include <mink_config.h>
#include <cli.h>
#include <sstream>
#include <atomic.h>

// plugin information
class PluginInfo {
public:
    PluginInfo();
    ~PluginInfo();

    config::Config* config;
    cli::CLIService* cli;
    gdt::GDTSession* gdts;
    std::vector<std::string*> cfgd_lst;
    unsigned char last_cfgd_id[16];
    gdt::GDTClient* last_gdtc;
    sem_t sem_cfgd;
    config::UserId cfg_user_id;
    mink::Atomic<uint8_t> cfgd_active;
    gdt::HeartbeatInfo* hbeat;

};

// stream finished
class StreamEnd: public gdt::GDTCallbackMethod {
public:
    explicit StreamEnd(PluginInfo* _pi);
    void run(gdt::GDTCallbackArgs* args);

private:
    PluginInfo* plugin_info;

};


// stream next
class StreamNext: public gdt::GDTCallbackMethod {
public:
    StreamNext(PluginInfo* _pi, config::ConfigItem* _cfg_res);
    void run(gdt::GDTCallbackArgs* args);
    // TAB mode
    void process_tab(gdt::GDTCallbackArgs* args);
    // ENTER mode
    void process_enter(gdt::GDTCallbackArgs* args);
    // members
    PluginInfo* plugin_info;
    config::ConfigItem* cfg_res;
    config::ConfigModeType cm_mode;
    config::ConfigACMode ac_mode;
    std::stringstream line_stream;
    std::string line_buffer;
    int line_stream_lc;
    int error_count;
    int err_index;
    std::string err_lst[50];
};




#endif /* PLGCFG_EVENTS_H_ */
