/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef CONFIGD_EVENTS_H_
#define CONFIGD_EVENTS_H_

#include <mink_config.h>
#include <config_gdt.h>
#include <daemon.h>
#include <iostream>
#include <mink_utils.h>
#include <gdt.h>
#include <sstream>
#include <string>

// fwd declaration
class NewStream;

// stream next event definition
class StreamNext : public gdt::GDTCallbackMethod {
public:
    // constructor
    StreamNext();
    // TAB mode
    void process_tab(gdt::GDTCallbackArgs *args);
    // ENTER mode
    void process_enter(gdt::GDTCallbackArgs *args);
    // GET mode
    void process_get(gdt::GDTCallbackArgs *args);
    // handler method
    void run(gdt::GDTCallbackArgs *args) override;
    // members
    config::ConfigItem *cfg_res;
    NewStream *new_stream;
    uint32_t pt_cfg_cfg_line;
    uint32_t pt_cfg_cfg_error;
    uint32_t pt_cfg_item_name;
    uint32_t pt_cfg_item_path;
    uint32_t pt_cfg_item_desc;
    uint32_t pt_cfg_item_ns;
    uint32_t pt_cfg_item_value;
    uint32_t pt_cfg_item_nvalue;
    uint32_t pt_cfg_item_count;
    uint32_t pt_cfg_item_nt;

};

// stream finished
class StreamDone : public gdt::GDTCallbackMethod {
public:
    // event handler method
    void run(gdt::GDTCallbackArgs *args) override;

    // config change notification
    std::vector<config::CfgNotification *> ntfy_lst;
};

// new stream event definition
class NewStream : public gdt::GDTCallbackMethod {
public:
    // constructor
    NewStream();
    // TAB mode
    void process_tab(gdt::GDTCallbackArgs *args);
    // ENTER mode
    void process_enter(gdt::GDTCallbackArgs *args);
    // GET mode
    void process_get(gdt::GDTCallbackArgs *args);
    // REPLICATE mode
    void process_replicate(gdt::GDTCallbackArgs *args);
    // User LOGIN
    void process_user_login(gdt::GDTCallbackArgs *args) const;
    // User LOGOUT
    void process_user_logout(gdt::GDTCallbackArgs *args);
    // prepare notification
    void prepare_notifications();

    // event handler method
    void run(gdt::GDTCallbackArgs *args) override;

    // get config user id from GDT message
    int get_cfg_uid(config::UserId *usr_id,
                    asn1::GDTMessage *in_msg,
                    int sess_id) const;

    // members
    config::UserId cfg_user_id;
    std::string line;
    std::string cli_path;
    config::Config *config;
    int config_action;
    std::string tmp_lst[50];
    std::string tmp_err[50];
    int tmp_size;
    int res_size;
    int error_count;
    unsigned int res_index;
    int err_index;
    config::ConfigItem ac_res;
    uint32_t ac_res_count;
    config::ConfigItem tmp_node_lst;
    config::ConfigItem *last_found;
    config::ConfigModeType cm_mode;
    config::ConfigACMode ac_mode;
    std::stringstream line_stream;
    std::string line_buffer;
    int line_stream_lc;
    StreamNext stream_next;
    StreamDone stream_done;
    uint32_t ca_cfg_result;
    uint32_t pt_mink_config_ac_line;
    uint32_t pt_mink_config_cfg_line_count;
    uint32_t pt_mink_config_cli_path;
    uint32_t pt_mink_config_ac_err_count;
    uint32_t pt_cfg_item_cm_mode;
};

// client idle
class ClientIdle : public gdt::GDTCallbackMethod {
public:
    ClientIdle() = default;
    void run(gdt::GDTCallbackArgs *args) override;
    config::Config *config = nullptr;
};

// client terminated
class ClientDone : public gdt::GDTCallbackMethod {
public:
    explicit ClientDone(config::Config *_config);
    void run(gdt::GDTCallbackArgs *args) override;
    config::Config *config;
};

// client down (client terminating, client re-connecting)
class ClientDown : public gdt::GDTCallbackMethod {
public:
    explicit ClientDown(config::Config *_config);
    void run(gdt::GDTCallbackArgs *args) override;
    config::Config *config;
};

// new client GDT event
class NewClient : public gdt::GDTCallbackMethod {
public:
    explicit NewClient(config::Config *_config);
    void run(gdt::GDTCallbackArgs *args) override;
    // members
    NewStream new_stream;
    ClientIdle client_idle;
    config::Config *config;
};

#endif /* CONFIGD_EVENTS_H_ */
