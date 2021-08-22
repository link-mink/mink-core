/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef CONFIG_GDT_H_
#define CONFIG_GDT_H_

#include <mink_config.h>
#include <gdt.h>

namespace config {

    class GDTCfgNtfUser: public config::UserId {
    public:
        GDTCfgNtfUser(gdt::GDTClient* _gdtc);
        gdt::GDTClient* gdtc;

    };

    class GDTCfgNotification : public CfgNotification {
    public:
        GDTCfgNotification(std::string* _cfg_path);
        ~GDTCfgNotification();

        int notify(void* args);
        void* reg_user(void* usr);
        int unreg_user(void* usr);
        bool user_exists(GDTCfgNtfUser* usr);
        GDTCfgNtfUser* get_user(unsigned int usr_index);
        unsigned int get_user_count();

        config::ConfigItem ntf_cfg_lst;
        bool ready;

    private:
        std::vector<GDTCfgNtfUser> users;

    };

    // Distribute config stream next event definition
    class DistributeCfgStreamNext: public gdt::GDTCallbackMethod {
    public:
        DistributeCfgStreamNext();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);

        uint32_t res_count;
        int res_index;
        config::UserId cfg_user_id;
        std::string repl_line;
        uint32_t ca_cfg_replicate;
        uint32_t pt_cfg_repl_line;
        uint32_t pt_cfg_auth_id;

    };


    // Distribute config stream finished event definition
    class DistributeCfgStreamDone: public gdt::GDTCallbackMethod {
    public:
        // event handler method
        void run(gdt::GDTCallbackArgs* args);

        DistributeCfgStreamNext* snext;

    };


    // Notify user stream next event definition
    class NtfyUsrStreamNext: public gdt::GDTCallbackMethod {
    public:
        NtfyUsrStreamNext();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);

        uint32_t res_count;
        unsigned int res_index;
        config::ConfigItem cfg_flat;
        config::GDTCfgNotification* cfg_ntf;
        config::GDTCfgNtfUser* ntf_user;
        config::Config* config;
        uint32_t pt_cfg_item_value;
        uint32_t pt_cfg_item_path;
        uint32_t ca_cfg_set;
        uint32_t pt_cfg_item_count;
        uint32_t pt_cfg_item_ns;
        uint32_t pt_cfg_item_nt;

    };

    // Notify user stream finished
    class NtfyUsrStreamDone: public gdt::GDTCallbackMethod {
    public:
        NtfyUsrStreamDone();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);
        // stream next
        NtfyUsrStreamNext* snext;

    };


    // Reg user stream next event definition
    class RegUsrStreamNext: public gdt::GDTCallbackMethod {
    public:
        RegUsrStreamNext();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);
        // buffer
        uint32_t cfg_count;
        config::ConfigItem cfg_res;

    };

    // Reg user stream finished
    class RegUseStreamDone : public gdt::GDTCallbackMethod {
    public:
        RegUseStreamDone();
        ~RegUseStreamDone();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);
        // signal
        sem_t signal;
        int status;
        // stream next
        RegUsrStreamNext* snext;
    };

    // fwd declaration
    class CfgUpdateStreamNext;


    // config client terminated
    class CfgUpdateClientTerm : public gdt::GDTCallbackMethod {
    public:
        // event handler method
        void run(gdt::GDTCallbackArgs* args);

    };

    // Config update new stream
    class CfgUpdateStreamNew : public gdt::GDTCallbackMethod {
    public:
        CfgUpdateStreamNew();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);
        config::CfgNtfCallback* update_done;
        // config
        config::Config* config;
    };

    // Config update stream done
    class CfgUpdateStreamDone : public gdt::GDTCallbackMethod {
    private:
        void process_cfg_events();

    public:
        CfgUpdateStreamDone();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);
        // stream done
        CfgUpdateStreamNew* snew;
        CfgUpdateStreamNext* snext;
    };


    // Config update stream next
    class CfgUpdateStreamNext : public gdt::GDTCallbackMethod {
    public:
        CfgUpdateStreamNext();
        // event handler method
        void run(gdt::GDTCallbackArgs* args);
        // stream done
        CfgUpdateStreamDone sdone;
        // pending update count
        int update_count;
        int res_index;
        config::ConfigItem cfg_res;
    };


    // user login (called by user daemon)
    int user_login(config::Config* config,
                   gdt::GDTClient* cfgd_gdtc,
                   const char* _target_daemon_id,
                   char* _connected_daemon_id,
                   config::UserId* cfg_user_id);

    // user logout (called by user daemon)
    int user_logout(config::Config* config,
                    gdt::GDTClient* cfgd_gdtc,
                    const char* _daemon_id,
                    config::UserId* cfg_user_id);


    // register user to receive notifications (called by user daemon)
    int notification_request(config::Config* config,
                             gdt::GDTClient* cfgd_gdtc,
                             const char* usr_root,
                             config::CfgNtfCallback* update_rcvd,
                             const char* _daemon_id,
                             config::UserId* cfg_user_id,
                             gdt::GDTCallbackMethod* non_cfg_hndlr);

    // create config event hanlers
    gdt::GDTCallbackMethod* create_cfg_event_handler(config::Config* config,
                                                     gdt::GDTCallbackMethod* non_cfg_hndlr = NULL);


    // notify user when configuration changes (called by config daemon after commit)
    int notify_user(config::Config* config,
                    config::ConfigItem* cfg_flat,
                    config::GDTCfgNtfUser* ntf_user,
                    config::GDTCfgNotification* cfg_ntf);

    // replicate to other config daemon (called by config daemon)
    int replicate(const char* repl_line,
                  gdt::GDTClient* _client,
                  const char* _daemon_id,
                  config::UserId* _cfg_user_id);
}



#endif /* CONFIG_GDT_H_ */
