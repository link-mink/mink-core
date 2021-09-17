/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_CONFIG_H_
#define MINK_CONFIG_H_

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <curses.h>

namespace config {

    /**
     * Configuration node type
     */
    enum ConfigNodeType {
        /** Unknown */
        CONFIG_NT_UNKNOWN   = -1,
        /** Block node (group) */
        CONFIG_NT_BLOCK     = 0,
        /** Value node */
        CONFIG_NT_ITEM      = 1,
        /** Command node */
        CONFIG_NT_CMD       = 2,
        /** Parameter node */
        CONFIG_NT_PARAM     = 4

    };

    /**
     * Configration auto complete mode
     */
    enum ConfigACMode {
        /** TAB mode */
        CONFIG_ACM_TAB      = 0,
        /** ENTER mode */
        CONFIG_ACM_ENTER    = 1
    };

    /**
     * Configuration mode type
     */
    enum ConfigModeType {
        /** Unknown */
        CONFIG_MT_UNKNOWN   = -1,
        /** Show node value */
        CONFIG_MT_SHOW      = 0,
        /** Set node value */
        CONFIG_MT_SET       = 1,
        /** Command mode */
        CONFIG_MT_CMD       = 2,
        /** Delete node */
        CONFIG_MT_DEL       = 3,
        /** Edit node (change working node) */
        CONFIG_MT_EDIT      = 4
    };

    /**
     * Configuration node state
     */
    enum ConfigNodeState {
        /** Unknown state */
        CONFIG_NS_UNKNOWN   = -1,
        /** Ready, no changes */
        CONFIG_NS_READY     = 0,
        /** Modified */
        CONFIG_NS_MODIFIED  = 1,
        /** Deleted */
        CONFIG_NS_DELETED   = 2


    };


    // fwd declaration
    class CfgNotification;
    class CfgNtfCallback;


    /**
     * Configuration item node
     */
    class ConfigItem {
    public:
        ConfigItem();
        ConfigItem(const ConfigItem &o);
        ConfigItem &operator=(const ConfigItem &o);
        virtual ~ConfigItem();

        /**
         *  Special auto complete method, called when
         auto completing parameter value starting with '?' symbol
         */
        virtual void special_ac(void** args, int argc);

        /**
         * Get configuration item
         * @param[in]   _name           Pointer to configuration line string
         * @param[in]   create          Create new flag
         * @param[in]   last_nt         New node type
         * @param[in]   _set_new_flag   Set is_new flag if set
         * @return      Pointer to configuration item or nullptr if not found
         */
        ConfigItem* operator ()(const char* _name, 
                                bool create = false, 
                                ConfigNodeType last_nt = CONFIG_NT_UNKNOWN, 
                                bool _set_new_flag = false);

        /**
         * Convert node value to int
         * @param[in]   node_path       Node path
         * @param[in]   default_val     Default if not found
         * @return      Integer representation of node value
         */
        int to_int(const char* node_path = nullptr, int default_val = 0);

        /**
         * Convert node value to boolean
         * @param[in]   node_path       Node path
         * @return      Boolean representation of node value
         */
        bool to_bool(const char* node_path = nullptr);

        /**
         * Check in node value exists
         * @param[in]   node_path       Node path
         * @return      True if node valiue is not empty or False otherwise
         */
        bool val_exists(const char* node_path = nullptr);

        /**
         * Convert node value to C string
         * @param[in]   node_path       Node path
         * @return      C string representation of node value
         */
        const char* to_cstr(const char* node_path = nullptr);

        /**
         * Find chilld
         * @param[in]   item    Pointer to needle item
         * @return      Item index or -1 if not found
         */
        int find(const ConfigItem* item);

        /**
         * Find parent
         * @param[in]   name    Name of parent node
         * @return      Pointer to parent node or nullptr if not found
         */
        ConfigItem* find_parent(const char* name);

        /**
         * Check if modified (root or children, recursive)
         * @return      True if modified
         */
        bool is_modified(ConfigItem* _node = nullptr);

        /**
         * Set ON CHANGE event handler
         * @param[in]   _on_change      Pointer to ON CHANGE event handler
         */
        void set_on_change_handler(CfgNtfCallback* _on_change, bool recursive = false);

        /**
         * Get ON CHANGE event handler
         * @return      Pointer to oN CHANGE event handler
         */
        CfgNtfCallback* get_on_change_handler();

        /**
         * Run ON CHANGE event handler
         * @param[in]   mod_index       Index of current modifications in cfg tree
         * @param[in]   mod_count       Number of modifications in cfg tree
         * @return      0 for success or error code
         */
        int run_on_change_handler(unsigned int mod_index, unsigned int mod_count);

        /** Parent node */
        ConfigItem* parent;
        /** Node name */
        std::string name;
        /** Node value */
        std::string value;
        /** New uncommitted value */
        std::string new_value;
        /** Node value type */
        std::string type;
        /** Node description */
        std::string desc;
        /** Node type */
        ConfigNodeType node_type;
        /** Node state */
        ConfigNodeState node_state;
        /** Child nodes */
        std::vector<ConfigItem*> children;
        /** Template flag */
        bool is_template;
        bool is_empty;
        /** New node flag */
        bool is_new;
        /** ON CHANGE handler executed flag */
        bool onc_hndlr_exec;
        /** Node ON CHANGE event handler */
        CfgNtfCallback* on_change;
        ConfigItem* sort_node;
    };

    /**
     * Configuration item sort
     */
    struct ConfigItemSort{
        bool operator() (ConfigItem* i, ConfigItem* j) const;
    };

    /**
     * Configuration node notification callback
     */
    class CfgNtfCallback {
    public:
        CfgNtfCallback() = default;
        virtual ~CfgNtfCallback();

        /**
         * Run callback method
         * @param[in]   cfg         Pointer to new flattened configuration node set
         * @param[in]   mod_index   Index of current modifications in cfg tree
         * @param[in]   mod_count   Number of modifications in cfg tree
         */
        virtual void run(ConfigItem* cfg, 
                         unsigned int mod_index = 0, 
                         unsigned int mod_count = 0);

    };



    /**
     * Configuration node on_change notification
     *
     */
    class CfgNotification {
    public:
        explicit CfgNotification(const std::string* _cfg_path);
        virtual ~CfgNotification();

        /**
         * Run notification
         * @param[in]   args        Argument pointer
         * @return      0 if notify was successful or 1 if error occurred
         *
         */
        virtual int notify(void* args);

        /**
         * Register new node user
         * @param[in]   usr         Pointer to configuration node user
         * @return      Pointer to node user or nullptr if error occurred
         *
         */
        virtual void* reg_user(void* usr);

        /**
         * Unregister node user
         * @param[in]   usr         Pointer to configuration node user
         * @return      0 if unreg was successful or 1 if error occurred
         *
         */
        virtual int unreg_user(void* usr);

        /**
         * Get configuration node path
         * @return      Pointer to node path string
         */
        std::string* get_cfg_path();

    private:
        /** Configuration node path */
        std::string cfg_path;
    };


    /**
     * Special Rollback revision auto complete node
     */
    class ConfigItemRBR : public ConfigItem {
    public:
        /**
         * Special constructor
         * @param[in]   _parent     Pointer to parent node
         */
        explicit ConfigItemRBR(ConfigItem* _parent);

        /**
         * Special auto complete method
         * @param[in]   args        Pointer to argument list
         * @param[in]   argc        Number of arguments
         */
        void special_ac(void** args, int argc) override;

    };


    /**
     * Configuration data pattern
     */
    class CFGPattern {
    public:
        /** Pattern name */
        std::string name;
        /** Pattern regular expression */
        std::string pattern;
        /** Pattern description */
        std::string desc;
    };

    /**
     * User id
     */
    class UserId {
    public:
        UserId();
        /** Custom '!=' operator */
        bool operator != (const UserId& right) const;
        /** Custom '==' operator */
        bool operator == (const UserId& right)const;
        /** User type (daemon type) */
        unsigned char user_type[16];
        /**
         * User id
         * daemon type (15) + daemon id (15) + extra id (15) + nullptr character (1)
         */
        unsigned char user_id[46];

    };

    /**
     * User info
     */
    class UserInfo {
    public:
        /**
         * Constructor
         * @param[in]   _wnode  Pointer to user's working node
         */
        explicit UserInfo(ConfigItem* _wnode);
        /** Unix timestamp of last user action */
        time_t timestamp;
        /** User's working node */
        ConfigItem* wnode;
    };

    /**
     * User id comparison for user map
     */
    class UserIdCompare {
    public:
        /**
         * Custom operator '()'
         */
        bool operator ()(const UserId& x, const UserId& y) const;
    };


    /**
     * Configuration management class
     */
    class Config {
    public:
        Config();
        Config(const Config &o) = delete;
        Config &operator=(const Config &o) = delete;
        ~Config();

        /**
         * Add configuration notification
         * @param[in]   cfg_ntf     Pointer to notification object
         *
         */
        void add_notification(CfgNotification* cfg_ntf);

        /**
         * Remove notification from list
         * @param[in]   cfg_ntf     Pointer to notification object
         * @return      Pointer to notification object or nullptr if not found
         *
         */
        CfgNotification* remove_notification(CfgNotification* cfg_ntf);

        /**
         * Get notification for specific node path
         * @param[in]   cfg_path    Pointer to node path string
         * @return      Pointer to notification object or nullptr if not found
         *
         */
        CfgNotification* get_notification(const std::string* cfg_path);

        /**
         * Set transaction owner id
         * @param[in]   _id         Owner id
         */
        void set_transaction_owner(const UserId* _id);

        /**
         * Get transaction owner id
         * @return      Owner id
         */
        UserId get_transaction_owner() const;

        /**
         * Start transaction
         * @param[in]   _owner_id   Owner id
         *
         */
        void start_transaction(const UserId* _owner_id);

        /**
         * End transaction
         */
        void end_transaction();

        /**
         * Get transaction state
         * @return      True if transaction started or False otherwise
         */
        bool transaction_started() const;

        /**
         * Lock mutex
         * @return      Mutex lock operation result
         */
        int lock();

        /**
         * Unlock mutex
         * @return      Mutex unlock operation result
         */
        int unlock();

        /**
         * Load configuration definition
         * @param[in]   cfg_def     Pointer to configuration definition
         */
        void load_definition(ConfigItem* cfg_def);

        /**
         * Create and set new configuration definition
         * @return      Pointer to new configuration definition
         */
        ConfigItem* new_definition();

        /**
         * Validate definition templates
         * @param[in]   cfg_def     Pointer to configuration definition
         * @return      True if definition is valid or False otherwise
         */
        bool validate_definition(ConfigItem* cfg_def);

        /**
         * Print configuration tree
         * @param[in]   tree        Pointer to configuration tree
         * @param[in]   depth       Current depth, should be 0
         * @param[in]   ncurses     If ncurses flag is set, use ncurses library for output
         */
        static void print_config_tree(ConfigItem* tree, int depth, bool ncurses);


        /**
         * Flatten configuration tree
         * @param[in]   tree        Pointer to configuration tree
         * @param[out]  output      Output buffer
         */
        static void flatten(ConfigItem* tree, ConfigItem* output);

        /**
         * Get space separated list of parents
         * @param[in]   tree        Pointer to configuration tree
         * @param[out]  output      Output buffer
         */
        static void get_parent_line(ConfigItem* tree, std::string* output);

        /**
         * Add new configuration data pattern
         * @param[in]   ptrn        Pointer to configuration data pattern
         */
        void add_pattern(CFGPattern* ptrn);

        /**
         * Get configuration data pattern
         * @param[in]   type        Pointer to data pattern string
         * @return      Pointer to pattern object or nullptr if not found
         */
        CFGPattern* get_pattern(const std::string* type);

        /**
         * Validate data value
         * @param[in]   value       Pointer to data value string
         * @param[in]   type        Pointer to data type string
         * @param[in]   cfg_node    Pointer to current configuration node
         * @return      True is data value fits the pattern or False otherwise
         */
        bool pattern_valid(std::string* value, 
                           const std::string* type, 
                           ConfigItem* cfg_node = nullptr);

        /**
         * Merge configuration data contents with configuration definition
         * @param[in]   _definition     Pointer to configuration definition
         * @param[in]   _contents       Pointer to configuration contents
         * @param[in]   set_node_state  Flag indicating dual stage merge (commit)
         * @return      0 if merge was successful or 1 if error occurred
         */
        int merge(ConfigItem* _definition, ConfigItem* _contents, bool set_node_state);

        /**
         * Validate if configuration contents are compatible with definition
         * @param[in]   _definition     Pointer to configuration definition
         * @param[in]   _contents       Pointer to configuration contents
         * @return      True if configuration contents are compatible with definition or False otherwise
         */
        bool validate(ConfigItem* _definition, ConfigItem* _contents);

        /**
         * Reset configuration definition, discard all configuration data contents
         * @param[in]   _definition     Pointer to configuration definition
         * @return      0 if reset was successful or 1 if error occured
         */
        int reset(ConfigItem* _definition);

        /**
         * Prepare configuration definition for complete replacement of configuration data contents
         * @param[in]   _definition     Pointer to configuration definition
         */
        void replace_prepare(ConfigItem* _definition);

        /**
         * Get configuration data contents
         * @param[in]   _contents       Pointer to configuration data contents
         * @param[out]  result          Pointer to output data buffer
         * @param[out]  result_size     Pointer to output size buffer
         * @param[in]   depth           Depth value, should be 0
         */
        void show_config(ConfigItem* _contents, unsigned char* result, int* result_size, int depth);

        /**
         * Print configuration data contents to standard output
         * @param[in]   _contents       Pointer to configuration data contents
         * @param[in]   depth           Depth value, should be 0
         * @param[out]  result_size     Pointer to result size buffer
         * @param[in]   ncurses         If ncurses flag is set, use ncurses library for output
         * @param[in]   no_output       If set, suppress output
         */
        void show_config(ConfigItem* _contents, int depth, int* result_size, bool ncurses, bool no_output);

        /**
         * Print configuration data contents to virtual window
         * @param[in]   _contents       Pointer to configuration data contents
         * @param[in]   depth           Depth value, should be 0
         * @param[out]  result_size     Pointer to result size buffer
         * @param[in]   no_output       If set, suppress output
         * @param[out]  win             Pointer to output window
         */
        void show_config(ConfigItem* _contents, int depth, int* result_size, bool no_output, WINDOW* win);

        /**
         * Print configuration data contents to string stream
         * @param[in]   _contents       Pointer to configuration data contents
         * @param[in]   depth           Depth value, should be 0
         * @param[out]  result_size     Pointer to result size buffer
         * @param[in]   no_output       If set, suppress output
         * @param[out]  out_stream      Pointer to string stream
         */
        void show_config(ConfigItem* _contents, 
                         int depth, 
                         int* result_size, 
                         bool no_output, 
                         std::stringstream* out_stream);

        /**
         * Get configuration output line count
         * @param[in]   _contents       Pointer to configuration data contents
         * @return      Number of lines containted in configuration file
         */
        int get_config_lc(ConfigItem* _contents);

        /**
         * Save configuration data contents to file
         * @param[in]   _contents       Pointer to configuration data contents
         * @param[in]   depth           Depth value, should be 0
         * @param[out]  result_size     Pointer to result size buffer
         * @param[in]   no_output       If set, suppress output
         * @param[out]  out_stream      Pointer to output file stream
         * @param[in]   no_uncm         If set, uncommitted data will be skipped
         * @param[in]   desc            Description of current configuration (commit comment)
         *
         */
        void show_config(ConfigItem* _contents, 
                         int depth, 
                         int* result_size, 
                         bool no_output, 
                         std::ofstream* out_stream, 
                         bool no_uncm, 
                         std::string* desc);

        /**
         * Get commands needed to recreate current configuration data contents
         * @param[in]   _definition     Pointer to configuration definition
         * @param[out]  result          Pointer to output data buffer
         * @param[out]  result_size     Pointer to output size buffer
         * @param[in]   depth           Depth value, should be 0
         */
        void show_commands(ConfigItem* _definition,  unsigned char* result, int* result_size, int depth);

        /**
         * Print commands needed to recreate current configuration data contents
         * @param[in]   _definition     Pointer to configuration data contents
         * @param[in]   depth           Depth value, should be 0
         * @param[in]   ncurses         If ncurses flag is set, use ncurses library for output
         */
        void show_commands(ConfigItem* _definition, int depth, bool ncurses);

        /**
         * Print commands needed to recreate current configuration data contents to virtual window
         * @param[in]   _definition     Pointer to configuration data contents
         * @param[in]   depth           Depth value, should be 0
         * @param[out]  win             Pointer to output window
         */
        void show_commands(ConfigItem* _definition, int depth, WINDOW* win);

        /**
         * Print commands needed to recreate current configuration data contents to string stream
         * @param[in]   _definition     Pointer to configuration data contents
         * @param[in]   depth           Depth value, should be 0
         * @param[out]  out_stream      Pointer to string stream
         */
        void show_commands(ConfigItem* _definition, int depth, std::stringstream* out_stream);

        /**
         * Get line count of commands needed to generate current configuration
         * @param[in]   _contents       Pointer to configuration data contents
         * @return      Number of commands needed to generate current configuration
         */
        int get_commands_lc(ConfigItem* _definition);

        /**
         * Print configuration definition using ncurses library
         * @param[in]   show_val        If set, show node value
         * @param[in]   show_desc       If set, show node description
         * @param[in]   def             Pointer to configuration definition
         * @param[in]   level           Starting level, should be 0
         * @param[in]   max_levels      Max level, should be 1
         */
        void print_cfg_def(bool show_val, bool show_desc, ConfigItem* def, int level, int max_levels);

        /**
         * Print configuration definition to virtual ncurses window
         * @param[in]   show_val        If set, show node value
         * @param[in]   show_desc       If set, show node description
         * @param[in]   def             Pointer to configuration definition
         * @param[in]   level           Starting level, should be 0
         * @param[in]   max_levels      Max level, should be 1
         * @param[out]  win             Pointer to output window
         */
        void print_cfg_def(bool show_val, 
                           bool show_desc, 
                           ConfigItem* def, 
                           int level, 
                           int max_levels, 
                           WINDOW* win);

        /**
         * Auto complete method
         * @param[in,out]       mode                Pointer to current configuration mode
         * @param[in]           ac_mode             Pointer to current auto complete mode
         * @param[in]           def                 Pointer to configuration definition
         * @param[in]           _current_def_path   Pointer to current configuration definition path
         * @param[in]           line                Pointer to string array containing line tokens
         * @param[in]           line_size           Size of string array containing line tokens
         * @param[out]          result              Pointer to output result
         * @param[out]          result_size         Pointer to output result size buffer
         * @param[out]          last_found          Pointer to last perfectly matched token
         * @param[out]          error_count         Pointer to error count buffer
         * @param[out]          error_result        Pointer to output error result
         * @param[int]          pretend             If True, do not change any values or states
         * @param[out]          tmp_node_lst        Pointer to temporary output result, all included items
         *                                          should be deallocated when this method returns
         *
         */
        void auto_complete(ConfigModeType* mode,
                           ConfigACMode ac_mode,
                           ConfigItem* def,
                           ConfigItem* _current_def_path,
                           std::string* line,
                           int line_size,
                           ConfigItem* result,
                           int* result_size,
                           ConfigItem** last_found,
                           int* error_count,
                           std::string* error_result,
                           bool pretend,
                           ConfigItem* tmp_node_lst);

        /**
         * Search configuration definition
         * @param[in]           def             Pointer to configuration definition
         * @param[in]           current_level   Current level, should be 0
         * @param[in]           target_level    Target level, should be 0
         * @param[in]           target          Pointer to needle string
         * @param[out]          result          Pointer to output result buffer
         *
         */
        void search_definition(ConfigItem* def, 
                               int current_level, 
                               int target_level, 
                               std::string* target, 
                               ConfigItem* result);

        /**
         * Auto complete file system path
         * @param[in]           path            Pointer to string containing full or partial path
         * @param[out]          result          Pointer to output result buffer
         *
         */
        void search_fsys(std::string* path, ConfigItem* result);

        /**
         * Copy nodes from source to destination
         * @param[in]           source          Pointer to source tree
         * @param[out]          dest            Pointer to output destination tree
         * @param[in]           new_state       State of new nodes
         */
        void copy_nodes(ConfigItem* source, ConfigItem* dest, ConfigNodeState new_state = CONFIG_NS_UNKNOWN);

        /**
         * Generate current working node path
         * @param[in]           def             Pointer to source tree
         * @param[out]          result          Pointer to output destination tree
         *
         */
        void generate_path(ConfigItem* def, std::string* result);

        /**
         * Commit changes
         * @param[in]           _definition     Pointer to configuration definition
         * @param[in]           pretend         If set, commit will be simulated
         * @return              Number of changes required by commit action
         *
         */
        int commit(ConfigItem* _definition, bool pretend);

        int sort(ConfigItem* _definition);

        /**
         * Discard changes
         * @param[in]           _definition     Pointer to configuration definition
         *
         */
        void discard(ConfigItem* _definition);

        /**
         * Get configuration definition root node
         * @return              Pointer to configuration definition root node
         */
        ConfigItem* get_definition_root();

        /**
         * Get configuration definition working node
         * @return              Pointer to configuration definition working node
         *
         */
        ConfigItem* get_definition_wn();

        /**
         * Set configuration definition working node
         * @param[in]           _def_node   Pointer to current working node
         */
        void set_definition_wn(ConfigItem* _def_node);

        /**
         * Get root level configuration command tree
         * @return              Pointer to command tree
         */
        ConfigItem* get_cmd_tree();

        /**
         * Get configuration definition working node for specific user
         * @param[in]           _usr_id	    User id
         * @return              Pointer to user information
         *
         */
        UserInfo* get_definition_wn(const UserId* _usr_id);

        /**
         * Get pointer to a list of user specific configuration paths
         * @return              Pointer to a list of user specific configuration paths
         */
        std::map<UserId, UserInfo*, UserIdCompare>* get_usr_path_map();

        /**
         * Set configuration definition working node for specific user
         * @param[in]           _usr_id     User id
         * @param[in]           _usr_info   Pointer to user info
         *
         */
        void set_definition_wn(const UserId* _usr_id, UserInfo* _usr_info);

        /**
         * Update user info timestamp or create new user
         * @param[in]           _usr_id     User id
         *
         */
        void update_definition_wn(const UserId* _usr_id);

        /**
         * Set all user configuration definition working nodes to root
         *
         */
        void reset_all_wns();

        /**
         * Remove user from active user list
         * @param[in]           _usr_id     User id
         *
         */
        void remove_wn_user(const UserId* _usr_id);

        /**
         * Find needle node in stack of nodes
         * @param[in]           _needle     Node to find
         * @param[in]           _stack      Nodes to search through
         * @return              Pointer to needle node or nullptr if not found
         *
         */
        ConfigItem* find_node(ConfigItem* _needle, ConfigItem* _stack);



    private:
        /** Mutex for multi threaded access */
        pthread_mutex_t mtx_config;
        /** Mutex attributes for multi threaded access */
        pthread_mutexattr_t mtx_config_attr;
        /** Pointer to current configuration definition */
        ConfigItem* definition;
        /** Pointer to current configuration definition working node */
        ConfigItem* current_def_path;
        /** List of configuration data patterns */
        std::vector<CFGPattern*> patterns;
        /** Pointer to top level command tree */
        ConfigItem* cmd_tree;
        /** List of user specific configuration paths */
        std::map<UserId, UserInfo*, UserIdCompare> usr_path_map;
        /** Transaction indicator */
        bool transaction;
        /** Transaction owner id */
        UserId transaction_owner;
        /** List of configuration notifications */
        std::vector<CfgNotification*> notifications;
    };

}


#endif /* MINK_CONFIG_H_ */
