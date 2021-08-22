/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef CLI_H_
#define CLI_H_

#include <string>
#include <iostream>
#include <vector>
#include <signal.h>

using namespace std;

/**
 * CTRL + character macro
 */
#define CTRL(c) ((c) & 037)

namespace cli {
    /**
     * CLI Common node type
     */
    enum CLINodeType {
        /** Constant node (group) */
        CLI_CONST       = 0x01,
        /** External plugin method */
        CLI_METHOD      = 0x02,
        /** External script */
        CLI_SCRIPT      = 0x03,
        /** Script or method parameter */
        CLI_PARAM       = 0x04,
        /** Unknown */
        CLI_UNKNOWN     = -1
    };

    /**
     * CLI State
     */
    enum CLIState {
        /** Unknown */
        CLI_ST_UNKNOWN          = -1,
        /** Execute command mode (ENTER) */
        CLI_ST_EXECUTE          = 0,
        /** Auto completion mode (TAB) */
        CLI_ST_AUTO_COMPLETE    = 1
    };

    /**
     * CLI Pattern (regex)
     */
    class CLIPattern {
    public:
        /** Pattern name */
        string name;
        /** Pattern regex */
        string pattern;
    };

    /**
     * CLI Item
     */
    class CLIItem {
    public:
        CLIItem();
        ~CLIItem();
        /** Parent node */
        CLIItem* parent;
        /** Common node type (user defined types NOT INCLUDED */
        CLINodeType node_type;
        /** Node name */
        string name;
        /** External script or plugin path */
        string script_path;
        /** Original node type (user defined types INCLUDED) */
        string type;
        /** Node description */
        string desc;
        /** Child nodes */
        vector<CLIItem*> children;
        /** Param set flag, used only by CLI_PARAM nodes */
        bool is_set;
        /** Param value, used only by CLI_PARAM nodes */
        string param_value;
    };

    /**
     * CLI Service
     */
    class CLIService {
    public:
        CLIService();
        ~CLIService();

        /**
         * Set CLI definition source
         * @param[in]   cli_tree    Pointer to CLI definition
         */
        void set_cli_tree(CLIItem* cli_tree);

        /**
         * Start CLI interface loop
         */
        void start();

        /**
         * Add new CLI pattern to list of active patterns
         * @param[in]   ptrn        Pointer to pattern descriptor
         */
        void add_pattern(CLIPattern* ptrn);

        /**
         * Validate parameter value
         * @param[in]   param_value     Pointer to parameter value
         * @param[in]   param_type      Pointer to parameter type
         * @return      True if parameter if valid or False otherwise
         */
        bool param_valid(string* param_value, string* param_type);

        /**
         * Set initial welcome message
         * @param[in]   _info_msg       Pointer to message string
         */
        void set_info_msg(const char* _info_msg);

        /**
         * Get pattern for specific type of parameter
         * @param[in]   type            Pointer to parameter type string
         * @return      Pointer to pattern descriptor or NULL if not found
         */
        CLIPattern* get_pattern(string* type);

        /**
         * Print formatted CLI definition tree
         * @param[in]   tree            Pointer to CLI definition
         * @param[in]   depth           Initial depth value, should be 0
         */
        static void print_cli_tree(cli::CLIItem* tree, int depth);

        /**
         * Generate prompt string
         */
        void generate_prompt();

        /**
         * Add current line to history list
         * @param[in]       _line       Pointer to string containing command line data
         */
        void add_to_history(string* _line);

        /**
         * Get size of history list
         * @return          Size of history list
         */
        int get_historu_size();

        /**
         * Get current line
         * @return          _line       Pointer to current line string
         */
        std::string* get_current_line();

        /**
         * Clear current line
         */
        void clear_curent_line();

        /**
         * Get current prompt
         * @return          _line       Pointer to current prompt string
         */
        std::string* get_prompt();

        /**
         * Generate path string
         * @param[in]       def         Pointer to CLI definition of node
         *                              currently located in
         * @param[out]      result      Pointer to result string
         */
        void generate_path(CLIItem* def, std::string* result);

        /**
         * Get current path string string
         * @return          Pointer to current path string
         */
        std::string* get_current_path_line();

        /**
         * Get CLI service id
         * @return          Pointer to current id string
         */
        std::string* get_id();

        /**
         * Set CLI service id
         * @param[in]       _id         Pointer to new id string
         */
        void set_id(std::string* _id);

        /**
         * Signal handler (CTRL + C)
         * @param[in]       signum      Signal code
         */
        static void signal_handler(int signum);

        /**
         * Get current path
         * @return          Pointer to current path
         */
        cli::CLIItem* get_current_path();

        bool toggle_interrupt();
        bool get_interrupt();
        void set_interrupt(bool _val);
        bool* get_interrupt_p();

        /** Maximum number of history lines */
        unsigned int max_history;
        /** Current history index */
        unsigned int history_index;
        /** Current CLI state */
        CLIState state;
        /** Current use input */
        string current_line;
        /** Command line arguments */
        char** cmdl_argv;
        /** Command line argument count */
        int cmdl_argc;
        /** SIGINT flag */
        bool interrupt;
        /** Buffered/interrupted character */
        int buff_ch;

        /**
         * Current CLI Service pointer
         */
        static CLIService* CURRENT_CLI_SERVICE;

    private:
        /**
         * Initialize colors
         */
        void init_colors();

        /**
         * Print CLI definition help context
         * @param[in]   def             Pointer to CLI definition
         * @param[in]   level           Initial level (usually 0)
         * @param[in]   max_levels      Maximum level (usually 1)
         *
         */
        void print_cli_def(CLIItem* def, int level, int max_levels);

        /**
         * Auto complete user input, generate help context data
         * @param[in]       def         Pointer to CLI definition
         * @param[in,out]   line        Pointer to tokenized user input
         * @param[in]       line_size   Number of tokens contained in user input
         * @param[out]      result      Pointer to CLI output result for help context data
         * @param[out]      result_size Number of perfectly matched tokens
         * @param[out]      last_found  Pointer to last perfectly matched CLI node
         */
        void cli_auto_complete(CLIItem* def,
                               string* line,
                               int line_size,
                               CLIItem* result,
                               int* result_size,
                               CLIItem** last_found);

        /**
         * Search CLI definition for partially matched data
         * @param[in]       def             Pointer to CLI definition
         * @param[in]       current_level   Initial level (usually 0)
         * @param[in]       target_level    Target level (usually 0)
         * @param[in]       target          Pointer to string with data to search for
         * @param[out]      result          Pointer to CLI output result for matched data
         */
        void search_cli_def(CLIItem* def,
                            int current_level,
                            int target_level,
                            string* target,
                            CLIItem* result);

        /** Pointer to CLI config parser */
        void* mink_parser;
        /** Pointer to main CLI definition */
        CLIItem* cli_def;
        /** Pointer to CLI definition of node currently located in */
        CLIItem* current_path;
        /** Current path string (pwd) */
        string current_path_line;
        /** Prompt string */
        string prompt;
        /** Initial welcome message */
        string info_msg;
        /** History list */
        vector<string*> history;
        /** Pattern list */
        vector<CLIPattern*> patterns;
        /** External handler flag (block plugin mode) */
        bool external_handler;
        /** Pointer returned by plugin init method */
        void* external_plugin;
        /** External plugin handle */
        void* external_plugin_handle;
        /** CLI service id */
        std::string cli_id;
    };

}


#endif /* CLI_H_ */
