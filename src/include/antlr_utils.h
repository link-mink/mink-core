/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef ANTLR_UTILS_H_
#define ANTLR_UTILS_H_

#include <iostream>
#include <algorithm>
#include <string>
#include <antlr3.h>
#include <minkLexer.h>
#include <minkParser.h>
#include <cli.h>
#include <mink_config.h>

namespace antlr {
    class MinkParser {
    public:
        MinkParser() = default;
        MinkParser(const MinkParser &o) = delete;
        MinkParser &operator=(const MinkParser &o) = delete;
        ~MinkParser();
        pANTLR3_INPUT_STREAM input = nullptr;
        pANTLR3_COMMON_TOKEN_STREAM tstream = nullptr;
        pminkParser parser = nullptr;
        pminkLexer lexer = nullptr;

    };


    // methods
    MinkParser* create_parser();
    void process_config_block(pANTLR3_BASE_TREE tmp_ast, 
                              cli::CLIItem* tmp_cli);

    void process_config_block(pANTLR3_BASE_TREE tmp_ast, 
                              config::ConfigItem* tmp_cfg, 
                              bool is_definition);

    void cli_process_pattern_block(pANTLR3_BASE_TREE tmp_ast, 
                                   cli::CLIService* cli_service);

    void cfg_process_pattern_block(pANTLR3_BASE_TREE tmp_ast, 
                                   config::Config* cfg);

    void cli_process_config(pANTLR3_BASE_TREE p_ast_tree, 
                            cli::CLIItem* cli_tree_res);

    void process_config_def(pANTLR3_BASE_TREE p_ast_tree, 
                            config::ConfigItem* config_tree_res);

    void process_config(pANTLR3_BASE_TREE p_ast_tree, 
                        config::ConfigItem* config_tree_res);

    void cli_process_patterns(pANTLR3_BASE_TREE p_ast_tree, 
                              cli::CLIService* cli_service);

    void config_process_patterns(pANTLR3_BASE_TREE p_ast_tree, 
                                 config::Config* cfg);

    void build_cli_tree(pANTLR3_BASE_TREE p_ast_tree, 
                        cli::CLIItem* cli_tree);

    void build_config_def_tree(pANTLR3_BASE_TREE p_ast_tree, 
                               config::ConfigItem* config_tree, 
                               bool is_definition);

    void build_pattern_tree(pANTLR3_BASE_TREE p_ast_tree, 
                            config::Config* cli_service);

    void build_pattern_tree(pANTLR3_BASE_TREE p_ast_tree, 
                            cli::CLIService* cli_service);

    void print_tree(pANTLR3_BASE_TREE tree, 
                    int depth);

    void no_error_report(const pANTLR3_BASE_RECOGNIZER recognizer, 
                         pANTLR3_UINT8 * tokenNames);

    void parse_line(const std::string* data, 
                    std::string* result, 
                    int result_max_size, 
                    int* result_size);

    void parse_line(const std::string* data, 
                    std::string* result, 
                    int result_max_size, 
                    int* result_size, 
                    MinkParser* parser_info);

    void free_mem(void* parser_info);
}


#endif /* ANTLR_UTILS_H_ */
