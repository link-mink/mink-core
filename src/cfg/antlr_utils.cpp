/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include<antlr_utils.h>
using namespace std;


antlr::MinkParser::MinkParser(){
    input = NULL;
    tstream = NULL;
    parser = NULL;
    lexer = NULL;

}
antlr::MinkParser::~MinkParser(){
    // free input stream
    if(tstream != NULL){
        tstream->free(tstream);
        tstream = NULL;

    }

    if(input != NULL){
        input->close(input);
        input = NULL;

    }

    if(lexer != NULL){
        lexer->free(lexer);
        lexer = NULL;

    }

    if(parser != NULL){
        parser->free(parser);
        parser = NULL;

    }
}


// process pattern block (cfg)
void antlr::cfg_process_pattern_block(pANTLR3_BASE_TREE tmp_ast, config::Config* cfg){
    pANTLR3_BASE_TREE tmp_ci;
    string tmp_str;
    config::CFGPattern* cfg_ptrn = new config::CFGPattern();

    // pattern name
    tmp_ci = (pANTLR3_BASE_TREE)tmp_ast->children->get(tmp_ast->children, 0);
    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
    // remove double quotes
    tmp_str.erase(remove(tmp_str.begin(), tmp_str.end(), '"' ), tmp_str.end());
    cfg_ptrn->name = tmp_str;

    // patern regex
    tmp_ci = (pANTLR3_BASE_TREE)tmp_ast->children->get(tmp_ast->children, 1);
    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
    // remove PTRN quotes
    tmp_str.erase(tmp_str.begin(), tmp_str.begin() + 4);
    tmp_str.erase(tmp_str.end() - 4, tmp_str.end());
    cfg_ptrn->pattern = tmp_str;

    // description
    tmp_ci = (pANTLR3_BASE_TREE)tmp_ast->children->get(tmp_ast->children, 2);
    if(tmp_ci->children != NULL){
        if(tmp_ci->children->count > 0){
            // description string
            tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
            tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
            // remove double quotes
            tmp_str.erase(tmp_str.begin(), tmp_str.begin() + 1);
            tmp_str.erase(tmp_str.end() - 1, tmp_str.end());
            // set
            cfg_ptrn->desc = tmp_str;

        }
    }



    // add to list
    cfg->add_pattern(cfg_ptrn);

}


// process pattern block (cli)
void antlr::cli_process_pattern_block(pANTLR3_BASE_TREE tmp_ast, cli::CLIService* cli_service){
    pANTLR3_BASE_TREE tmp_ci;
    string tmp_str;
    cli::CLIPattern* cli_ptrn = new cli::CLIPattern();

    // pattern name
    tmp_ci = (pANTLR3_BASE_TREE)tmp_ast->children->get(tmp_ast->children, 0);
    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
    // remove double quotes
    tmp_str.erase(remove(tmp_str.begin(), tmp_str.end(), '"' ), tmp_str.end());
    cli_ptrn->name = tmp_str;

    // patern regex
    tmp_ci = (pANTLR3_BASE_TREE)tmp_ast->children->get(tmp_ast->children, 1);
    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
    // remove PTRN quotes
    tmp_str.erase(tmp_str.begin(), tmp_str.begin() + 4);
    tmp_str.erase(tmp_str.end() - 4, tmp_str.end());
    cli_ptrn->pattern = tmp_str;

    // add to list
    cli_service->add_pattern(cli_ptrn);


}
// process config block (config def)
void antlr::process_config_block(pANTLR3_BASE_TREE tmp_ast, 
                                 config::ConfigItem* tmp_cfg, 
                                 bool is_definition){
    int n2 = tmp_ast->children->count;
    pANTLR3_BASE_TREE tmp_ci;
    string tmp_str;
    for(int j = 0; j<n2; j++){
        tmp_ci = (pANTLR3_BASE_TREE)tmp_ast->children->get(tmp_ast->children, j);
        tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
        // id/name
        if(tmp_str == "ITEM_ID"){
            if(tmp_ci->children != NULL){
                if(tmp_ci->children->count > 0){
                    tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
                    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                    tmp_cfg->name = tmp_str;
                    // special sort flag
                    if(tmp_str.substr(0, 3) == "/S/"){
                        tmp_cfg->name = tmp_str.substr(3);
                        tmp_cfg->sort_node = tmp_cfg;

                    }

                    // check template node flag
                    tmp_ci = tmp_ci->getParent(tmp_ci);
                    if(tmp_ci->children->count > 1){
                        tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 1);
                        tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                        tmp_cfg->is_template = (tmp_str == "*");
                    }

                }

            }
            // type
        }else if(tmp_str == "ITEM_TYPE"){
            if(tmp_ci->children != NULL){
                if(tmp_ci->children->count > 0){
                    tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
                    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                    // remove double quotes
                    tmp_str.erase(remove(tmp_str.begin(), tmp_str.end(), '"' ), tmp_str.end());
                    if(is_definition){
                        tmp_cfg->type = tmp_str;

                    }else{
                        tmp_cfg->value = tmp_str;
                        tmp_cfg->new_value = tmp_str;

                    }

                    if(tmp_str == "CONST") tmp_cfg->node_type = config::CONFIG_NT_BLOCK;
                    else {
                        if(!tmp_cfg->is_template) tmp_cfg->node_type = config::CONFIG_NT_ITEM;
                    }

                }
            }
            // description
        }else if(tmp_str == "ITEM_DESC"){
            if(tmp_ci->children != NULL){
                if(tmp_ci->children->count > 0){
                    tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
                    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                    // remove double quotes
                    tmp_str.erase(remove(tmp_str.begin(), tmp_str.end(), '"' ), tmp_str.end());
                    tmp_cfg->desc = tmp_str;
                }
            }
            // item
        }else if(tmp_str == "CONFIG_ITEM" || tmp_str == "CONFIG_BLOCK"){
            config::ConfigItem* new_cfg = new config::ConfigItem();
            new_cfg->node_type = config::CONFIG_NT_BLOCK;
            process_config_block(tmp_ci, new_cfg, is_definition);
            new_cfg->parent = tmp_cfg;
            tmp_cfg->children.push_back(new_cfg);

            // sort check
            if(new_cfg->sort_node != NULL && tmp_cfg->is_template){
                tmp_cfg->sort_node = new_cfg->sort_node;
                new_cfg->sort_node = NULL;
            }

            // check for special empty template block node
            if(tmp_cfg->is_template &&
                    tmp_cfg->children.size() > 0 &&
                    tmp_cfg->children[0]->name == "...") {
                tmp_cfg->children[0]->name = "";
                tmp_cfg->is_empty = true;
            }


        }

    }
}


// process config block (cli)
void antlr::process_config_block(pANTLR3_BASE_TREE tmp_ast, cli::CLIItem* tmp_cli){
    int n2 = tmp_ast->children->count;
    pANTLR3_BASE_TREE tmp_ci;
    string tmp_str;

    for(int j = 0; j<n2; j++){
        tmp_ci = (pANTLR3_BASE_TREE)tmp_ast->children->get(tmp_ast->children, j);
        tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
        // id/name
        if(tmp_str == "ITEM_ID"){
            if(tmp_ci->children != NULL){
                if(tmp_ci->children->count > 0){
                    tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
                    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                    tmp_cli->name = tmp_str;
                }
            }
            // type
        }else if(tmp_str == "ITEM_TYPE"){
            if(tmp_ci->children != NULL){
                if(tmp_ci->children->count > 0){
                    tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
                    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                    // remove double quotes
                    tmp_str.erase(remove(tmp_str.begin(), tmp_str.end(), '"' ), tmp_str.end());
                    tmp_cli->type = tmp_str;

                    if(tmp_str == "METHOD") tmp_cli->node_type = cli::CLI_METHOD;
                    else if(tmp_str == "SCRIPT") tmp_cli->node_type = cli::CLI_SCRIPT;
                    else if(tmp_str == "CONST") tmp_cli->node_type = cli::CLI_CONST;
                    else tmp_cli->node_type = cli::CLI_PARAM;

                    // script/module param
                    if(tmp_cli->node_type == cli::CLI_SCRIPT || 
                       tmp_cli->node_type == cli::CLI_METHOD || 
                       tmp_cli->node_type == cli::CLI_CONST){
                        if(tmp_ci->children != NULL){
                            if(tmp_ci->children->count > 0){
                                tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
                                tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                                // remove double quotes
                                tmp_str.erase(remove(tmp_str.begin(), tmp_str.end(), '"' ), tmp_str.end());
                                // set script/module path
                                tmp_cli->script_path = tmp_str;
                            }

                        }

                    }
                }
            }
            // description
        }else if(tmp_str == "ITEM_DESC"){
            if(tmp_ci->children != NULL){
                if(tmp_ci->children->count > 0){
                    tmp_ci = (pANTLR3_BASE_TREE)tmp_ci->children->get(tmp_ci->children, 0);
                    tmp_str = (char*)tmp_ci->toString(tmp_ci)->chars;
                    // remove double quotes
                    tmp_str.erase(remove(tmp_str.begin(), tmp_str.end(), '"' ), tmp_str.end());
                    tmp_cli->desc = tmp_str;

                }
            }
            // item
        }else if(tmp_str == "CONFIG_ITEM" || tmp_str == "CONFIG_BLOCK"){
            cli::CLIItem* new_cli = new cli::CLIItem();
            process_config_block(tmp_ci, new_cli);
            new_cli->parent = tmp_cli;
            tmp_cli->children.push_back(new_cli);

        }
    }
}

// process config patterns
void antlr::config_process_patterns(pANTLR3_BASE_TREE p_ast_tree, config::Config* cfg){
    // build cli
    pANTLR3_BASE_TREE tmp_tree = NULL;
    string tmp_str;
    // node name/value
    // children
    if(p_ast_tree->children != NULL){
        // child count
        int n = p_ast_tree->children->size(p_ast_tree->children);
        for(int i = 0; i<n; i++){
            tmp_tree = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
            tmp_str = (char*)tmp_tree->toString(tmp_tree)->chars;
            if(tmp_str == "TYPE_ROOT"){
                antlr::build_pattern_tree(tmp_tree, cfg);
                break;
            }

        }
    }

}


// process cli patterns
void antlr::cli_process_patterns(pANTLR3_BASE_TREE p_ast_tree, cli::CLIService* cli_service){
    // build cli
    pANTLR3_BASE_TREE tmp_tree = NULL;
    string tmp_str;
    // node name/value
    // children
    if(p_ast_tree->children != NULL){
        // child count
        int n = p_ast_tree->children->size(p_ast_tree->children);
        for(int i = 0; i<n; i++){
            tmp_tree = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
            tmp_str = (char*)tmp_tree->toString(tmp_tree)->chars;
            if(tmp_str == "TYPE_ROOT"){
                antlr::build_pattern_tree(tmp_tree, cli_service);
                break;
            }


        }
    }

}

// process config
void antlr::process_config(pANTLR3_BASE_TREE p_ast_tree, config::ConfigItem* config_tree_res){
    // build cli
    pANTLR3_BASE_TREE tmp_tree = NULL;
    string tmp_str;
    // node name/value
    // children
    tmp_str = (char*)p_ast_tree->toString(p_ast_tree)->chars;
    if(tmp_str == "CONFIG_ROOT"){
        config_tree_res->name = "ROOT";
        config_tree_res->node_type = config::CONFIG_NT_BLOCK;
        antlr::build_config_def_tree(p_ast_tree, config_tree_res, false);

    }else{
        if(p_ast_tree->children != NULL){
            // child count
            int n = p_ast_tree->children->count;
            for(int i = 0; i<n; i++){
                tmp_tree = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
                tmp_str = (char*)tmp_tree->toString(tmp_tree)->chars;
                if(tmp_str == "CONFIG_ROOT"){
                    config_tree_res->name = "ROOT";
                    config_tree_res->node_type = config::CONFIG_NT_BLOCK;
                    antlr::build_config_def_tree(tmp_tree, config_tree_res, false);
                    break;
                }


            }
        }

    }




}


// process config defintion
void antlr::process_config_def(pANTLR3_BASE_TREE p_ast_tree, config::ConfigItem* config_tree_res){
    // build cli
    pANTLR3_BASE_TREE tmp_tree = NULL;
    string tmp_str;
    // node name/value
    // children
    tmp_str = (char*)p_ast_tree->toString(p_ast_tree)->chars;
    if(tmp_str == "CONFIG_ROOT"){
        config_tree_res->name = "ROOT";
        config_tree_res->node_type = config::CONFIG_NT_BLOCK;
        antlr::build_config_def_tree(p_ast_tree, config_tree_res, true);

    }else{
        if(p_ast_tree->children != NULL){
            // child count
            int n = p_ast_tree->children->size(p_ast_tree->children);
            for(int i = 0; i<n; i++){
                tmp_tree = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
                tmp_str = (char*)tmp_tree->toString(tmp_tree)->chars;
                if(tmp_str == "CONFIG_ROOT"){
                    config_tree_res->name = "ROOT";
                    config_tree_res->node_type = config::CONFIG_NT_BLOCK;
                    antlr::build_config_def_tree(tmp_tree, config_tree_res, true);
                    break;
                }


            }
        }

    }


}


// process cli config
void antlr::cli_process_config(pANTLR3_BASE_TREE p_ast_tree, cli::CLIItem* cli_tree_res){
    // build cli
    pANTLR3_BASE_TREE tmp_tree = NULL;
    string tmp_str;
    // node name/value
    tmp_str = (char*)p_ast_tree->toString(p_ast_tree)->chars;
    if(tmp_str == "CONFIG_ROOT"){
        cli_tree_res->name = "ROOT";
        cli_tree_res->node_type = cli::CLI_CONST;
        antlr::build_cli_tree(p_ast_tree, cli_tree_res);

    }else{
        // children
        if(p_ast_tree->children != NULL){
            // child count
            int n = p_ast_tree->children->size(p_ast_tree->children);
            for(int i = 0; i<n; i++){
                tmp_tree = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
                tmp_str = (char*)tmp_tree->toString(tmp_tree)->chars;
                if(tmp_str == "CONFIG_ROOT"){
                    cli_tree_res->name = "ROOT";
                    cli_tree_res->node_type = cli::CLI_CONST;
                    antlr::build_cli_tree(tmp_tree, cli_tree_res);
                    break;
                }

            }
        }

    }

}

// build pattern tree (config)
void antlr::build_pattern_tree(pANTLR3_BASE_TREE p_ast_tree, config::Config* cfg){
    pANTLR3_BASE_TREE tmp_ast;
    string tmp_str;

    if(p_ast_tree->children != NULL){
        // child count
        int n = p_ast_tree->children->size(p_ast_tree->children);
        for(int i = 0; i<n; i++){
            tmp_ast = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
            tmp_str = (char*)tmp_ast->toString(tmp_ast)->chars;
            if(tmp_str == "TYPE_ITEM"){
                cfg_process_pattern_block(tmp_ast, cfg);
            }

        }
    }
}


// build pattern tree (cli)
void antlr::build_pattern_tree(pANTLR3_BASE_TREE p_ast_tree, cli::CLIService* cli_service){
    pANTLR3_BASE_TREE tmp_ast;
    string tmp_str;

    if(p_ast_tree->children != NULL){
        // child count
        int n = p_ast_tree->children->size(p_ast_tree->children);
        for(int i = 0; i<n; i++){
            tmp_ast = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
            tmp_str = (char*)tmp_ast->toString(tmp_ast)->chars;
            if(tmp_str == "TYPE_ITEM"){
                cli_process_pattern_block(tmp_ast, cli_service);
            }

        }
    }

}
// build confif def tree
void antlr::build_config_def_tree(pANTLR3_BASE_TREE p_ast_tree, 
                                  config::ConfigItem* config_tree, 
                                  bool is_definition){
    config::ConfigItem* tmp_cfg;
    pANTLR3_BASE_TREE tmp_ast;
    string tmp_str;

    if(p_ast_tree->children != NULL){
        // child count
        int n = p_ast_tree->children->size(p_ast_tree->children);
        for(int i = 0; i<n; i++){
            tmp_ast = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
            tmp_str = (char*)tmp_ast->toString(tmp_ast)->chars;
            if(tmp_str == "CONFIG_ITEM" || tmp_str == "CONFIG_BLOCK"){
                tmp_cfg = new config::ConfigItem();
                tmp_cfg->node_type = config::CONFIG_NT_BLOCK;
                process_config_block(tmp_ast, tmp_cfg, is_definition);
                tmp_cfg->parent = config_tree;
                config_tree->children.push_back(tmp_cfg);

                // sort check
                if(tmp_cfg->sort_node != NULL && config_tree->is_template){
                    config_tree->sort_node = tmp_cfg->sort_node;
                    tmp_cfg->sort_node = NULL;
                }

                // check for special empty template block node
                if(tmp_cfg->is_template &&
                        tmp_cfg->children.size() > 0 &&
                        tmp_cfg->children[0]->name == "...") {
                    tmp_cfg->children[0]->name = "";
                    tmp_cfg->is_empty = true;
                }

            }

        }
    }

}


// build cli tree
void antlr::build_cli_tree(pANTLR3_BASE_TREE p_ast_tree, cli::CLIItem* cli_tree){
    pANTLR3_BASE_TREE tmp_ast;
    string tmp_str;

    if(p_ast_tree->children != NULL){
        // child count
        int n = p_ast_tree->children->size(p_ast_tree->children);
        for(int i = 0; i<n; i++){
            tmp_ast = (pANTLR3_BASE_TREE)p_ast_tree->children->get(p_ast_tree->children, i);
            tmp_str = (char*)tmp_ast->toString(tmp_ast)->chars;
            if(tmp_str == "CONFIG_ITEM" || tmp_str == "CONFIG_BLOCK"){
                cli::CLIItem* tmp_cli = new cli::CLIItem();
                process_config_block(tmp_ast, tmp_cli);
                tmp_cli->parent = cli_tree;
                cli_tree->children.push_back(tmp_cli);

            }

        }
    }

}
// print ast tree
void antlr::print_tree(pANTLR3_BASE_TREE tree, int depth){
    pANTLR3_BASE_TREE tmp_tree;
    // padding
    for(int i = 0; i<depth; i++) cout << "  ";
    // node name/value
    cout << tree->toString(tree)->chars << endl;
    // children
    if(tree->children != NULL){
        // child count
        int n = tree->children->size(tree->children);
        for(int i = 0; i<n; i++){
            tmp_tree = (pANTLR3_BASE_TREE)tree->children->get(tree->children, i);
            // print
            print_tree(tmp_tree, depth + 1);
        }
    }

}
void antlr::no_error_report (pANTLR3_BASE_RECOGNIZER recognizer, pANTLR3_UINT8 * tokenNames) {
    // no errors reported to stdout
}

// tokenize line, reuse
void antlr::parse_line(string* data, 
                       string* result, 
                       int result_max_size, 
                       int* result_size, 
                       void* parser_info){
    parse_line(data, result, result_max_size, result_size, (MinkParser*)parser_info);
}


// tokenize line, reuse
void antlr::parse_line(string* data, 
                       string* result, 
                       int result_max_size, 
                       int* result_size, 
                       MinkParser* parser_info){
    if(parser_info == NULL) return;

    pANTLR3_BASE_TREE tmp_tree = NULL;
    string tmp_str;

    // reset error state
    parser_info->lexer->pLexer->rec->state->errorCount = 0;
    parser_info->parser->pParser->rec->state->errorCount = 0;

    // input stream
    parser_info->input->reuse(parser_info->input, 
                              (unsigned char*)data->c_str(), 
                              data->size(), 
                              (unsigned char*)"line_stream");

    // token stream
    parser_info->tstream->reset(parser_info->tstream);

    // parse and build ast
    minkParser_lineParser_return ast = parser_info->parser->lineParser(parser_info->parser);
    // err check
    int err_c = parser_info->lexer->pLexer->rec->getNumberOfSyntaxErrors(parser_info->lexer->pLexer->rec);
    err_c += parser_info->parser->pParser->rec->getNumberOfSyntaxErrors(parser_info->parser->pParser->rec);

    *result_size = 0;
    //print_tree(ast.tree, 0);
    if(err_c == 0 && ast.tree != NULL){
        if(ast.tree->children != NULL){
            // child count
            int n = ast.tree->children->size(ast.tree->children);
            for(int i = 0; i<n; i++){
                // check buffer
                if(*result_size >= result_max_size) return;
                // inc result size
                (*result_size)++;
                // get node value
                tmp_tree = (pANTLR3_BASE_TREE)ast.tree->children->get(ast.tree->children, i);
                tmp_str = (char*)tmp_tree->toString(tmp_tree)->chars;
                // result
                result[i] = tmp_str;
            }
        }

    }


}


antlr::MinkParser* antlr::create_parser(){
    MinkParser* pp = new MinkParser();
    // input stream
    pp->input = antlr3StringStreamNew((unsigned char*)"", ANTLR3_ENC_8BIT, 0, (unsigned char*)"line_stream");
    // lexer
    pp->lexer = minkLexerNew(pp->input);
    // no lexer error reporting
    pp->lexer->pLexer->rec->displayRecognitionError = &no_error_report;
    // token stream
    pp->tstream = antlr3CommonTokenStreamSourceNew(ANTLR3_SIZE_HINT, TOKENSOURCE(pp->lexer));
    // create parser
    pp->parser = minkParserNew(pp->tstream);
    // no parser error reporting
    pp->parser->pParser->rec->displayRecognitionError = &no_error_report;

    return pp;
}

// tokenize line
void antlr::parse_line(string* data, string* result, int result_max_size, int* result_size){
    pANTLR3_BASE_TREE tmp_tree = NULL;
    string tmp_str;


    // input stream
    pANTLR3_INPUT_STREAM input = antlr3StringStreamNew((unsigned char*)data->c_str(), 
                                                       ANTLR3_ENC_8BIT, 
                                                       data->size(), 
                                                       (unsigned char*)"line_stream");
    // lexer
    pminkLexer lexer = minkLexerNew(input);
    // no error reporting
    lexer->pLexer->rec->displayRecognitionError = &no_error_report;
    // token stream
    pANTLR3_COMMON_TOKEN_STREAM tstream = antlr3CommonTokenStreamSourceNew(ANTLR3_SIZE_HINT, 
                                                                           TOKENSOURCE(lexer));
    // create parser
    pminkParser parser = minkParserNew(tstream);
    // no error reporting
    parser->pParser->rec->displayRecognitionError = &no_error_report;
    // parse and build ast
    minkParser_lineParser_return ast = parser->lineParser(parser);
    // err check
    int err_c = lexer->pLexer->rec->getNumberOfSyntaxErrors(lexer->pLexer->rec);
    err_c += parser->pParser->rec->getNumberOfSyntaxErrors(parser->pParser->rec);


    *result_size = 0;
    //print_tree(ast.tree, 0);
    if(err_c == 0 && ast.tree != NULL){
        if(ast.tree->children != NULL){
            // child count
            int n = ast.tree->children->size(ast.tree->children);
            for(int i = 0; i<n; i++){
                // check buffer
                if(*result_size >= result_max_size) return;
                // inc result size
                (*result_size)++;
                // get node value
                tmp_tree = (pANTLR3_BASE_TREE)ast.tree->children->get(ast.tree->children, i);
                tmp_str = (char*)tmp_tree->toString(tmp_tree)->chars;
                // result
                result[i] = tmp_str;
            }
        }

    }


    // free input stream
    tstream->free(tstream);
    tstream = NULL;

    input->close(input);
    input = NULL;

    lexer->free(lexer);
    lexer = NULL;

    parser->free(parser);
    parser = NULL;


}


void antlr::free_mem(void* parser_info){
    if(parser_info != NULL){
        MinkParser* mink_parser = (MinkParser*)parser_info;
        delete mink_parser;

    }
}


