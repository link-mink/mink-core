/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <cli.h>
#include <curses.h>
#include <antlr_utils.h>
#include <mink_utils.h>
#include <mink_dynamic.h>
#include <regex>
#include <dlfcn.h>


// static
cli::CLIService* cli::CLIService::CURRENT_CLI_SERVICE = nullptr;

// CLIItem
cli::CLIItem::~CLIItem(){
    // children
    std::all_of(children.cbegin(), children.cend(), [](CLIItem *c) {
        delete c;
        return true;
    });
    children.clear();
}




cli::CLIService::CLIService(): current_path_line("/"),
                               prompt("<UNDEFINED> ") {
    cli_def = nullptr;
    max_history = 50;
    history_index = -1;
    current_path = nullptr;
    mink_parser = antlr::create_parser();
    external_handler = false;
    external_plugin = nullptr;
    external_plugin_handle = nullptr;
    state = CLI_ST_UNKNOWN;
    info_msg = "Welcome to mINK command-line interface (CLI)";
    cmdl_argc = 0;
    cmdl_argv = nullptr;
    interrupt = false;
    // set static pointer to current instance
    cli::CLIService::CURRENT_CLI_SERVICE = this;
    buff_ch = -1;

}

cli::CLIService::~CLIService(){
    std::all_of(history.cbegin(), history.cend(), [](std::string *s) {
        delete s;
        return true;
    });
    history.clear();

    std::all_of(patterns.cbegin(), patterns.cend(), [](CLIPattern *p) {
        delete p;
        return true;
    });
    patterns.clear();

    // free parser
    antlr::free_mem(mink_parser);
}

std::string* cli::CLIService::get_prompt(){
    return &prompt;
}


void cli::CLIService::clear_curent_line(){
    current_line.clear();
}


std::string* cli::CLIService::get_current_line(){
    return &current_line;
}

std::string* cli::CLIService::get_current_path_line(){
    return &current_path_line;
}

std::string* cli::CLIService::get_id(){
    return &cli_id;
}

void cli::CLIService::set_id(const std::string* _id){
    cli_id = *_id;
}

void cli::CLIService::signal_handler(int signum){
    switch(signum){
        case SIGINT:
            if(CURRENT_CLI_SERVICE != nullptr){
                CURRENT_CLI_SERVICE->set_interrupt(true);
                int y, x;
                getyx(stdscr, y, x);
                move(y, 0);
                clrtoeol();
                printw(CURRENT_CLI_SERVICE->get_prompt()->c_str());
                CURRENT_CLI_SERVICE->clear_curent_line();
                refresh();
            }
            break;
        default:
            break;
    }
}



cli::CLIItem* cli::CLIService::get_current_path(){
    return current_path;
}

bool cli::CLIService::toggle_interrupt(){
    interrupt = !interrupt;
    return interrupt;
}

bool cli::CLIService::get_interrupt() const {
    return interrupt;
}
void cli::CLIService::set_interrupt(bool _val){
    interrupt = _val;
}

bool* cli::CLIService::get_interrupt_p(){
    return &interrupt;
}

void cli::CLIService::print_cli_tree(cli::CLIItem* tree, int depth){
    // padding
    for(int i = 0; i<depth; i++) std::cout << "  ";
    std::cout << tree->name << " - " << tree->type << " - " << tree->desc << std::endl;
    // child count
    int n = tree->children.size();
    for(int i = 0; i<n; i++){
        // print
        print_cli_tree(tree->children[i], depth + 1);
    }

}



void cli::CLIService::set_cli_tree(CLIItem* cli_tree){
    cli_def = cli_tree;
    current_path = cli_def;
}

/**
 * Initialize colors
 */
static void init_colors(void){
    // red fg, transparent bg
    init_pair(1, COLOR_RED, -1);
    // blue fg, transparent bg
    init_pair(2, COLOR_BLUE, -1);
    // white fg, transparent bg
    init_pair(3, COLOR_WHITE, -1);
    // green fg, transparent bg
    init_pair(4, COLOR_GREEN, -1);
    // yellow fg, transparent bg
    init_pair(5, COLOR_YELLOW, -1);
    // cyan fg, transparent bg
    init_pair(6, COLOR_CYAN, -1);
    // magenta fg, transparent bg
    init_pair(7, COLOR_MAGENTA, -1);
    // black fg, white bg
    init_pair(8, COLOR_BLACK, COLOR_WHITE);


}

void cli::CLIService::search_cli_def(CLIItem* def,
                                     int current_level,
                                     int target_level,
                                     std::string* target,
                                     CLIItem* result){
    if((def != nullptr) && (target != nullptr) && (result != nullptr)){
        CLIItem* tmp_ci = nullptr;
        // child count
        int n = def->children.size();
        for(int i = 0; i<n; i++){
            tmp_ci = def->children[i];
            // check if at the right level
            if(current_level != target_level){
                search_cli_def(tmp_ci, current_level + 1, target_level, target, result);
            }else{
                if(tmp_ci->name.compare(0, target->length(), *target) == 0){
                    result->children.push_back(tmp_ci);
                }
            }
        }
    }
}


void cli::CLIService::cli_auto_complete(CLIItem* def,
                                        std::string* line,
                                        int line_size,
                                        CLIItem* result,
                                        int* result_size,
                                        CLIItem** last_found){
    std::string tmp_str;
    if((def != nullptr) && (line != nullptr)){
        // reset result size
        *result_size = 0;
        // check for line tokens
        if(line_size > 0){
            bool param_found = false;
            for(int i = 0; i<line_size; i++){
                // curent line token
                tmp_str = line[i];

                // param value detection, check if previous node type is CLI_PARAM
                if ((*last_found != nullptr) &&
                    ((*last_found)->node_type == cli::CLI_PARAM)) {
                    (*result_size)++;
                    param_found = true;
                    // mark as set
                    (*last_found)->is_set = true;
                    (*last_found)->param_value = tmp_str;
                }

                // clear result for current level
                result->children.clear();
                // search matching nodes if current node is note param value
                if(!param_found) search_cli_def(def, 0, 0, &tmp_str, result);
                // single match
                if(result->children.size() == 1) {
                    // definition found, inc
                    (*result_size)++;
                    *last_found = result->children[0];
                    // if not param, search one level deeper
                    if(result->children[0]->node_type != cli::CLI_PARAM){
                        // go deeper
                        def = result->children[0];
                        *last_found = def;
                        // update line if one and only one match found
                        line[i] = result->children[0]->name;
                        result->children.clear();
                        tmp_str = "";
                        // search available options
                        search_cli_def(def, 0, 0, &tmp_str, result);

                        // if param, update line
                    }else{
                        // update line if one and only one match found
                        line[i] = result->children[0]->name;

                    }

                    // more matches, stop processing
                }else{
                    *last_found = nullptr;
                    // param value
                    if(param_found){
                        param_found = false;
                        tmp_str = "";
                        // display all parameters again
                        search_cli_def(def, 0, 0, &tmp_str, result);
                        // other
                    }else{
                        // if multiple nodes match
                        if(!result->children.empty()){
                            // assume min size of 100
                            unsigned int min_size = 100;
                            // find shortest string
                            for (unsigned int j = 0;
                                 j < result->children.size(); j++)
                                if (result->children[j]->name.size() < min_size)
                                    min_size = result->children[j]->name.size();
                            // set max_match to current min_size
                            unsigned int max_match = min_size;
                            // get common starting substring
                            for(unsigned int j = 1; j<result->children.size(); j++){
                                for(unsigned int k = 0; k<min_size; k++){
                                    if(result->children[j]->name[k] != result->children[0]->name[k]){
                                        if(k < max_match) max_match = k;
                                        break;

                                    }

                                }
                            }

                            // check exact match
                            for(unsigned int j = 0; j<result->children.size(); j++){
                                if(max_match == result->children[j]->name.size()){
                                    *last_found = result->children[j];
                                    break;
                                }

                            }


                            // check for perfect match
                            if((line[i].size() == max_match) && ((*last_found) != nullptr)){
                                // definition found, inc
                                (*result_size)++;
                                result->children.clear();
                                // if group, get children
                                if((*last_found)->node_type == cli::CLI_CONST) {
                                    // search available options
                                    tmp_str = "";
                                    def = *last_found;
                                    search_cli_def(def, 0, 0, &tmp_str, result);
                                    // add single item to result
                                }else{
                                    result->children.push_back(*last_found);

                                }

                                // update current line
                                line[i] = (*last_found)->name;


                                // set current line item to common substring
                            }else{
                                line[i] = result->children[0]->name.substr(0, max_match);

                            }


                        }

                        // if not last item, stop processing when multiple lines match
                        if((i != (line_size - 1)) && (*last_found == nullptr)) return;

                    }
                }

            }
            // no line input, display all zero level options
        }else{
            search_cli_def(def, 0, 0, &tmp_str, result);

        }
    }
}

void cli::CLIService::print_cli_def(CLIItem* def, int level, int max_levels){
    if(def != nullptr){
        // child count
        unsigned int n = def->children.size();
        // find max length
        unsigned int max_length = 0;
        for (unsigned int i = 0; i < n; i++)
            if (def->children[i]->name.size() > max_length)
                max_length = def->children[i]->name.size();
        ++max_length;

        for(unsigned int i = 0; i<n; i++){
            // padding
            switch(def->children[i]->node_type){
                case cli::CLI_CONST: attron(COLOR_PAIR(2)); break;
                case cli::CLI_PARAM: attron(COLOR_PAIR(5)); break;
                default: attron(COLOR_PAIR(4)); break;

            }

            printw("%*s", max_length, def->children[i]->name.c_str());
            if(def->children[i]->is_set){
                attron(COLOR_PAIR(4));
                printw(" ** [");
                printw(def->children[i]->param_value.c_str());
                printw("] ** ");
                attroff(COLOR_PAIR(4));
            }
            if(def->children[i]->desc != ""){
                printw(" - ");
                attrset(A_NORMAL);
                attron(COLOR_PAIR(3));
                printw(def->children[i]->desc.c_str());

            }
            printw("\n");
            attrset(A_NORMAL);

            // next level
            if ((level + 1) < max_levels)
                print_cli_def(def->children[i], level + 1, max_levels);
        }
    }
}

int cli::CLIService::get_historu_size() const {
    return history.size();
}

void cli::CLIService::add_to_history(const std::string* _line){
    if(history.size() < max_history){
        history.push_back(new std::string(*_line));
    }else{
        // move
        for (unsigned int i = 1; i < history.size(); i++)
            *history[i - 1] = *history[i];

        // add new
        *history[history.size() - 1] = *_line;
    }
}


void cli::CLIService::add_pattern(CLIPattern* ptrn){
    patterns.push_back(ptrn);
}


cli::CLIPattern* cli::CLIService::get_pattern(const std::string* type){
    for(unsigned int i = 0; i<patterns.size(); i++){
        if(patterns[i]->name == *type){
            return patterns[i];
        }
    }
    return nullptr;
}
bool cli::CLIService::param_valid(std::string* param_value, const std::string* param_type){
    const cli::CLIPattern* ptrn = get_pattern(param_type);
    if(ptrn != nullptr){
        std::regex regex(ptrn->pattern);
        // remove quotes if necessary
        if(((*param_value)[0] == '"') && ((*param_value)[param_value->size() - 1] == '"')){
            param_value->erase(param_value->begin(), param_value->begin() + 1);
            param_value->erase(param_value->end() - 1, param_value->end());
        }

        return std::regex_match(*param_value, regex);

    }
    return false;
}

void cli::CLIService::generate_prompt(){
    char tmp[100];
    getlogin_r(tmp, 100);
    prompt = tmp;
    gethostname(tmp, 100);
    prompt.append("@");
    prompt.append(tmp);
    prompt.append(":");
    prompt.append(current_path_line.c_str());
    prompt.append(" ");
    prompt.append("> ");

}

void cli::CLIService::generate_path(CLIItem* def, std::string* result){
    if ((def != nullptr) &&
        (result != nullptr) &&
        (def->node_type == cli::CLI_CONST) &&
        (def->parent != nullptr)) {
        *result = "/" + def->name + *result;
        generate_path(def->parent, result);
    }
}

void cli::CLIService::set_info_msg(const char* _info_msg){
    info_msg.clear();
    info_msg.append(_info_msg);

}

void cli::CLIService::start(){
    int tmp_ch, x, y;
    CLIItem tmp_cli_res;
    CLIItem* last_found = nullptr;

    // ncurses init
    initscr();
    start_color();
    use_default_colors();
    noecho();
    cbreak();
    keypad(stdscr, true);
    scrollok(stdscr, true);

    // init colors
    init_colors();

    // set prompt
    generate_prompt();

    getyx(stdscr, y, x);
    move(y, 0);


    // print info message
    printw("%s\n\n", info_msg.c_str());
    // print prompt
    printw(prompt.c_str());


    // loop
    while(true){
        // buffered characted
        if(buff_ch != -1) {
            tmp_ch = buff_ch;
            buff_ch = -1;

        }else{
            // get input
            tmp_ch = getch();

        }

        // TAB - auto complete
        if(tmp_ch == '\t'){
            interrupt = false;

            std::string tmp_lst[50];
            int tmp_size = 0;
            int res_size = 0;

            // move to end of line
            getyx(stdscr, y, x);
            move(y, prompt.size() + current_line.size());
            // set state
            state = CLI_ST_AUTO_COMPLETE;

            // new line
            printw("\n");

            // external handler (plugin)
            if(external_handler){
                mink_dynamic::run_external_method(external_plugin_handle,
                                                "block_handler",
                                                &external_plugin,
                                                1,
                                                true);

            }else{
                // parse line
                mink_utils::tokenize(&current_line, tmp_lst, 50, &tmp_size, true);

                // auto complete
                last_found = nullptr;
                cli_auto_complete(current_path,
                                  tmp_lst,
                                  tmp_size,
                                  &tmp_cli_res,
                                  &res_size,
                                  &last_found);

                // replace current line with auto completed values
                current_line.clear();
                for(int i = 0; i<tmp_size; i++){
                    current_line.append(tmp_lst[i]);
                    if(i < res_size) current_line.append(" "); else break;
                }

                // print results
                print_cli_def(&tmp_cli_res, 0, 1);

                // check if all tokens were perfectly matched
                if(tmp_size == res_size){
                    CLIItem* tmp_c = nullptr;
                    // check for children
                    if(!tmp_cli_res.children.empty()){
                        // set pointer to first child
                        tmp_c = tmp_cli_res.children[0];
                        // METHOD or SCRIPT parent only
                        if((tmp_c->parent->node_type == cli::CLI_SCRIPT) ||
                           (tmp_c->parent->node_type == cli::CLI_METHOD)){
                            unsigned int params_set = 0;
                            // look for set parameters
                            for (unsigned int i = 0;
                                 i < tmp_c->parent->children.size(); i++)
                                if (tmp_c->parent->children[i]->is_set)
                                    params_set++;
                            // all parameters are set
                            if(params_set == tmp_c->parent->children.size()){
                                attron(COLOR_PAIR(6));
                                printw(" --> <cr> <--");
                                printw("\n");
                                attroff(COLOR_PAIR(6));
                            }
                        }
                        // no multiples, all tokens matched
                    }else{
                        attron(COLOR_PAIR(6));
                        printw(" --> <cr> <--");
                        printw("\n");
                        attroff(COLOR_PAIR(6));
                    }
                }

                // clear
                for (unsigned int i = 0; i < tmp_cli_res.children.size(); i++)
                    tmp_cli_res.children[i]->is_set = false;
                tmp_cli_res.children.clear();

                printw(prompt.c_str());
                printw(current_line.c_str());

            }

            // ENTER - execute command
        }else if(tmp_ch == '\n'){
            interrupt = false;

            std::string tmp_lst[50];
            int tmp_size = 0;
            int res_size = 0;

            // move to end of line
            getyx(stdscr, y, x);
            move(y, prompt.size() + current_line.size());
            // set state
            state = CLI_ST_EXECUTE;
            // new line
            printw("\n");

            // external handler (plugin)
            if(external_handler){
                mink_dynamic::run_external_method(external_plugin_handle,
                                                "block_handler",
                                                &external_plugin,
                                                1,
                                                true);

                // special action (dir up)
            }else if(current_line == ".."){
                if(current_path->parent != nullptr){
                    current_path = current_path->parent;
                    current_path_line = "";
                    generate_path(current_path, &current_path_line);
                    if(current_path_line == "") current_path_line = "/";
                    generate_prompt();
                    current_line = "";
                    external_handler = false;
                    if((current_path->node_type == cli::CLI_CONST) &&
                       (current_path->script_path.size() > 0)){
                        external_handler = true;
                    }
                }
                printw(prompt.c_str());
                // special action (back to root)
            }else if(current_line == "/"){
                current_path = cli_def;
                current_path_line = "/";
                generate_path(current_path, &current_path_line);
                if(current_path_line == "") current_path_line = "/";
                generate_prompt();
                current_line = "";
                external_handler = false;
                if((current_path->node_type == cli::CLI_CONST) &&
                   (current_path->script_path.size() > 0)){
                    external_handler = true;
                }
                printw(prompt.c_str());

            }else{
                // parse line
                mink_utils::tokenize(&current_line, tmp_lst, 50, &tmp_size, true);
                // auto complete
                last_found = nullptr;
                cli_auto_complete(current_path,
                                  tmp_lst,
                                  tmp_size,
                                  &tmp_cli_res,
                                  &res_size,
                                  &last_found);

                // replace current line with auto completed values
                current_line.clear();
                for(int i = 0; i<tmp_size; i++){
                    current_line.append(tmp_lst[i]);
                    if(i < res_size) current_line.append(" "); else break;
                }


                // check if all tokens were perfectly matched
                if(tmp_size == res_size){
                    CLIItem* tmp_c = nullptr;
                    // check for children (script/method with parameters)
                    if((!tmp_cli_res.children.empty()) && (last_found == nullptr)){
                        // set pointer to first child
                        tmp_c = tmp_cli_res.children[0];
                        // METHOD or SCRIPT parent only
                        if((tmp_c->parent->node_type == cli::CLI_SCRIPT) ||
                           (tmp_c->parent->node_type == cli::CLI_METHOD)){
                            bool p_valid;
                            int err_c = 0;
                            std::string tmp_str(tmp_c->parent->script_path);
                            tmp_str.append(" ");
                            const char* tmp_arg_names[tmp_c->parent->children.size()];
                            const char* tmp_arg_values[tmp_c->parent->children.size()];
                            int argc = 0;

                            // parameters loop
                            for (unsigned int i = 0;
                                 i < tmp_c->parent->children.size(); i++)
                                if (tmp_c->parent->children[i]->is_set) {
                                    // construct script arguments
                                    tmp_str.append(tmp_c->parent->children[i]->name);
                                    tmp_str.append("=");
                                    tmp_str.append(tmp_c->parent->children[i]->param_value);
                                    tmp_str.append(" ");
                                    // set pointers to data (needed by modules)
                                    tmp_arg_names[argc] =
                                        tmp_c->parent->children[i]
                                            ->name.c_str();
                                    tmp_arg_values[argc] =
                                        tmp_c->parent->children[i]
                                            ->param_value.c_str();
                                    ++argc;
                                    // check if argument is valid
                                    p_valid = param_valid(&tmp_c->parent->children[i]->param_value,
                                                          &tmp_c->parent->children[i]->type);
                                    // display error
                                    if (!p_valid) {
                                        err_c++;
                                        attron(COLOR_PAIR(1));
                                        printw("ERROR: ");
                                        attroff(COLOR_PAIR(1));
                                        printw(
                                            "Parameter \"%s\" contains invalid "
                                            "\"%s\" value \"%s\"!\n",
                                            tmp_c->parent->children[i]
                                                ->name.c_str(),
                                            tmp_c->parent->children[i]
                                                ->type.c_str(),
                                            tmp_c->parent->children[i]
                                                ->param_value.c_str());
                                    }
                                }
                            // run method/script with params
                            if(err_c == 0){
                                switch(tmp_c->parent->node_type){
                                    // script
                                    case cli::CLI_SCRIPT:
                                        mink_utils::run_external_print(tmp_str.c_str(), true);
                                        break;

                                        // method
                                    case cli::CLI_METHOD:
                                        mink_dynamic::run_external_method_handler(tmp_c->parent->script_path.c_str(),
                                                                                  tmp_arg_names,
                                                                                  tmp_arg_values,
                                                                                  argc,
                                                                                  true);
                                        break;

                                    default: break;
                                }
                            }
                            // group with children
                        }else if(tmp_c->parent->node_type == cli::CLI_CONST){
                            current_path = tmp_c->parent;
                            current_path_line = "";
                            generate_path(current_path, &current_path_line);
                            if(current_path_line == "") current_path_line = "/";
                            generate_prompt();

                        }
                        // no multiples, all tokens matched (script/method without parameters)
                    }else if(last_found != nullptr){
                        if((last_found->node_type == cli::CLI_SCRIPT) ||
                           (last_found->node_type == cli::CLI_METHOD)){
                            switch(last_found->node_type){
                                // script
                                case cli::CLI_SCRIPT:
                                    mink_utils::run_external_print(last_found->script_path.c_str(), true);
                                    break;

                                    // method
                                case cli::CLI_METHOD:
                                    mink_dynamic::run_external_method_handler(last_found->script_path.c_str(),
                                                                              nullptr,
                                                                              nullptr,
                                                                              0,
                                                                              true);
                                    break;

                                default: break;
                            }
                            // group without children
                        }else if(last_found->node_type == cli::CLI_CONST){
                            current_path = last_found;
                            current_path_line = "";
                            generate_path(current_path, &current_path_line);
                            generate_prompt();
                            // check for external handler (plugin)
                            if(current_path->script_path.size() > 0){
                                external_plugin_handle = mink_dynamic::load_plugin(current_path->script_path.c_str());
                                if(external_plugin_handle != nullptr){
                                    external_handler = true;
                                    void* cli_p = this;
                                    external_plugin = mink_dynamic::run_external_method(external_plugin_handle,
                                                                                      "block_handler_init",
                                                                                      &cli_p,
                                                                                      1,
                                                                                      true);

                                }else{
                                    attron(COLOR_PAIR(1));
                                    printw("ERROR: ");
                                    attroff(COLOR_PAIR(1));
                                    printw("Cannot load plugin '%s[%s]'!\n", current_path->script_path.c_str(), dlerror());

                                    current_path = cli_def;
                                    current_path_line = "/";
                                    generate_path(current_path, &current_path_line);
                                    if(current_path_line == "") current_path_line = "/";
                                    generate_prompt();
                                    current_line = "";

                                }


                            }
                        }

                    }
                }
                // clear
                for (unsigned int i = 0; i < tmp_cli_res.children.size(); i++)
                    tmp_cli_res.children[i]->is_set = false;
                tmp_cli_res.children.clear();

                // add to history
                add_to_history(&current_line);
                history_index = history.size();

                // reset line
                current_line = "";
                printw(prompt.c_str());


            }



            // backspace
        }else if(tmp_ch == KEY_BACKSPACE){
            getyx(stdscr, y, x);
            if(x > prompt.size()){
                if (x - prompt.size() <= current_line.size())
                    current_line.erase(x - prompt.size() - 1, 1);
                move(y, 0);
                clrtoeol();
                printw(prompt.c_str());
                printw(current_line.c_str());
                move(y, x - 1);
            }

            // exit
        }else if(tmp_ch == CTRL('D')){
            // exit plugin handler
            if(external_handler){
                // plugin exit
                mink_dynamic::run_external_method(external_plugin_handle,
                                                  "block_handler_free",
                                                  &external_plugin,
                                                  1,
                                                  true);
                // path update
                if(current_path->parent != nullptr){
                    current_path = current_path->parent;
                    current_path_line = "";
                    generate_path(current_path, &current_path_line);
                    if(current_path_line == "") current_path_line = "/";
                    generate_prompt();
                    current_line = "";
                    external_handler = false;
                    mink_dynamic::unload_plugin(external_plugin_handle);
                    external_plugin = nullptr;
                    external_plugin_handle = nullptr;
                    printw(prompt.c_str());


                }
                // cli exit
            }else{
                break;

            }
            // clear screen
        }else if(tmp_ch == CTRL('L')){
            clear();
            printw(prompt.c_str());
            printw(current_line.c_str());
            // arrow left
        }else if(tmp_ch == KEY_LEFT){
            getyx(stdscr, y, x);
            if(x > prompt.size()){
                move(y, x - 1);
            }

            // arrow right
        }else if(tmp_ch == KEY_RIGHT){
            getyx(stdscr, y, x);
            if(x < prompt.size() + current_line.size()){
                move(y, x + 1);
            }

            // history UP
        }else if(tmp_ch == KEY_UP){
            --history_index;
            if(history.size() > history_index){
                current_line = *history[history_index];
                getyx(stdscr, y, x);
                move(y, 0);
                clrtoeol();
                printw(prompt.c_str());
                printw(current_line.c_str());

            }

            // history DOWN
        }else if(tmp_ch == KEY_DOWN){
            ++history_index;
            if(history_index >= history.size()) history_index = history.size() - 1;
            if(history.size() > history_index){
                current_line = *history[history_index];
                getyx(stdscr, y, x);
                move(y, 0);
                clrtoeol();
                printw(prompt.c_str());
                printw(current_line.c_str());

            }

            // delete
        }else if(tmp_ch == KEY_DC){
            getyx(stdscr, y, x);
            if(x > prompt.size() - 1){
                if (x - prompt.size() <= current_line.size())
                    current_line.erase(x - prompt.size(), 1);
                move(y, 0);
                clrtoeol();
                printw(prompt.c_str());
                printw(current_line.c_str());
                move(y, x);
            }
        }else if(tmp_ch == KEY_PPAGE){
            // ignore
        }else if(tmp_ch == KEY_NPAGE){
            // ignore
            // other
        }else{
            if(isprint(tmp_ch)){
                getyx(stdscr, y, x);
                if (x - prompt.size() <= current_line.size())
                    current_line.insert(x - prompt.size(), (char*)&tmp_ch);
                move(y, 0);
                clrtoeol();
                printw(prompt.c_str());
                printw(current_line.c_str());
                move(y, x + 1);

            }

        }

        refresh();

    }
    endwin();


}
