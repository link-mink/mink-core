/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <mink_config.h>
#include <regex>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <mink_utils.h>
#include <sys/stat.h>
#include <iomanip>


// CfgNtfCallback
config::CfgNtfCallback::~CfgNtfCallback() = default;

void config::CfgNtfCallback::run(ConfigItem* cfg, unsigned int mod_index, unsigned int mod_count){
    // reserved
}

// CfgNotification
config::CfgNotification::CfgNotification(const std::string* _cfg_path): cfg_path(*_cfg_path){}

config::CfgNotification::~CfgNotification() = default;

int config::CfgNotification::notify(void* args){
    return 0;
}

void* config::CfgNotification::reg_user(void* usr){
    return nullptr;
}

int config::CfgNotification::unreg_user(void* usr){
    return 0;
}

std::string* config::CfgNotification::get_cfg_path(){
    return &cfg_path;
}

// ConfigItemSort
bool config::ConfigItemSort::operator()(ConfigItem* i, ConfigItem* j) const {
    if (i->sort_node == nullptr || j->sort_node == nullptr) {
        return strcmp(i->name.c_str(), j->name.c_str()) < 0;
    }
    ConfigItem* s1 = (*i)(i->sort_node->name.c_str());
    ConfigItem* s2 = (*j)(j->sort_node->name.c_str());
    if (s1 == nullptr || s2 == nullptr)
        return strcmp(i->name.c_str(), j->name.c_str()) < 0;
    int is1 = s1->to_int();
    int is2 = s2->to_int();
    return is1 < is2;
}

// ConfigItem
config::ConfigItem::ConfigItem(): parent(nullptr),
                                  node_type(CONFIG_NT_UNKNOWN),
                                  node_state(CONFIG_NS_READY),
                                  is_template(false),
                                  is_empty(false),
                                  is_new(false),
                                  onc_hndlr_exec(false),
                                  on_change(nullptr),
                                  sort_node(nullptr){
}

config::ConfigItem::ConfigItem(const ConfigItem &o) : parent(o.parent),
                                                      name(o.name),
                                                      value(o.value),
                                                      new_value(o.new_value),
                                                      type(o.type),
                                                      desc(o.desc),
                                                      node_type(o.node_type),
                                                      node_state(o.node_state),
                                                      is_template(o.is_template),
                                                      is_empty(o.is_empty),
                                                      is_new(o.is_new),
                                                      onc_hndlr_exec(o.onc_hndlr_exec),
                                                      on_change(o.on_change),
                                                      sort_node(o.sort_node) {}

config::ConfigItem &config::ConfigItem::operator=(const ConfigItem &o){
    if (this == &o) return *this;
    parent = o.parent;
    name = o.name;
    value = o.value;
    new_value = o.new_value;
    type = o.type;
    desc = o.desc;
    node_type = o.node_type;
    node_state = o.node_state;
    is_template = o.is_template;
    is_empty = o.is_empty;
    is_new = o.is_new;
    onc_hndlr_exec = o.onc_hndlr_exec;
    on_change = o.on_change;
    sort_node = o.sort_node;
    return *this;
}

config::ConfigItem::~ConfigItem(){
    // children
    std::all_of(children.cbegin(), children.cend(), [](ConfigItem *n) {
        if (n != nullptr) delete n;
        return true;
    });
    children.clear();
}

config::ConfigItem* config::ConfigItem::find_parent(const char* n){
    if(parent == nullptr) return nullptr;
    if(strcmp(parent->name.c_str(), n) == 0) return parent;
    return parent->find_parent(n);
}

bool config::ConfigItem::is_modified(ConfigItem* _node){
    // null check
    if(_node == nullptr) _node = this;
    // check current
    if (_node->node_state != CONFIG_NS_READY || _node->is_new) return true;
    // children
    for(unsigned int i = 0; i<_node->children.size(); i++){
        if(is_modified(_node->children[i])) return true;
    }
    // default
    return false;
}

int config::ConfigItem::find(const ConfigItem* item){
    for (unsigned int i = 0; i < children.size(); i++)
        if (children[i] == item) return i;
    return -1;
}

void config::ConfigItem::set_on_change_handler(CfgNtfCallback* _on_change, bool recursive){
    on_change = _on_change;
    if(recursive) {
        std::all_of(children.cbegin(), children.cend(),
                    [_on_change, recursive](ConfigItem *n) {
                        n->set_on_change_handler(_on_change, recursive);
                        return true;
                    });
    }
}

config::CfgNtfCallback* config::ConfigItem::get_on_change_handler(){
    return on_change;
}

int config::ConfigItem::run_on_change_handler(unsigned int mod_index, unsigned int mod_count){
    if(on_change == nullptr) return 1;

    // first pass (MOD/DEL)
    if(!onc_hndlr_exec) on_change->run(this, mod_index, mod_count);

    // set exec flag and inc pass num
    onc_hndlr_exec = !onc_hndlr_exec;
    is_new = !is_new;

    // return
    return (onc_hndlr_exec ? 0 : 1);
}



int config::ConfigItem::to_int(const char* node_path, int default_val){
    if(node_path == nullptr){
        if(value.size() > 0) return atoi(value.c_str());
        else return default_val;

    }else{
        const ConfigItem* node = (*this)(node_path);
        if(node == nullptr) return default_val;
        if(node->value.size() > 0) return atoi(node->value.c_str());
        else return default_val;

    }

}

bool config::ConfigItem::to_bool(const char* node_path){
    if(node_path == nullptr){
        return atoi(value.c_str());

    }else{
        const ConfigItem* node = (*this)(node_path);
        if(node == nullptr) return false;
        return atoi(node->value.c_str());

    }

}

const char* config::ConfigItem::to_cstr(const char* node_path){
    if(node_path == nullptr){
        return value.c_str();

    }else{
        const ConfigItem* node = (*this)(node_path);
        if(node == nullptr) return nullptr;
        return node->value.c_str();

    }

}


bool config::ConfigItem::val_exists(const char* node_path){
    if(node_path == nullptr){
        return value.size() > 0;

    }else{
        const ConfigItem* node = (*this)(node_path);
        if(node == nullptr) return false;
        return node->value.size() > 0;

    }

}


config::ConfigItem* config::ConfigItem::operator ()(const char* _name,
                                                    bool create,
                                                    ConfigNodeType last_nt,
                                                    bool _set_new_flag){
    // check input
    if(_name == nullptr) return nullptr;
    std::string line(_name);
    std::string tokens[50];
    int res_size = 0;
    // tokenize
    mink_utils::tokenize(&line, tokens, 50, &res_size, false);
    ConfigItem* res_item = nullptr;
    ConfigItem* cur_item = this;
    ConfigItem* tmp_item = nullptr;

    // loop tokens
    for(int i = 0; i<res_size; i++){
        // reset result
        res_item = nullptr;

        // special case (parent symbol)
        if(tokens[i] == "^") {
            cur_item = cur_item->parent;
            res_item = cur_item;
            continue;
        }

        // loop current item children, skip template nodes
        for (unsigned int j = 0; j < cur_item->children.size(); j++)
            // token matched
            if ((!cur_item->children[j]->is_template) &&
                (cur_item->children[j]->name == tokens[i])) {
                // go deeper
                cur_item = cur_item->children[j];
                // set result
                res_item = cur_item;
                break;
            }

        // create node
        if(create && (res_item == nullptr) && cur_item){
            tmp_item = new ConfigItem();
            tmp_item->node_type = (i < res_size - 1 ? CONFIG_NT_BLOCK : last_nt);
            tmp_item->node_state = CONFIG_NS_READY;
            tmp_item->parent = cur_item;
            tmp_item->is_empty = cur_item->is_empty;
            tmp_item->name = tokens[i];
            cur_item->children.push_back(tmp_item);
            cur_item = tmp_item;
            res_item = tmp_item;
            // set block node ON CHANGE handler of parent (needed to catch ADD operation)
            tmp_item->on_change = tmp_item->parent->on_change;
            // set is_new flag to differentiate from MODIFIED/DELETED action
            if(_set_new_flag) tmp_item->is_new = true;

        }else{
            // if not matched return
            if(res_item == nullptr) return nullptr;

        }

    }

    // return result
    return res_item;
}

void config::ConfigItem::special_ac(void** args, int argc){
    if(argc != 5) return;

    auto result = (config::ConfigItem*)args[0];
    auto tmp_node_lst = (config::ConfigItem*)args[1];
    ConfigItem* new_node  = nullptr;
    auto val_type = (std::string*)args[2];
    auto ptrn = (CFGPattern*)args[3];
    auto cfg = (Config*)args[4];

    // check for special NON regex pattern,
    // minimum size, enclosing brackets
    if ((ptrn != nullptr) &&
        (ptrn->pattern.substr(0, 7) == ":pmcfg:") &&
        (ptrn->pattern.size() > 9) &&
        (ptrn->pattern[7] == '[') &&
        (ptrn->pattern[ptrn->pattern.size() - 1] == ']')) {


        std::string tmp_str = ptrn->pattern.substr(8, ptrn->pattern.size() - 9);
        ConfigItem* tmp_cfg = nullptr;

        // absolute starts with '/'
        if (tmp_str[0] == '/') {
            tmp_str.erase(0, 1);
            // get node list
            tmp_cfg =
                (*cfg->get_definition_root())(tmp_str.c_str());

            // relative
        } else {
            // get node list
            if (parent != nullptr) tmp_cfg = (*this)(tmp_str.c_str());
        }

        // check if found
        if (tmp_cfg != nullptr) {
            // get available values
            std::all_of(tmp_cfg->children.cbegin(), tmp_cfg->children.cend(),
                        [result](const ConfigItem *n) {
                            if (!n->is_template) {
                                auto nn = new config::ConfigItem();
                                nn->name = "<" + n->name + ">";
                                nn->node_state = config::CONFIG_NS_READY;
                                nn->node_type = config::CONFIG_NT_PARAM;
                                result->children.push_back(nn);
                            }
                            return true;
                        });
            // free mem later
            std::all_of(result->children.cbegin(), result->children.cend(),
                        [tmp_node_lst](ConfigItem *n) {
                            tmp_node_lst->children.push_back(n);
                            return true;
                        });
            // return
            return;
        }
    }
    // display notice
    new_node = new config::ConfigItem();
    new_node->name = "<Please enter \""  + *val_type + "\" value";
    // check description
    if(ptrn && ptrn->desc != ""){
        new_node->name.append(" identified by \"");
        new_node->name.append(ptrn->desc);
        new_node->name.append("\"");
    }
    new_node->name.append(">");

    new_node->node_state = config::CONFIG_NS_READY;
    new_node->node_type = config::CONFIG_NT_PARAM;
    result->children.push_back(new_node);

    // free mem later
    std::all_of(result->children.cbegin(), result->children.cend(),
                [tmp_node_lst](ConfigItem *n) {
                    tmp_node_lst->children.push_back(n);
                    return true;
                });
}


// ConfigItem Rollback Revision
config::ConfigItemRBR::ConfigItemRBR(ConfigItem* _parent){
    node_type = CONFIG_NT_PARAM;
    name = "revision";
    desc = "Revision number for rollback operation";
    parent = _parent;

}

void config::ConfigItemRBR::special_ac(void** args, int argc){
    if(argc != 5) return;

    auto result = (config::ConfigItem*)args[0];
    auto tmp_node_lst = (config::ConfigItem*)args[1];
    config::ConfigItem* new_node  = nullptr;
    std::stringstream tmp_str;
    std::string tmp_path;
    struct stat st;
    dirent** fnames;
    std::string line;
    std::string tokens[10];
    std::string desc;
    int res_size = 0;

    int n = scandir("./commit-log/",
                    &fnames,
                    mink_utils::_ac_rollback_revision_filter,
                    mink_utils::_ac_rollback_revision_sort);

    if(n < 0) return;
    int c = 0;
    char tmp_ch[200];
    for(int i = 0; i<n; i++){
        new_node = new config::ConfigItem();
        tmp_path = "./commit-log/";
        tmp_path.append(fnames[i]->d_name);
        // file stats
        stat(tmp_path.c_str(), &st);
        // first line
        std::ifstream ifs(tmp_path.c_str());
        std::getline(ifs, line);
        mink_utils::tokenize(&line, tokens, 10, &res_size, false);
        ifs.close();
        // check if first special line is valid
        desc = "";
        if ((res_size > 2) &&
            (tokens[0] == "//")
            && (tokens[1] == "@desc")) {

            desc = tokens[2];
        }

        // zero buffer
        memset(tmp_ch, 0, 200);
        // format time
        tmp_str.str("");
        tm time_info = {};
        localtime_r(&st.st_mtim.tv_sec, &time_info);
        strftime(tmp_ch, 200, "%Y-%m-%d %H:%M:%S", &time_info);
        tmp_str << c << " - " << tmp_ch;
        new_node->name = tmp_str.str();
        new_node->desc = desc;
        ++c;
        // push result
        result->children.push_back(new_node);
        free(fnames[i]);

    }
    delete[] fnames;
    // free mem later
    std::all_of(result->children.cbegin(), result->children.cend(),
                [tmp_node_lst](ConfigItem *ni) {
                    tmp_node_lst->children.push_back(ni);
                    return true;
                });
}

// User Id
config::UserId::UserId(){
    memset(user_type, 0, sizeof(user_type));
    memset(user_id, 0, sizeof(user_id));
}

// User Info
config::UserInfo::UserInfo(ConfigItem* _wnode): timestamp(time(nullptr)),
                                                wnode(_wnode){
}

bool config::UserId::operator != (const UserId& right) const {
    return memcmp(this->user_id, right.user_id, sizeof(right.user_id)) != 0 ||
           memcmp(this->user_type, right.user_type, sizeof(right.user_type)) !=
               0;
}

bool config::UserId::operator == (const UserId& right) const {
    return memcmp(this->user_id, right.user_id, sizeof(right.user_id)) == 0 &&
           memcmp(this->user_type, right.user_type, sizeof(right.user_type)) ==
               0;
}


// User Id compare
bool config::UserIdCompare::operator ()(const UserId& x, const UserId& y) const {
    return memcmp(x.user_id, y.user_id, sizeof(x.user_id)) < 0;
}



// Config
config::Config::Config(){
    definition = nullptr;
    transaction = false;
    current_def_path = nullptr;
    // mutex
    pthread_mutexattr_init(&mtx_config_attr);
    pthread_mutexattr_settype(&mtx_config_attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&mtx_config, &mtx_config_attr);

    cmd_tree = new ConfigItem();
    cmd_tree->name = "ROOT_CMD";
    cmd_tree->node_type = CONFIG_NT_BLOCK;
    auto tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "set";
    tmp_node->desc = "Creates a new node or modifies a value in an existing node";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "show";
    tmp_node->desc = "Displays configuration node";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "edit";
    tmp_node->desc = "Navigates to a subnode in the configuration tree for editing";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "delete";
    tmp_node->desc = "Deletes a configuration node";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "top";
    tmp_node->desc = "Exits to the top level of configuration mode";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "up";
    tmp_node->desc = "Navigates up one level in the configuration tree";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "configuration";
    tmp_node->desc = "Displays configuration file contents";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "commands";
    tmp_node->desc = "Displays configuration file commands";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "commit";
    tmp_node->desc = "Applies any uncommitted configuration changes";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_PARAM;
    tmp_node->name = "description";
    tmp_node->desc = "Meaningful comment describing current commit";
    tmp_node->parent = cmd_tree->children[cmd_tree->children.size() - 1];
    cmd_tree->children[cmd_tree->children.size() - 1]->children.push_back(tmp_node);


    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "discard";
    tmp_node->desc = "Discard all configuration changes";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "rollback";
    tmp_node->desc = "Load previous configuration revision";
    cmd_tree->children.push_back(tmp_node);

    // Rollback revision special auto complete node
    tmp_node = new ConfigItemRBR(cmd_tree->children[cmd_tree->children.size() - 1]);
    cmd_tree->children[cmd_tree->children.size() - 1]->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "load";
    tmp_node->desc = "Loads a saved configuration";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_PARAM;
    tmp_node->name = "file-name";
    tmp_node->desc = "The name of the configuration file";
    tmp_node->parent = cmd_tree->children[cmd_tree->children.size() - 1];
    cmd_tree->children[cmd_tree->children.size() - 1]->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_CMD;
    tmp_node->name = "save";
    tmp_node->desc = "Saves the running configuration to a file";
    cmd_tree->children.push_back(tmp_node);

    tmp_node = new ConfigItem();
    tmp_node->node_type = CONFIG_NT_PARAM;
    tmp_node->name = "file-name";
    tmp_node->desc = "The name of the file where the information is to be saved";
    tmp_node->parent = cmd_tree->children[cmd_tree->children.size() - 1];
    cmd_tree->children[cmd_tree->children.size() - 1]->children.push_back(tmp_node);



}


config::Config::~Config(){
    // mutex
    pthread_mutex_destroy(&mtx_config);
    pthread_mutexattr_destroy(&mtx_config_attr);

    // patterns
    std::all_of(patterns.cbegin(), patterns.cend(), [](CFGPattern *n) {
        delete n;
        return true;
    });
    patterns.clear();

    // user wn list
    usr_path_map.clear();

    // cmd def
    delete cmd_tree;

    // delete notification
    std::all_of(notifications.cbegin(), notifications.cend(),
                [](CfgNotification *n) {
                    delete n;
                    return true;
                });
    notifications.clear();
}

void config::Config::flatten(ConfigItem* tree, ConfigItem* output){
    if ((tree != nullptr) && (output != nullptr) && (!tree->is_template)) {
        output->children.push_back(tree);

        std::all_of(tree->children.cbegin(), tree->children.cend(),
                    [output](ConfigItem *n) {
                        flatten(n, output);
                        return true;
                    });
    }
}

void config::Config::get_parent_line(ConfigItem* tree, std::string* output){
    if(tree != nullptr && output != nullptr){
        // get parents
        *output = "";
        if(tree->parent == nullptr) return;
        config::ConfigItem* tmp_node = tree;

        while(tmp_node->parent->name != "ROOT"){
            output->insert(0, tmp_node->parent->name + " ");
            tmp_node = tmp_node->parent;
        }

    }
}



void config::Config::print_config_tree(ConfigItem* tree, int depth, bool ncurses){
    if(tree == nullptr) return;
    // padding
    for(int i = 0; i<depth; i++){
        if(ncurses) printw("  "); else std::cout << "  ";
    }
    if(ncurses){
        printw("%s [type=%s, value=%s, nodetype=%d, nodestate=%d, is_template=%d, is_new=%d, desc=%s]",
                tree->name.c_str(),
                tree->type.c_str(),
                tree->value.c_str(),
                tree->node_type,
                tree->node_state,
                tree->is_template,
                tree->is_new,
                tree->desc.c_str());
    }else{
        std::cout << tree->name << " [type=" << tree->type <<
            ", value=" << tree->value <<
            ", nodetype=" << tree->node_type <<
            ", nodestate=" << tree->node_state <<
            ", is_template=" << tree->is_template <<
            ", is_empty=" << tree->is_empty <<
            ", is_new=" << tree->is_new <<
            ", desc=" << tree->desc <<
            ", sort=" << tree->sort_node
            << "]";

    }
    if(ncurses) printw("\n"); else std::cout << std::endl;
    // child count
    int n = tree->children.size();
    for(int i = 0; i<n; i++){
        // print
        print_config_tree(tree->children[i], depth + 1, ncurses);
    }

}

int config::Config::get_commands_lc(ConfigItem* _definition){
    if(_definition == nullptr) return 0;

    ConfigItem* tmp_node = nullptr;
    int res = 0;
    for(unsigned int i = 0; i<_definition->children.size(); i++){
        // set pointer to current node
        tmp_node = _definition->children[i];
        // skip template node
        if(tmp_node->is_template) continue;
        // skip empty
        if(tmp_node->name == "") continue;

        // config block
        if(tmp_node->node_type == CONFIG_NT_BLOCK){
            if(tmp_node->node_state == CONFIG_NS_DELETED){
                ++res;

            }else{
                // process block
                res += get_commands_lc(tmp_node) + 1;

            }

            // config item
        }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                 (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){
            ++res;

        }
    }
    return res;

}

void config::Config::show_commands(ConfigItem* _definition, int depth, std::stringstream* out_stream){
    if(_definition != nullptr){
        ConfigItem* tmp_node = nullptr;
        std::string tmp_str;
        std::string tmp_cmd;
        for(unsigned int i = 0; i<_definition->children.size(); i++){
            // set pointer to current node
            tmp_node = _definition->children[i];
            // skip template node
            if(tmp_node->is_template) continue;
            // skip empty
            if(tmp_node->name.size() == 0) continue;

            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){
                if(tmp_node->node_state == CONFIG_NS_DELETED){
                    // get parents
                    tmp_str = "";
                    while(tmp_node->parent->name != "ROOT"){
                        tmp_str.insert(0, tmp_node->parent->name + " ");
                        tmp_node = tmp_node->parent;
                    }
                    tmp_node = _definition->children[i];
                    // print cmd
                    *out_stream << "delete " << tmp_str << tmp_node->name << std::endl;

                }else{
                    // get parents
                    tmp_str = "";
                    while(tmp_node->parent->name != "ROOT"){
                        tmp_str.insert(0, tmp_node->parent->name + " ");
                        tmp_node = tmp_node->parent;
                    }
                    tmp_node = _definition->children[i];

                    // explicit node creation ('!' prefix)
                    *out_stream << "set " << tmp_str << "!" << tmp_node->name << std::endl;
                    // process block
                    show_commands(tmp_node, depth + 1, out_stream);

                }

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){
                if (tmp_node->node_state == CONFIG_NS_DELETED)
                    tmp_cmd = "delete ";
                else
                    tmp_cmd = "set ";
                // set cmd
                *out_stream << tmp_cmd;

                // get parents
                tmp_str = "";
                while(tmp_node->parent->name != "ROOT"){
                    tmp_str.insert(0, tmp_node->parent->name + " ");
                    tmp_node = tmp_node->parent;
                }
                tmp_node = _definition->children[i];

                // print cmd
                if(tmp_node->node_state != CONFIG_NS_DELETED){
                    *out_stream << tmp_str << tmp_node->name << " \""
                                << tmp_node->new_value << "\"" << std::endl;

                }else{
                    *out_stream << tmp_str << tmp_node->name << std::endl;

                }

            }
        }
    }
}


void config::Config::show_commands(ConfigItem* _definition, int depth, WINDOW* win){
    if(_definition != nullptr){
        ConfigItem* tmp_node = nullptr;
        std::string tmp_str;
        std::string tmp_cmd;
        for(unsigned int i = 0; i<_definition->children.size(); i++){
            // set pointer to current node
            tmp_node = _definition->children[i];
            // skip template node
            if(tmp_node->is_template) continue;

            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){
                if(tmp_node->node_state == CONFIG_NS_DELETED){
                    // get parents
                    tmp_str = "";
                    while(tmp_node->parent->name != "ROOT"){
                        tmp_str.insert(0, tmp_node->parent->name + " ");
                        tmp_node = tmp_node->parent;
                    }
                    tmp_node = _definition->children[i];
                    // print cmd
                    wprintw(win, "delete %s%s\n", tmp_str.c_str(), tmp_node->name.c_str());

                }else{
                    // process block
                    show_commands(tmp_node, depth + 1, win);

                }

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){
                if(tmp_node->node_state == CONFIG_NS_DELETED) tmp_cmd = "delete "; else tmp_cmd = "set ";
                // set cmd
                wprintw(win, tmp_cmd.c_str());

                // get parents
                tmp_str = "";
                while(tmp_node->parent->name != "ROOT"){
                    tmp_str.insert(0, tmp_node->parent->name + " ");
                    tmp_node = tmp_node->parent;
                }
                tmp_node = _definition->children[i];

                // print cmd
                if(tmp_node->node_state != CONFIG_NS_DELETED){
                    wprintw(win, "%s%s \"%s\"\n",
                            tmp_str.c_str(),
                            tmp_node->name.c_str(),
                            tmp_node->new_value.c_str());

                }else{
                    wprintw(win, "%s%s\n", tmp_str.c_str(), tmp_node->name.c_str());

                }

            }
        }
    }
}


void config::Config::show_commands(ConfigItem* _definition, int depth, bool ncurses){
    if(_definition != nullptr){
        ConfigItem* tmp_node = nullptr;
        std::string tmp_str;
        std::string tmp_cmd;
        for(unsigned int i = 0; i<_definition->children.size(); i++){
            // set pointer to current node
            tmp_node = _definition->children[i];
            // skip template node
            if(tmp_node->is_template) continue;

            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){
                if(tmp_node->node_state == CONFIG_NS_DELETED){
                    // get parents
                    tmp_str = "";
                    while(tmp_node->parent->name != "ROOT"){
                        tmp_str.insert(0, tmp_node->parent->name + " ");
                        tmp_node = tmp_node->parent;
                    }
                    tmp_node = _definition->children[i];
                    // print cmd
                    if (ncurses)
                        printw("delete %s%s\n", tmp_str.c_str(),
                               tmp_node->name.c_str());
                    else
                        std::cout << "delete " << tmp_str << tmp_node
                                  << std::endl;

                }else{
                    // process block
                    show_commands(tmp_node, depth + 1, ncurses);

                }

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){
                if(tmp_node->node_state == CONFIG_NS_DELETED) tmp_cmd = "delete "; else tmp_cmd = "set ";
                // set cmd
                if(ncurses) printw(tmp_cmd.c_str()); else std::cout << tmp_cmd;

                // get parents
                tmp_str = "";
                while(tmp_node->parent->name != "ROOT"){
                    tmp_str.insert(0, tmp_node->parent->name + " ");
                    tmp_node = tmp_node->parent;
                }
                tmp_node = _definition->children[i];

                // print cmd
                if(tmp_node->node_state != CONFIG_NS_DELETED){
                    if (ncurses)
                        printw("%s%s \"%s\"\n", tmp_str.c_str(),
                               tmp_node->name.c_str(),
                               tmp_node->new_value.c_str());
                    else
                        std::cout << tmp_str << tmp_node->name << " \""
                                  << tmp_node->new_value << "\"" << std::endl;

                }else{
                    if(ncurses) printw("%s%s\n", tmp_str.c_str(), tmp_node->name.c_str());
                    else std::cout << tmp_str << tmp_node->name << std::endl;

                }

            }
        }
    }

}


void config::Config::show_commands(ConfigItem* _definition,
                                   unsigned char* result,
                                   int* result_size,
                                   int depth){
    if(_definition != nullptr && result != nullptr && result_size != nullptr){
        ConfigItem* tmp_node = nullptr;
        std::string tmp_str;
        int tmp_size = 0;
        for(unsigned int i = 0; i<_definition->children.size(); i++){
            // set pointer to current node
            tmp_node = _definition->children[i];
            // skip template node
            if(tmp_node->is_template) continue;

            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){
                tmp_size = 0;
                // process block
                show_commands(tmp_node, result, &tmp_size, depth + 1);
                // fwd buffer
                result += tmp_size;
                *result_size += tmp_size;

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM && tmp_node->new_value != ""){
                // set cmd
                memcpy(result, "set ", 4);
                result += 4;
                *result_size += 4;

                // get parents
                tmp_str = "";
                while(tmp_node->parent->name != "ROOT"){
                    tmp_str.insert(0, tmp_node->parent->name + " ");
                    tmp_node = tmp_node->parent;
                }
                tmp_node = _definition->children[i];

                // parents
                memcpy(result, tmp_str.c_str(), tmp_str.size());
                result += tmp_str.size();
                *result_size += tmp_str.size();

                // node name
                memcpy(result, tmp_node->name.c_str(), tmp_node->name.size());
                result += tmp_node->name.size();
                *result_size += tmp_node->name.size();

                // start value
                memcpy(result, " \"", 2);
                result += 2;
                *result_size += 2;

                // value
                memcpy(result, tmp_node->new_value.c_str(), tmp_node->new_value.size());
                result += tmp_node->new_value.size();
                *result_size += tmp_node->new_value.size();

                // end value and new line
                memcpy(result, "\"\n", 2);
                result += 2;
                *result_size += 2;

            }
        }
    }
}

void config::Config::show_config(ConfigItem* _contents,
                                 int depth,
                                 int* result_size,
                                 bool no_output,
                                 std::ofstream* out_stream,
                                 bool no_uncm,
                                 std::string* desc){
    if(_contents != nullptr){
        ConfigItem* tmp_node = nullptr;
        int tmp_size = 0;
        int extra = 0;
        std::string tmp_str;
        std::string* tmp_val;

        // first comment line
        if((desc != nullptr) && !no_output && (*desc != "")){
            *out_stream << "// @desc \"" << *desc << "\"\n";
        }

        if(no_output && _contents->is_empty) (*result_size)++;


        // find max length
        unsigned int max_length = 0;
        // calculate padding for item names
        for (unsigned int i = 0; i < _contents->children.size(); i++)
            if (!_contents->children[i]->is_template &&
                _contents->children[i]->node_type == CONFIG_NT_ITEM) {
                tmp_node = _contents->children[i];
                if (tmp_node->name.size() +
                        (tmp_node->node_state != CONFIG_NS_READY ? 1 : 0) >
                    max_length)
                    max_length =
                        tmp_node->name.size() +
                        (tmp_node->node_state != CONFIG_NS_READY ? 1 : 0);
            }

        // loop contents
        for(unsigned int i = 0; i<_contents->children.size(); i++){
            tmp_node = _contents->children[i];
            // skip template node
            if(tmp_node->is_template) continue;
            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){
                // if not showing uncommitted data, skip new template based nodes
                if(no_uncm){
                    if(tmp_node->is_new) continue;
                    // if showing uncommitted data, skip delete template based nodes
                }else{
                    if(tmp_node->node_state == CONFIG_NS_DELETED) continue;
                }

                // check group size
                tmp_size = 0;
                show_config(tmp_node, depth + 1, &tmp_size, true, out_stream, no_uncm, nullptr);

                if(tmp_size > 0){
                    // padding
                    for(int j = 0; j<depth; j++){
                        if(!no_output){
                            out_stream->write("\t", 1);

                        }
                    }
                    if(!no_output) *result_size += depth;

                    // name and open block
                    if(!no_output){
                        extra = 0;
                        // node state
                        switch(tmp_node->node_state){
                            default:
                                tmp_str = "";
                                break;
                        }
                        // node name
                        tmp_str.append(tmp_node->name);

                        if(!tmp_node->is_empty){
                            out_stream->write(tmp_str.c_str(), tmp_str.size());
                            out_stream->write(" {\n", 3);
                            *result_size += tmp_node->name.size() + 3 + extra;


                        }else{

                            out_stream->write(tmp_str.c_str(), tmp_str.size());
                            *result_size += tmp_node->name.size() + extra;

                        }

                    }

                    // children
                    tmp_size = 0;
                    show_config(tmp_node, depth + 1, &tmp_size, no_output, out_stream, no_uncm, nullptr);
                    *result_size += tmp_size;


                    // padding
                    if(!no_output){
                        if(!tmp_node->is_empty){
                            for(int j = 0; j<depth; j++){
                                out_stream->write("\t", 1);
                            }
                            *result_size += depth;

                        }

                    }


                    // close block
                    if(!no_output){
                        if(!tmp_node->is_empty){
                            out_stream->write("}\n", 2);
                            *result_size += 2;

                        }else{
                            out_stream->write("{}\n", 3);
                            *result_size += 3;

                        }


                    }


                }


                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){
                // skip if deleted and showing uncommitted data
                // important for config save operation since deleted nodes should not
                // be visible in output file
                if(!no_uncm && tmp_node->node_state == CONFIG_NS_DELETED) continue;

                // check if showing uncommitted
                if(no_uncm) tmp_val = &tmp_node->value; else tmp_val = &tmp_node->new_value;
                // skip config item without value
                if(*tmp_val == "") continue;

                // padding
                if(!no_output){
                    for(int j = 0; j<depth; j++){
                        out_stream->write("\t", 1);
                    }
                    *result_size += depth;
                }

                // name and value
                if(!no_output){
                    extra = 0;
                    // node state
                    switch(tmp_node->node_state){
                        default:
                            tmp_str = "";
                            break;
                    }
                    // node name
                    tmp_str.append(tmp_node->name);

                    *out_stream << tmp_str << " ";
                    *out_stream << std::setfill(' ') << std::setw(max_length - tmp_str.size() + 1);
                    *out_stream << "\"" << *tmp_val << "\"\n";

                    *result_size += tmp_str.size() + tmp_val->size()  + 4 + extra;


                }else{
                    *result_size += tmp_val->size();
                }
            }
        }
    }
}
int config::Config::get_config_lc(ConfigItem* _contents){
    if(_contents != nullptr){
        ConfigItem* tmp_node = nullptr;
        int tmp_size = 0;
        int res = 0;
        std::string tmp_str;
        // loop contents
        for(unsigned int i = 0; i<_contents->children.size(); i++){
            tmp_node = _contents->children[i];
            // skip template node
            if(tmp_node->is_template) continue;
            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){
                // check empty
                if(tmp_node->is_empty){
                    ++res;
                    continue;
                }
                // check group size
                tmp_size = get_config_lc(tmp_node);
                if(tmp_size > 0){
                    // children
                    tmp_size = get_config_lc(tmp_node);
                    res += tmp_size + 2;
                }


                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){
                ++res;

            }
        }
        return res;
    }
    return 0;
}


void config::Config::show_config(ConfigItem* _contents,
                                 int depth,
                                 int* result_size,
                                 bool no_output,
                                 std::stringstream* out_stream){
    if(_contents != nullptr){
        ConfigItem* tmp_node = nullptr;
        int tmp_size = 0;
        int extra = 0;
        std::string tmp_str;

        if(no_output && _contents->is_empty) (*result_size)++;

        // find max length
        unsigned int max_length = 0;
        // calculate padding for item names
        for (unsigned int i = 0; i < _contents->children.size(); i++)
            if (!_contents->children[i]->is_template &&
                _contents->children[i]->node_type == CONFIG_NT_ITEM) {
                tmp_node = _contents->children[i];
                if (tmp_node->name.size() +
                        (tmp_node->node_state != CONFIG_NS_READY ? 1 : 0) >
                    max_length)
                    max_length =
                        tmp_node->name.size() +
                        (tmp_node->node_state != CONFIG_NS_READY ? 1 : 0);
            }
        // loop contents
        for(unsigned int i = 0; i<_contents->children.size(); i++){
            tmp_node = _contents->children[i];
            // skip template node
            if(tmp_node->is_template) continue;

            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){

                // check group size
                tmp_size = 0;
                show_config(tmp_node, depth + 1, &tmp_size, true, out_stream);

                if(tmp_size > 0){
                    // padding
                    for(int j = 0; j<depth; j++){
                        if(!no_output) *out_stream << "\t";
                    }
                    if(!no_output) *result_size += depth;

                    // name and open block
                    if(!no_output){
                        extra = 0;
                        // node state
                        switch(tmp_node->node_state){
                            case CONFIG_NS_DELETED:
                                tmp_str = "-";
                                extra++;
                                break;

                            case CONFIG_NS_MODIFIED:
                                tmp_str = "+";
                                extra++;
                                break;

                            default:
                                tmp_str = "";
                                break;
                        }
                        // node name
                        tmp_str.append(tmp_node->name);

                        if(!tmp_node->is_empty){
                            *out_stream << tmp_str << " {" << std::endl;
                            *result_size += tmp_node->name.size() + 3 + extra;

                        }else{
                            *out_stream << tmp_str;
                            *result_size += tmp_node->name.size() + extra;

                        }
                    }

                    // children
                    tmp_size = 0;
                    show_config(tmp_node, depth + 1, &tmp_size, no_output, out_stream);
                    *result_size += tmp_size;


                    // padding
                    if(!no_output){
                        for(int j = 0; j<depth; j++) *out_stream << "\t";
                        *result_size += depth;
                    }

                    // close block
                    if(!no_output){
                        if(!tmp_node->is_empty){
                            *out_stream << "}" << std::endl;
                            *result_size += 2;

                        }else{
                            *out_stream << std::endl;
                            *result_size += 1;

                        }
                    }
                }

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){

                // padding
                if(!no_output){
                    for(int j = 0; j<depth; j++) *out_stream << "\t";
                    *result_size += depth;
                }

                // name and value
                if(!no_output){
                    extra = 0;
                    // node state
                    switch(tmp_node->node_state){
                        case CONFIG_NS_DELETED:
                            tmp_str = "-";
                            extra++;
                            break;

                        case CONFIG_NS_MODIFIED:
                            tmp_str = "+";
                            extra++;
                            break;

                        default:
                            tmp_str = "";
                            break;
                    }
                    // node name
                    tmp_str.append(tmp_node->name);

                    *out_stream << tmp_str << " ";
                    *out_stream << std::setfill(' ') << std::setw(max_length - tmp_str.size() + 1);
                    *out_stream << "\"" << tmp_node->new_value << "\"" << std::endl;

                    *result_size += tmp_str.size() + tmp_node->new_value.size()  + 4 + extra;

                }else{
                    *result_size += tmp_node->new_value.size();
                }
            }
        }
    }
}


void config::Config::show_config(ConfigItem* _contents,
                                 int depth,
                                 int* result_size,
                                 bool no_output,
                                 WINDOW* win){
    if(_contents != nullptr){
        ConfigItem* tmp_node = nullptr;
        int tmp_size = 0;
        int extra = 0;
        std::string tmp_str;
        // loop contents
        for(unsigned int i = 0; i<_contents->children.size(); i++){
            tmp_node = _contents->children[i];
            // skip template node
            if(tmp_node->is_template) continue;
            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){

                // check group size
                tmp_size = 0;
                show_config(tmp_node, depth + 1, &tmp_size, true, win);

                if(tmp_size > 0){
                    // padding
                    for(int j = 0; j<depth; j++){
                        if(!no_output) wprintw(win, "\t");
                    }
                    if(!no_output) *result_size += depth;

                    // name and open block
                    if(!no_output){
                        extra = 0;
                        // node state
                        switch(tmp_node->node_state){
                            case CONFIG_NS_DELETED:
                                tmp_str = "-";
                                extra++;
                                break;

                            case CONFIG_NS_MODIFIED:
                                tmp_str = "+";
                                extra++;
                                break;

                            default:
                                tmp_str = "";
                                break;
                        }
                        // node name
                        tmp_str.append(tmp_node->name);

                        wprintw(win, "%s {\n", tmp_str.c_str());
                        *result_size += tmp_node->name.size() + 3 + extra;
                    }

                    // children
                    tmp_size = 0;
                    show_config(tmp_node, depth + 1, &tmp_size, no_output, win);
                    *result_size += tmp_size;


                    // padding
                    if(!no_output){
                        for(int j = 0; j<depth; j++) wprintw(win, "\t");
                        *result_size += depth;
                    }

                    // close block
                    if(!no_output){
                        wprintw(win, "}\n");
                        *result_size += 2;
                    }

                }

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){

                // padding
                if(!no_output){
                    for(int j = 0; j<depth; j++) wprintw(win, "\t");
                    *result_size += depth;
                }

                // name and value
                if(!no_output){
                    extra = 0;
                    // node state
                    switch(tmp_node->node_state){
                        case CONFIG_NS_DELETED:
                            tmp_str = "-";
                            extra++;
                            break;

                        case CONFIG_NS_MODIFIED:
                            tmp_str = "+";
                            extra++;
                            break;

                        default:
                            tmp_str = "";
                            break;
                    }
                    // node name
                    tmp_str.append(tmp_node->name);

                    wprintw(win, "%s\t\"%s\"\n", tmp_str.c_str(), tmp_node->new_value.c_str());
                    *result_size += tmp_str.size() + tmp_node->new_value.size()  + 4 + extra;


                }else{
                    *result_size += tmp_node->new_value.size();
                }
            }
        }
    }
}


void config::Config::show_config(ConfigItem* _contents,
                                 int depth,
                                 int* result_size,
                                 bool ncurses,
                                 bool no_output){
    if(_contents != nullptr){
        ConfigItem* tmp_node = nullptr;
        int tmp_size = 0;
        int extra = 0;
        std::string tmp_str;
        // loop contents
        for(unsigned int i = 0; i<_contents->children.size(); i++){
            tmp_node = _contents->children[i];
            // skip template node
            if(tmp_node->is_template) continue;
            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){

                // check group size
                tmp_size = 0;
                show_config(tmp_node, depth + 1, &tmp_size, ncurses, true);

                if(tmp_size > 0){
                    // padding
                    for(int j = 0; j<depth; j++){
                        if(!no_output){
                            if(ncurses) printw("\t"); else std::cout << "\t";

                        }
                    }
                    if(!no_output) *result_size += depth;

                    // name and open block
                    if(!no_output){
                        extra = 0;
                        // node state
                        switch(tmp_node->node_state){
                            case CONFIG_NS_DELETED:
                                tmp_str = "-";
                                extra++;
                                break;

                            case CONFIG_NS_MODIFIED:
                                tmp_str = "+";
                                extra++;
                                break;

                            default:
                                tmp_str = "";
                                break;
                        }
                        // node name
                        tmp_str.append(tmp_node->name);

                        if(ncurses) printw("%s {\n", tmp_str.c_str());
                        else std::cout << tmp_str << " {" << std::endl;
                        *result_size += tmp_node->name.size() + 3 + extra;
                    }

                    // children
                    tmp_size = 0;
                    show_config(tmp_node, depth + 1, &tmp_size, ncurses, no_output);
                    *result_size += tmp_size;


                    // padding
                    if(!no_output){
                        for(int j = 0; j<depth; j++){
                            if(ncurses) printw("\t"); else std::cout << "\t";
                        }
                        *result_size += depth;
                    }

                    // close block
                    if(!no_output){
                        if(ncurses) printw("}\n"); else std::cout << "}" << std::endl;

                        *result_size += 2;
                    }

                }

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM &&
                     (tmp_node->new_value != "" || tmp_node->node_state == CONFIG_NS_DELETED)){

                // padding
                if(!no_output){
                    for(int j = 0; j<depth; j++){
                        if(ncurses) printw("\t"); else std::cout << "\t";
                    }
                    *result_size += depth;
                }

                // name and value
                if(!no_output){
                    extra = 0;
                    // node state
                    switch(tmp_node->node_state){
                        case CONFIG_NS_DELETED:
                            tmp_str = "-";
                            extra++;
                            break;

                        case CONFIG_NS_MODIFIED:
                            tmp_str = "+";
                            extra++;
                            break;

                        default:
                            tmp_str = "";
                            break;
                    }
                    // node name
                    tmp_str.append(tmp_node->name);

                    if(ncurses){
                        printw("%s\t\"%s\"\n", tmp_str.c_str(), tmp_node->new_value.c_str());
                    }else{
                        std::cout << tmp_str << "\t\"" << tmp_node->new_value.c_str() << "\"" << std::endl;
                    }

                    *result_size += tmp_str.size() + tmp_node->new_value.size()  + 4 + extra;


                }else{
                    *result_size += tmp_node->new_value.size();
                }
            }
        }
    }
}

void config::Config::show_config(ConfigItem* _contents, unsigned char* result, int* result_size, int depth){
    if(_contents != nullptr && result != nullptr && result_size != nullptr){
        ConfigItem* tmp_node = nullptr;
        int tmp_size = 0;
        // loop contents
        for(unsigned int i = 0; i<_contents->children.size(); i++){
            tmp_node = _contents->children[i];
            // skip template node
            if(tmp_node->is_template) continue;
            // config block
            if(tmp_node->node_type == CONFIG_NT_BLOCK){
                // padding
                for(int j = 0; j<depth; j++) *(result++) = '\t';
                (*result_size) += depth;

                // name
                memcpy(result, tmp_node->name.c_str(), tmp_node->name.size());
                result += tmp_node->name.size();

                // open block
                memcpy(result, " {\n", 3);
                (*result_size) += tmp_node->name.size() + 3;
                result += 3;

                // children
                tmp_size = 0;
                show_config(tmp_node, result, &tmp_size, depth + 1);
                result += tmp_size;

                // padding
                for(int j = 0; j<depth; j++) *(result++) = '\t';
                (*result_size) += depth;

                // close block
                memcpy(result, "}\n", 2);
                result += 2;
                (*result_size) += tmp_size + 2;

                // rewind if block is empty
                if(tmp_size == 0){
                    result -= (depth*2 + tmp_node->name.size() + 5);
                    (*result_size) -= (depth*2 + tmp_node->name.size() + 5);
                }

                // config item
            }else if(tmp_node->node_type == CONFIG_NT_ITEM && tmp_node->new_value != ""){

                // padding
                for(int j = 0; j<depth; j++) *(result++) = '\t';
                (*result_size) += depth;

                // name
                memcpy(result, tmp_node->name.c_str(), tmp_node->name.size());
                result += tmp_node->name.size();
                memcpy(result, "\t\"", 2);
                (*result_size) += tmp_node->name.size() + 2;
                result += 2;

                // type
                memcpy(result, tmp_node->new_value.c_str(), tmp_node->new_value.size());
                result += tmp_node->new_value.size();
                memcpy(result, "\"\n", 2);
                (*result_size) += tmp_node->new_value.size() + 2;
                result += 2;
            }
        }
    }
}

void config::Config::search_fsys(std::string* path, ConfigItem* result){
    if(path != nullptr && result != nullptr){
        char chr[path->size() + 1];
        char* pch = nullptr;
        DIR* dir;
        dirent* ent;
        std::string full_path("/");
        std::string tmp_path;
        ConfigItem* tmp_item = nullptr;
        char *sptr = nullptr;
        // zero mem
        memset(chr, 0, path->size() + 1);

        // check for path contents
        // if no tokens exist, do not tokenize
        if(*path == "/") pch = &(*path)[0];
        // tokenize
        else{
            memcpy(chr, path->c_str(), path->size());
            pch = strtok_r(chr, "/", &sptr);
        }


        // loop
        while(pch != nullptr){
            // free mem
            std::all_of(result->children.cbegin(), result->children.cend(),
                        [](ConfigItem *n) {
                            delete n;
                            return true;
                        });
            result->children.clear();
            tmp_path = pch;
            // if dir selected, do not list contents, stop processing
            if(tmp_path == "."){
                tmp_item = new ConfigItem();
                tmp_item->name.append(tmp_path);
                result->children.push_back(tmp_item);
                if(full_path == "/") full_path.append(tmp_path);
                else full_path.append("/" + tmp_path);
                // correct path data
                *path = full_path;
                return;
            }
            // open dir
            dir = opendir(full_path.c_str());
            if(full_path == "/") full_path = "";
            // if dir
            if(dir != nullptr) {
                // get dir contents
                while ((ent = readdir(dir)) != nullptr) {
                    if ((strcmp(ent->d_name, "..") != 0) &&
                        (tmp_path.compare(0,
                                          tmp_path.size(),
                                          ent->d_name,
                                          0,
                                          tmp_path.size()) == 0)) {
                        tmp_item = new ConfigItem();
                        tmp_item->name.append(ent->d_name);
                        result->children.push_back(tmp_item);
                    }
                }
                // perfect match
                if(result->children.size() == 1) full_path.append("/" + result->children[0]->name);
                // more results
                else if(result->children.size() > 0){
                    if(tmp_path != "/"){
                        // assume min size of 100
                        unsigned int min_size = 100;
                        // find shortest string
                        for (unsigned int j = 0; j < result->children.size();
                             j++)
                            if (result->children[j]->name.size() < min_size)
                                min_size = result->children[j]->name.size();
                        // set max_match to current min_size
                        unsigned int max_match = min_size;
                        // get common starting substring
                        for (unsigned int j = 1; j < result->children.size();
                             j++) {
                            for (unsigned int k = 0; k < min_size; k++) {
                                if (result->children[j]->name[k] !=
                                    result->children[0]->name[k]) {
                                    if (k < max_match) max_match = k;
                                    break;
                                }
                            }
                        }
                        // set max matched substr
                        tmp_path = result->children[0]->name.substr(0, max_match);

                        // check exact match
                        for(unsigned int j = 0; j<result->children.size(); j++){
                            if(max_match == result->children[j]->name.size()){
                                tmp_path = result->children[j]->name;
                                // save match
                                ConfigItem* ti = result->children[j];
                                // free mem
                                for (unsigned int i = 0;
                                     i < result->children.size(); i++)
                                    if (i != j) delete result->children[i];
                                // clear
                                result->children.clear();
                                // add saved match
                                result->children.push_back(ti);
                                break;
                            }

                        }
                        // update full path
                        full_path.append("/" + tmp_path);
                    }
                    // no results
                }else{
                    // if not in zero level, assume new dir/file
                    if(tmp_path != "/"){
                        // free mem
                        std::all_of(result->children.cbegin(),
                                    result->children.cend(), [](ConfigItem *n) {
                                        delete n;
                                        return true;
                                    });
                        result->children.clear();
                        tmp_item = new ConfigItem();
                        tmp_item->name.append(tmp_path);
                        result->children.push_back(tmp_item);
                        full_path.append("/" + tmp_path);
                    }

                }

                // close dir
                closedir (dir);
                // next token if strtok already initialized
                if(*path != "/") {
                    pch = strtok_r(nullptr, "/", &sptr);
                }
                }
                else {
                    break;
                }
        }

        // check if perfect match is directory
        if(result->children.size() == 1 || full_path == ""){
            if(full_path == ""){
                dir = opendir("/");
                full_path = "";
            }else dir = opendir(full_path.c_str());
            // if dir
            if(dir != nullptr){
                full_path.append("/");
                // free mem
                std::all_of(result->children.cbegin(),
                            result->children.cend(), [](ConfigItem *n) {
                                delete n;
                                return true;
                            });
                result->children.clear();
                // lit dir contents
                while ((ent = readdir (dir)) != nullptr) {
                    if(strcmp(ent->d_name, "..") != 0){
                        tmp_item = new ConfigItem();
                        tmp_item->name = ent->d_name;
                        result->children.push_back(tmp_item);

                    }

                }
                closedir(dir);

            }

        }

        // correct path data
        *path = full_path;
    }
}


void config::Config::search_definition(ConfigItem* def,
                                       int current_level,
                                       int target_level,
                                       std::string* target,
                                       ConfigItem* result){
    if(def != nullptr && target != nullptr && result != nullptr){
        ConfigItem* tmp_ci = nullptr;
        // child count
        int n = def->children.size();
        for(int i = 0; i<n; i++){
            tmp_ci = def->children[i];
            if(!tmp_ci->is_template){
                // check if at the right level
                if(current_level != target_level){
                    search_definition(tmp_ci, current_level + 1, target_level, target, result);
                    // right level
                }else{
                    // start index (check for SKIP AUTO COMPLETION '!' flag)
                    int si = ((*target)[0] == '!' ? 1 : 0);
                    // length
                    int l = (si == 1 ? target->length() - 1 : target->length());
                    // other string
                    std::string other_str(*target, si, l);
                    // compare
                    if (tmp_ci->name.compare(0,
                                             other_str.length(),
                                             other_str) == 0)
                        result->children.push_back(tmp_ci);
                }
            }
        }
    }
}

void config::Config::print_cfg_def(bool show_val,
                                   bool show_desc,
                                   ConfigItem* def,
                                   int level,
                                   int max_levels,
                                   WINDOW* win){
    if(def != nullptr){
        std::string* tmp_val = nullptr;
        // child count
        unsigned int n = def->children.size();
        // find max length
        unsigned int max_length = 0;
        // calculate padding for item names
        for (unsigned int i = 0; i < n; i++)
            if (def->children[i]->name.size() > max_length)
                max_length =
                    def->children[i]->name.size() +
                    (def->children[i]->node_state != CONFIG_NS_READY ? 1 : 0);
        ++max_length;
        // find max value length
        unsigned int max_val_length = 0;
        // calculate padding for item values
        if (show_val) {
            for (unsigned int i = 0; i < n; i++)
                if (def->children[i]->new_value.size() > max_val_length)
                    max_val_length = def->children[i]->new_value.size();
            ++max_val_length;
        }
        // tmp strings
        std::string tmp_name;
        std::string tmp_prefix;
        // loop nodes
        for(unsigned int i = 0; i<n; i++){
            // node state
            switch(def->children[i]->node_state){
                case CONFIG_NS_MODIFIED:
                    tmp_prefix = "+";
                    wattron(win, COLOR_PAIR(4));
                    tmp_val = &def->children[i]->new_value;
                    break;

                case CONFIG_NS_DELETED:
                    tmp_prefix = "-";
                    wattron(win, COLOR_PAIR(1));
                    tmp_val = &def->children[i]->new_value;
                    break;

                default:
                    tmp_prefix = "";
                    tmp_val = &def->children[i]->value;
                    break;
            }
            // prefix
            wprintw(win, "%*s", max_length - def->children[i]->name.size(), tmp_prefix.c_str());
            wattrset(win, A_NORMAL);

            // node type
            switch(def->children[i]->node_type){
                case CONFIG_NT_BLOCK: wattron(win, COLOR_PAIR(2)); break;
                case CONFIG_NT_CMD: wattron(win, COLOR_PAIR(4)); break;
                case CONFIG_NT_ITEM:
                case CONFIG_NT_PARAM: wattron(win, COLOR_PAIR(5)); break;
                default: wattrset(win, A_NORMAL); break;

            }

            // node name
            tmp_name = def->children[i]->name;
            wprintw(win, "%s", tmp_name.c_str());

            // value
            if(*tmp_val != "" && show_val){
                wattron(win, COLOR_PAIR(6));
                wprintw(win, " [");
                wprintw(win, "%*s", max_val_length, tmp_val->c_str());
                wprintw(win, " ]");
                wattroff(win, COLOR_PAIR(6));
            }
            // description
            if(def->children[i]->desc != "" && show_desc){
                wattrset(win, A_NORMAL);
                // padding for empty value
                if(*tmp_val == "" && max_val_length > 1) wprintw(win, "%*s", max_val_length + 4 , " ");
                wprintw(win, " - ");
                wattron(win, COLOR_PAIR(3));
                wprintw(win, def->children[i]->desc.c_str());

            }


            // newline
            wprintw(win, "\n");
            wattrset(win, A_NORMAL);

            // next level
            if ((level + 1) < max_levels)
                print_cfg_def(show_val, show_desc, def->children[i], level + 1,
                              max_levels, win);
        }
    }
}


void config::Config::print_cfg_def(bool show_val,
                                   bool show_desc,
                                   ConfigItem* def,
                                   int level,
                                   int max_levels){
    if(def != nullptr){
        std::string* tmp_val = nullptr;
        // child count
        unsigned int n = def->children.size();
        // find max length
        unsigned int max_length = 0;
        // calculate padding
        for (unsigned int i = 0; i < n; i++)
            if (def->children[i]->name.size() > max_length)
                max_length =
                    def->children[i]->name.size() +
                    (def->children[i]->node_state != CONFIG_NS_READY ? 1 : 0);
        ++max_length;
        std::string tmp_name;
        for(unsigned int i = 0; i<n; i++){
            // node state
            switch(def->children[i]->node_state){
                case CONFIG_NS_MODIFIED:
                    tmp_name = "+";
                    tmp_val = &def->children[i]->new_value;
                    break;

                case CONFIG_NS_DELETED:
                    tmp_name = "-";
                    tmp_val = &def->children[i]->new_value;
                    break;

                default:
                    tmp_name = "";
                    tmp_val = &def->children[i]->value;
                    break;
            }
            // node type
            switch(def->children[i]->node_type){
                case CONFIG_NT_BLOCK: attron(COLOR_PAIR(2)); break;
                case CONFIG_NT_CMD: attron(COLOR_PAIR(4)); break;
                case CONFIG_NT_ITEM:
                case CONFIG_NT_PARAM: attron(COLOR_PAIR(5)); break;
                default: attrset(A_NORMAL); break;

            }
            // node name
            tmp_name.append(def->children[i]->name);

            printw("%*s", max_length, tmp_name.c_str());
            if(*tmp_val != "" && show_val){
                attron(COLOR_PAIR(4));
                printw(" ** [");
                printw(tmp_val->c_str());
                printw("] ** ");
                attroff(COLOR_PAIR(4));
            }
            if(def->children[i]->desc != "" && show_desc){
                printw(" - ");
                attrset(A_NORMAL);
                attron(COLOR_PAIR(3));
                printw(def->children[i]->desc.c_str());

            }
            printw("\n");
            attrset(A_NORMAL);

            // next level
            if ((level + 1) < max_levels)
                print_cfg_def(show_val, show_desc, def->children[i], level + 1,
                              max_levels);
        }
    }
}


void config::Config::generate_path(ConfigItem* def, std::string* result){
    if ((def != nullptr) &&
        (result != nullptr) &&
        (def->node_type == CONFIG_NT_BLOCK) &&
        (def->parent != nullptr)) {

        *result = "/" + def->name + *result;
        generate_path(def->parent, result);
    }
}
config::ConfigItem* config::Config::get_definition_root(){
    return definition;
}

config::ConfigItem* config::Config::get_definition_wn(){
    return current_def_path;
}

config::ConfigItem* config::Config::get_cmd_tree(){
    return cmd_tree;
}

void config::Config::set_definition_wn(ConfigItem* _def_node){
    current_def_path = _def_node;
}



void config::Config::copy_nodes(ConfigItem* source, ConfigItem* dest, ConfigNodeState new_state){
    if(source != nullptr && dest != nullptr){
        ConfigItem* tmp_new_node = nullptr;
        // loop children
        for(unsigned int i = 0; i<source->children.size(); i++){
            tmp_new_node = new ConfigItem();
            tmp_new_node->is_template = source->children[i] ->is_template;
            tmp_new_node->is_empty = source->children[i] ->is_empty;
            tmp_new_node->node_type = source->children[i]->node_type;
            tmp_new_node->node_state = (new_state == CONFIG_NS_UNKNOWN
                                            ? source->children[i]->node_state
                                            : new_state);
            tmp_new_node->type = source->children[i]->type;
            tmp_new_node->name = source->children[i]->name;
            tmp_new_node->desc = source->children[i]->desc;
            tmp_new_node->value = source->children[i]->value;
            tmp_new_node->new_value = source->children[i]->new_value;
            tmp_new_node->sort_node = source->children[i]->sort_node;
            tmp_new_node->parent = dest;
            // add to new block node
            dest->children.push_back(tmp_new_node);
            // process children
            copy_nodes(source->children[i], tmp_new_node, new_state);
        }

    }
}

void config::Config::discard(ConfigItem* _definition){
    if(_definition != nullptr){
        ConfigItem* tmp_item = nullptr;
        unsigned int i = 0;
        // loop children
        while(i < _definition->children.size()){
            // skip template node
            if(!_definition->children[i]->is_template){
                // set child pointer
                tmp_item = _definition->children[i];

                // remove new nodes
                if(tmp_item->is_new){
                    // block node only
                    if(tmp_item->node_type == CONFIG_NT_BLOCK){
                        tmp_item->parent->children.erase(tmp_item->parent->children.begin() + i);
                        delete tmp_item;

                    }

                }else{
                    // check node state
                    switch(tmp_item->node_state){
                        // no action needed, process children
                        case CONFIG_NS_READY:
                            discard(tmp_item);
                            ++i;
                            break;

                            // state change, value update
                            // deleted state
                        case CONFIG_NS_MODIFIED:
                        case CONFIG_NS_DELETED:
                            //
                            tmp_item->node_state = CONFIG_NS_READY;
                            if(tmp_item->node_type == CONFIG_NT_ITEM) tmp_item->new_value = tmp_item->value;
                            discard(tmp_item);
                            ++i;
                            break;

                            // unknown node
                        default:
                            ++i;
                            break;


                    }
                }

            }else ++i;
        }
    }
}


int config::Config::sort(ConfigItem* _definition){
    if(_definition != nullptr){
        ConfigItem* tmp_item = nullptr;
        // loop children
        for(unsigned int i = 0; i<_definition->children.size(); i++){
            // set child pointer
            tmp_item = _definition->children[i];
            // skip item nodes
            if(tmp_item->node_type != CONFIG_NT_BLOCK) continue;
            // skip template node
            if(tmp_item->is_template) continue;
            // check if sortable
            if(tmp_item->sort_node == nullptr){
                sort(tmp_item);
                continue;
            }
            // sort
            ConfigItemSort cfg_sort;
            std::sort(tmp_item->parent->children.begin() + 1, tmp_item->parent->children.end(), cfg_sort);
            // process children
            sort(tmp_item);
        }
    }
    return 0;
}

int config::Config::commit(ConfigItem* _definition, bool pretend){
    if(_definition != nullptr){
        ConfigItem* tmp_item = nullptr;
        int res = 0;
        unsigned int i = 0;
        // loop children
        while(i < _definition->children.size()){
            // skip template node
            if(!_definition->children[i]->is_template){
                // set child pointer
                tmp_item = _definition->children[i];
                // set new flag to false
                tmp_item->is_new = false;
                // check node state
                switch(tmp_item->node_state){
                    // no action needed, process children
                    case CONFIG_NS_READY:
                        res += commit(tmp_item, pretend);
                        ++i;
                        break;

                        // state change, value update
                    case CONFIG_NS_MODIFIED:
                        ++res;
                        if(!pretend){
                            tmp_item->node_state = CONFIG_NS_READY;
                            if(tmp_item->node_type == CONFIG_NT_ITEM) tmp_item->value = tmp_item->new_value;

                        }
                        res += commit(tmp_item, pretend);
                        ++i;
                        break;

                        // deleted state
                    case CONFIG_NS_DELETED:
                        ++res;
                        if(!pretend){
                            // block node, delete template based node
                            if(tmp_item->node_type == CONFIG_NT_BLOCK){
                                tmp_item->parent->children.erase(tmp_item->parent->children.begin() + i);
                                delete tmp_item;

                                // item node set value to empty string
                            }else if(tmp_item->node_type == CONFIG_NT_ITEM){
                                tmp_item->node_state = CONFIG_NS_READY;
                                tmp_item->value = "";
                                tmp_item->new_value = "";
                                ++i;

                            }

                        }else ++i;
                        break;

                        // unknown node
                    default:
                        ++i;
                        break;


                }
            }else ++i;
        }
        return res;
    }
    return 0;
}


config::ConfigItem* config::Config::find_node(ConfigItem* _needle, ConfigItem* _stack){
    if(_needle != nullptr && _stack != nullptr){
        // check root
        if(_needle == _stack) return _stack;
        // check children
        for(unsigned int i = 0; i<_needle->children.size(); i++){
            // recursion
            if(find_node(_needle->children[i], _stack) != nullptr) return _stack;
        }
    }
    // not found
    return nullptr;
}

std::map<config::UserId, config::UserInfo*, config::UserIdCompare>* config::Config::get_usr_path_map(){
    return &usr_path_map;
}


config::UserInfo* config::Config::get_definition_wn(const UserId* _usr_id){
    if(usr_path_map.find(*_usr_id) != usr_path_map.end()) return usr_path_map[*_usr_id];
    return nullptr;
}

void config::Config::reset_all_wns(){
    // loop
    for(auto it = usr_path_map.begin(); it != usr_path_map.end(); ++it) {
        it->second->wnode = get_definition_root();
    }
}


void config::Config::update_definition_wn(const UserId* _usr_id){
    auto it = usr_path_map.find(*_usr_id);

    // user info exists
    if(it != usr_path_map.end()){
        UserInfo* usr_info = it->second;
        usr_info->timestamp = time(nullptr);

        // new user info
    }else{
        auto usr_info = new UserInfo(get_definition_root());
        usr_path_map[*_usr_id] = usr_info;

    }

}


void config::Config::set_definition_wn(const UserId* _usr_id, UserInfo* _usr_info){
    auto it = usr_path_map.find(*_usr_id);
    // free previous
    if(it != usr_path_map.end()) delete it->second;
    // add new one
    usr_path_map[*_usr_id] = _usr_info;

}

void config::Config::remove_wn_user(const UserId* _usr_id){
    // find and free
    auto it = usr_path_map.find(*_usr_id);
    if(it != usr_path_map.end()) delete it->second;
    // erase from map
    usr_path_map.erase(*_usr_id);
}


void config::Config::auto_complete(ConfigModeType* mode,
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
                                   ConfigItem* tmp_node_lst){
    std::string tmp_str;
    std::string tmp_err;
    if(def != nullptr && line != nullptr){
        *error_count = 0;
        // reset result size
        *result_size = 0;
        // check for line tokens
        if(line_size > 0){
            bool param_found = false;
            bool special_ac = false;
            // index 0 is not used since it represents mode information(get/set)
            // already contained in mode argument
            for(int i = 0; i<line_size; i++){
                // curent line token
                tmp_str = line[i];
                // check if in SET or CMD mode
                if(*last_found != nullptr && (*mode == CONFIG_MT_SET || *mode == CONFIG_MT_CMD)){
                    // item value detection, check if previous node was CONFIG_NT_ITEM or CONFIG_NT_PARAM
                    if((*last_found)->node_type == CONFIG_NT_ITEM ||
                       (*last_found)->node_type == CONFIG_NT_PARAM){
                        // set fsys ac flag
                        special_ac = false;
                        // clear result for current level
                        result->children.clear();

                        // file system auto complete mode
                        if(tmp_str[0] == '/' && ac_mode == CONFIG_ACM_TAB){
                            // set special ac flag (filesystem ac)
                            special_ac = true;
                            // fsys auto complete
                            search_fsys(&tmp_str, result);
                            --(*result_size);
                            line[i] = tmp_str;
                            // free mem later
                            for (unsigned int j = 0; j < result->children.size(); j++){
                                tmp_node_lst->children.push_back(result->children[j]);
                            }
                            // if perfect match
                            if(result->children.size() == 1){
                                // set fsys ac flag
                                special_ac = false;
                                (*result_size)++;
                            }

                            // special auto complete mode
                        }else if(tmp_str[0] == '?' && ac_mode == CONFIG_ACM_TAB){
                            // set special ac flag (context specific ac)
                            special_ac = true;
                            --(*result_size);
                            line[i] = "";
                            void* tmp_args[5];
                            tmp_args[0] = result;
                            tmp_args[1] = tmp_node_lst;
                            tmp_args[2] = &(*last_found)->type;
                            tmp_args[3] = get_pattern(&(*last_found)->type);
                            tmp_args[4] = this;
                            (*last_found)->special_ac(tmp_args, 5);

                        }

                        (*result_size)++;
                        param_found = true;
                        // check pattern
                        const CFGPattern* ptrn = get_pattern(&(*last_found)->type);
                        if(ptrn != nullptr){
                            // set new value
                            if(pattern_valid(&tmp_str, &(*last_found)->type, *last_found)){
                                // change value/state only in enter ac_mode
                                if(ac_mode == CONFIG_ACM_ENTER && !pretend){
                                    (*last_found)->new_value = tmp_str;
                                    if (*mode != CONFIG_MT_CMD)
                                        (*last_found)->node_state = CONFIG_NS_MODIFIED;
                                }
                            }else{
                                // create error msg
                                tmp_err = "";
                                tmp_err.append("Item \"");
                                tmp_err.append((*last_found)->name);
                                tmp_err.append("\" contains invalid \"");
                                tmp_err.append((*last_found)->type);
                                tmp_err.append("\" value \"");
                                tmp_err.append(tmp_str);
                                tmp_err.append("\"!\n");
                                // set error message, inc count
                                error_result[(*error_count)++] = tmp_err;
                            }
                        }else if(ac_mode == CONFIG_ACM_ENTER){
                            // remove enclosing literals
                            if(tmp_str[0] == '"' && tmp_str[tmp_str.size() - 1] == '"'){
                                tmp_str.erase(tmp_str.begin(), tmp_str.begin() + 1);
                                tmp_str.erase(tmp_str.end() - 1, tmp_str.end());
                            }

                            if(!pretend){
                                (*last_found)->new_value = tmp_str;
                                if(*mode != CONFIG_MT_CMD) (*last_found)->node_state = CONFIG_NS_MODIFIED;

                            }
                        }

                    }
                    // detect SET operation in GET mode
                }else if((*last_found != nullptr) && ((*last_found)->node_type == CONFIG_NT_ITEM)){
                    result->children.clear();
                    error_result[(*error_count)++] = "Cannot SET value in SHOW mode!\n";
                    return;
                }

                // search matching nodes if current node is note param value
                if(!param_found) {
                    // clear result for current level
                    result->children.clear();
                    // check if definition exists
                    if(!def->children.empty()){
                        // template
                        if(def->children[0]->is_template){
                            ConfigItem* tmpl_node = def->children[0];
                            // search defintion
                            search_definition(def, 0, 0, &tmp_str, result);
                            // special '!' at the beginning disables AUTO COMPLETION
                            if((tmp_str[0] == '!' ||
                               result->children.empty()) &&
                               *mode == CONFIG_MT_SET){
                                // check for name conflict in AUTO COMPLETION DISABLE mode
                                if(tmp_str[0] == '!'){
                                    // temp string
                                    std::string tmp_no_ac_str(tmp_str);
                                    // remove '!' prefix
                                    tmp_no_ac_str.erase(0, 1);
                                    // check for results
                                    if(!result->children.empty()){
                                        // loop results
                                        for(unsigned int h = 0; h<result->children.size(); h++){
                                            // check for exact match, return error if match found
                                            if(result->children[h]->name.length() == tmp_no_ac_str.length()){
                                                result->children.clear();
                                                // create error msg
                                                tmp_err = "";
                                                tmp_err.append("Item \"");
                                                tmp_err.append(tmp_no_ac_str);
                                                tmp_err.append("\" already exists!\n");
                                                // set error message, inc count
                                                error_result[(*error_count)++] = tmp_err;
                                                return;
                                            }
                                        }

                                    }
                                }

                                // special context help
                                if(tmp_str[0] == '?' && ac_mode == CONFIG_ACM_TAB){
                                    --(*result_size);
                                    line[i] = "";
                                    void* tmp_args[5];
                                    tmp_args[0] = result;
                                    tmp_args[1] = tmp_node_lst;
                                    tmp_args[2] = &tmpl_node->type;
                                    tmp_args[3] = get_pattern(&tmpl_node->type);
                                    tmp_args[4] = this;
                                    if(last_found && *last_found)
                                        (*last_found)->special_ac(tmp_args, 5);
                                    (*result_size)++;
                                    return;
                                }


                                // check is pattern exists
                                const CFGPattern* ptrn = get_pattern(&tmpl_node->type);

                                // check special '!' char (DO NOT AUTO COMPLETE)
                                // remove it from node name
                                if(tmp_str[0] == '!'){
                                    // erase '!' prefix
                                    tmp_str.erase(0, 1);
                                }

                                // validate pattern
                                if(pattern_valid(&tmp_str, &tmpl_node->type, tmpl_node) || ptrn == nullptr){
                                    auto new_node = new ConfigItem();
                                    new_node->node_type = CONFIG_NT_BLOCK;
                                    new_node->node_state = CONFIG_NS_MODIFIED;
                                    new_node->parent = def;
                                    new_node->sort_node = tmpl_node->sort_node;
                                    new_node->name = tmp_str;
                                    new_node->is_new = true;
                                    new_node->is_empty = tmpl_node->is_empty;
                                    // check special '!' char (DO NOT AUTO COMPLETE)
                                    // remove it from node name
                                    if(new_node->name[0] == '!'){
                                        // erase '!' prefix
                                        new_node->name.erase(0, 1);
                                        // clear results
                                        result->children.clear();
                                    }
                                    // copy nodes from template
                                    copy_nodes(tmpl_node, new_node, CONFIG_NS_MODIFIED);
                                    // add new node after template node if in ENTER ac_mode
                                    // or add to tmp_node_lst if in TAB mode
                                    // tmp_node_lst should be freed when result is no longer used
                                    if(ac_mode == CONFIG_ACM_ENTER){
                                        // add to definition
                                        def->children.push_back(new_node);

                                        // add to temp list
                                    }else tmp_node_lst->children.push_back(new_node);
                                    // include new node in result
                                    result->children.push_back(new_node);

                                    // template name error
                                }else{
                                    // create error msg
                                    tmp_err = "";
                                    tmp_err.append("Template \"");
                                    tmp_err.append(tmpl_node->name);
                                    tmp_err.append("\" contains invalid \"");
                                    tmp_err.append(tmpl_node->type);
                                    tmp_err.append("\" name \"");
                                    tmp_err.append(tmp_str);
                                    tmp_err.append("\"!\n");
                                    // set error message, inc count
                                    error_result[(*error_count)++] = tmp_err;
                                    return;

                                }



                            }
                            // regular NON template
                        }else{
                            // search definition
                            search_definition(def, 0, 0, &tmp_str, result);

                        }
                    }
                }
                // single match and not param value which can be auto completed from file system
                if(result->children.size() == 1 && !param_found) {
                    // definition found, inc
                    (*result_size)++;
                    *last_found = result->children[0];
                    // update line if one and only one match found
                    line[i] = result->children[0]->name;
                    // detect mode only once
                    if(*last_found != nullptr && *mode == CONFIG_MT_UNKNOWN){
                        if((*last_found)->node_type == CONFIG_NT_CMD ||
                           (*last_found)->node_type == CONFIG_NT_BLOCK){
                            if((*last_found)->name == "set"){
                                *mode = CONFIG_MT_SET;
                                // switch from cmd_tree to definition
                                def = _current_def_path;
                                // replace result with new definition
                                result->children.clear();
                                result->children.push_back(def);
                            }else if((*last_found)->name == "show"){
                                *mode = CONFIG_MT_SHOW;
                                // switch from cmd_tree to definition
                                def = _current_def_path;
                                // replace result with new definition
                                result->children.clear();
                                result->children.push_back(def);
                            }else if((*last_found)->name == "delete"){
                                *mode = CONFIG_MT_DEL;
                                // switch from cmd_tree to definition
                                def = _current_def_path;
                                // replace result with new definition
                                result->children.clear();
                                result->children.push_back(def);
                            }else if((*last_found)->name == "edit"){
                                *mode = CONFIG_MT_EDIT;
                                // switch from cmd_tree to definition
                                def = _current_def_path;
                                // replace result with new definition
                                result->children.clear();
                                result->children.push_back(def);

                            }else{
                                if((*last_found)->node_type == CONFIG_NT_CMD) *mode = CONFIG_MT_CMD;
                            }
                        }

                        // special cmd mode, stop processing if no params exist in cmd node
                        if((*mode == CONFIG_MT_CMD) && ((*last_found)->children.empty())){
                            return;
                        }

                    }



                    // if not param, search one level deeper
                    if(result->children[0]->node_type == CONFIG_NT_BLOCK ||
                       result->children[0]->node_type == CONFIG_NT_CMD){
                        // go deeper
                        def = result->children[0];
                        *last_found = def;
                        result->children.clear();
                        tmp_str = "";
                        // if in enter ac_mode
                        // if in set mode and last token in deleted state
                        if ((ac_mode == CONFIG_ACM_ENTER) &&
                            (*mode == CONFIG_MT_SET) &&
                            (i == (line_size - 1)) &&
                            ((*last_found)->node_state == CONFIG_NS_DELETED) &&
                            (!pretend)) {
                                (*last_found)->node_state = CONFIG_NS_MODIFIED;
                        }

                        // search available options
                        search_definition(def, 0, 0, &tmp_str, result);

                        // if CMD clear parameter values from previous session
                        if(def->node_type == CONFIG_NT_CMD){
                            for (unsigned int j = 0; j < def->children.size();
                                 j++)
                                if (def->children[j]->node_type == CONFIG_NT_PARAM &&
                                    !pretend)
                                    def->children[j]->new_value = "";
                        }
                    }

                    // multiple matches
                }else{
                    *last_found = nullptr;
                    // param value
                    if(param_found){
                        param_found = false;
                        // if file systetem auto complete finished with perfect match
                        if(!special_ac){
                            // clear result for current level
                            result->children.clear();
                            tmp_str = "";
                            // display all parameters again
                            search_definition(def, 0, 0, &tmp_str, result);

                        }
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
                            if(line[i].size() == max_match && *last_found != nullptr){
                                // definition found, inc
                                (*result_size)++;
                                result->children.clear();
                                // if param, include in result, useful for
                                // auto completion (display param=value list)
                                if ((*last_found)->node_type == CONFIG_NT_ITEM)
                                    result->children.push_back(*last_found);
                                else if ((*last_found)->node_type == CONFIG_NT_BLOCK) {
                                    // if in enter ac_mode
                                    // if in set mode and last token in
                                    // deleted state
                                    if ((ac_mode == CONFIG_ACM_ENTER) &&
                                        (*mode == CONFIG_MT_SET) &&
                                        (i == (line_size - 1)) &&
                                        ((*last_found)->node_state == CONFIG_NS_DELETED)) {
                                        if (!pretend)
                                            (*last_found)->node_state = CONFIG_NS_MODIFIED;
                                    }
                                    // search available options
                                    tmp_str = "";
                                    def = *last_found;
                                    search_definition(def, 0, 0, &tmp_str,
                                                      result);
                                }
                                // update current line
                                line[i] = (*last_found)->name;


                                // set current line item to common substring
                            }else{
                                line[i] = result->children[0]->name.substr(0, max_match);

                            }

                            // error, no match
                        }else{
                            result->children.clear();
                            error_result[(*error_count)++] = "Unknown item or command \"" + line[i] + "\"!\n";

                        }

                        // if not last item, stop processing when multiple lines match
                        if(i != (line_size - 1) && *last_found == nullptr) return;
                    }
                }


            }
        }else{
            search_definition(def, 0, 0, &tmp_str, result);

        }
    }

}

void config::Config::replace_prepare(ConfigItem* _definition){
    if(_definition == nullptr) return;

    ConfigItem* tmp_node = nullptr;
    unsigned int i = 0;
    // loop children
    while(i < _definition->children.size()){
        // current contents node
        tmp_node = _definition->children[i];
        if(tmp_node->is_template){
            // set state of all template based nodes
            if(tmp_node->parent->children.size() > 1){
                // set state of children
                for (unsigned int j = 1;
                     j < tmp_node->parent->children.size(); j++)
                    tmp_node->parent->children[j]->node_state =
                        CONFIG_NS_DELETED;
                // skip template and template based nodes
                i += tmp_node->parent->children.size();
                // next iteration
                continue;
            }
            // item
        }else if(tmp_node->node_type == CONFIG_NT_ITEM){
            tmp_node->node_state = CONFIG_NS_DELETED;

            // non template block
        }else{
            /// set children
            replace_prepare(tmp_node);

        }
        // inc
        ++i;
    }
}


int config::Config::reset(ConfigItem* _definition){
    if(_definition == nullptr) return 0;

    ConfigItem* tmp_node = nullptr;
    for(unsigned int i = 0; i<_definition->children.size(); i++){
        // current contents node
        tmp_node = _definition->children[i];
        if(tmp_node->is_template){
            // remove all template based nodes
            if(tmp_node->parent->children.size() > 1){
                // deallocate
                for (unsigned int j = 1;
                     j < tmp_node->parent->children.size(); j++)
                    delete tmp_node->parent->children[j];
                // remove
                tmp_node->parent->children.erase(
                    tmp_node->parent->children.begin() + 1,
                    tmp_node->parent->children.end());
            }
        }else{
            tmp_node->value = "";
            tmp_node->new_value = "";
            tmp_node->node_state = CONFIG_NS_READY;

        }
        // reset children
        reset(tmp_node);

    }
    return 0;
}

bool config::Config::validate(ConfigItem* _definition, ConfigItem* _contents){
    if(_definition == nullptr || _contents == nullptr) return true;

    bool res;
    ConfigItem* tmp_node = nullptr;
    CFGPattern* tmp_ptrn = nullptr;
    // loop contents
    for(unsigned int i = 0; i<_contents->children.size(); i++){
        bool found = false;
        // current contents node
        tmp_node = _contents->children[i];
        // loop definition
        for(unsigned int j = 0; j<_definition->children.size(); j++){
            // regular NON template definition
            if(!_definition->children[j]->is_template){
                if(tmp_node->name != _definition->children[j]->name)
                    continue;

                // check pattern only for item node
                if(tmp_node->node_type == CONFIG_NT_ITEM){
                    tmp_ptrn = get_pattern(&_definition->children[j]->type);
                    if(tmp_ptrn != nullptr){
                        // validate pattern
                        res = pattern_valid(&tmp_node->value,
                                            &_definition->children[j]->type,
                                            tmp_node);
                        if(!res) return false;
                    }

                }
                // validate children
                res = validate(_definition->children[j], tmp_node);
                // return on error
                if(!res) return false;
                found = true;
                break;

                // template definition
            }else{
                // template node must be a BLOCK node
                if(_contents->children[i]->node_type != CONFIG_NT_BLOCK)
                    return false;
                // create new template based node
                auto new_node = new ConfigItem();
                new_node->node_type = CONFIG_NT_BLOCK;
                new_node->parent = _definition->children[j]->parent;
                new_node->name = tmp_node->name;
                // copy nodes from template
                copy_nodes(_definition->children[j], new_node);
                // validate children
                res = validate(new_node, tmp_node);
                // deallocate
                delete new_node;
                // return on error
                if(!res){
                    // return error
                    return false;
                }
                // set as found
                found = true;
                break;


            }
        }
        // return error
        if(!found) return false;
    }
    // return ok
    return true;
}


int config::Config::merge(ConfigItem* _definition, ConfigItem* _contents, bool set_node_state){
    if(_definition != nullptr && _contents != nullptr){
        int res;
        ConfigItem* tmp_node = nullptr;
        CFGPattern* tmp_ptrn = nullptr;
        ConfigItem* new_node = nullptr;
        // loop contents
        for(unsigned int i = 0; i<_contents->children.size(); i++){
            bool found = false;
            // current contents node
            tmp_node = _contents->children[i];
            // loop definition
            for(unsigned int j = 0; j<_definition->children.size(); j++){
                // regular NON template definition
                if(!_definition->children[j]->is_template){
                    if(tmp_node->name == _definition->children[j]->name){
                        // check pattern only for item node
                        if(tmp_node->node_type == CONFIG_NT_ITEM){
                            tmp_ptrn = get_pattern(&_definition->children[j]->type);
                            // if pattern exists, validate
                            if(tmp_ptrn != nullptr){
                                // set type in contents node
                                tmp_node->type = _definition->children[j]->type;
                                // validate pattern
                                res = pattern_valid(&tmp_node->value,
                                                    &_definition->children[j]->type,
                                                    tmp_node);
                                if(res == 0) return 1;
                            }
                            // if flag is set, do not update NS_READY value
                            // (important for discard when loading cfg files)
                            if(!set_node_state) _definition->children[j]->value = tmp_node->value;
                            // set value
                            _definition->children[j]->new_value = tmp_node->value;
                            // set state flag
                            if(set_node_state) _definition->children[j]->node_state = CONFIG_NS_MODIFIED;

                        }

                        // validate children
                        res = merge(_definition->children[j], tmp_node, set_node_state);
                        // return on error
                        if(res != 0) return res;
                        found = true;
                        break;

                    }
                    // template definition
                }else{
                    // template node must be a BLOCK node
                    if(_contents->children[i]->node_type != CONFIG_NT_BLOCK) return 1;

                    // get pattern
                    tmp_ptrn = get_pattern(&_definition->children[j]->type);
                    // if pattern exists, validate
                    if(tmp_ptrn != nullptr){
                        res = pattern_valid(&tmp_node->name, &_definition->children[j]->type, tmp_node);
                        if(res == 0) return 1;

                    }

                    // only if set_node_state is set (used only when loading new config file)
                    // search for template based node
                    if(set_node_state){
                        new_node = nullptr;
                        // skip template node (zero index) and search for match
                        for(unsigned int k = 1; k<_definition->children.size(); k++){
                            // try to match node
                            if(_definition->children[k]->name == tmp_node->name){
                                // template based node found, set pointer
                                new_node = _definition->children[k];
                                new_node->node_state = CONFIG_NS_MODIFIED;
                                new_node->is_new = false;
                                found = true;
                                break;
                            }
                        }

                    }
                    // create new template based node if set_node_state was not set
                    // or if set_node_state was set and node was not found
                    if(!found){
                        new_node = new ConfigItem();
                        new_node->node_type = CONFIG_NT_BLOCK;
                        new_node->parent = _definition->children[j]->parent;
                        new_node->sort_node = _definition->children[j]->sort_node;
                        new_node->name = tmp_node->name;
                        new_node->is_empty = _definition->children[j]->is_empty;
                        // set state flag
                        if(set_node_state){
                            new_node->node_state = CONFIG_NS_MODIFIED;
                            new_node->is_new = true;
                        }
                        // copy nodes from template
                        copy_nodes(_definition->children[j], new_node);
                    }

                    // merge children
                    res = merge(new_node, tmp_node, set_node_state);
                    // error
                    if(res != 0){
                        // free new node if just created
                        if(!found) delete new_node;
                        // return error
                        return res;
                    }
                    // add node to definition if needed (if just created)
                    if(!found){
                        _definition->children[j]->parent->children.push_back(new_node);
                        // * do not sort nodes with empty flag set
                        // * these nodes are used for lists and should not be sorted
                        if(!new_node->is_empty){
                            // sort
                            ConfigItemSort cfg_sort;
                            std::sort(new_node->parent->children.begin() + 1,
                                      new_node->parent->children.end(),
                                      cfg_sort);
                        }
                    }
                    // set as found
                    found = true;
                    break;


                }
            }
            if(!found) return 1;
        }
    }
    return 0;
}

bool config::Config::validate_definition(ConfigItem* cfg_def){
    if(cfg_def == nullptr) return true;

    for(unsigned int i = 0; i<cfg_def->children.size(); i++){
        // validate template
        if(cfg_def->children[i]->is_template){
            if(cfg_def->children[i]->parent != nullptr){
                // template node parent  should not contain any other nodes
                if(cfg_def->children[i]->parent->children.size() > 1)
                    return false;
            }else return false;
        }
        // validate children
        if(!validate_definition(cfg_def->children[i])) return false;

    }
    return true;
}

void config::Config::add_notification(CfgNotification* cfg_ntf){
    notifications.push_back(cfg_ntf);
}

config::CfgNotification* config::Config::remove_notification(CfgNotification* cfg_ntf){
    for (unsigned int i = 0; i < notifications.size(); i++)
        if (notifications[i] == cfg_ntf) {
            notifications.erase(notifications.begin() + i);
            return cfg_ntf;
        }
    return nullptr;
}

config::CfgNotification* config::Config::get_notification(const std::string* cfg_path){
    for (unsigned int i = 0; i < notifications.size(); i++)
        if (*notifications[i]->get_cfg_path() == *cfg_path) {
            return notifications[i];
        }
    return nullptr;
}



void config::Config::set_transaction_owner(const UserId* _id){
    transaction_owner = *_id;
}

config::UserId config::Config::get_transaction_owner() const{
    return transaction_owner;
}

void config::Config::start_transaction(const UserId* _owner_id){
    transaction_owner = *_owner_id;
    transaction = true;
}

void config::Config::end_transaction(){
    transaction = false;
}

bool config::Config::transaction_started() const{
    return transaction;
}


int config::Config::lock(){
    return pthread_mutex_lock(&mtx_config);
}

int config::Config::unlock(){
    return pthread_mutex_unlock(&mtx_config);

}

config::ConfigItem* config::Config::new_definition(){
    auto new_def = new ConfigItem();
    new_def->name = "ROOT";
    new_def->node_type = config::CONFIG_NT_BLOCK;
    load_definition(new_def);
    return new_def;

}

void config::Config::load_definition(ConfigItem* cfg_def){
    definition = cfg_def;
    current_def_path = definition;
}


config::CFGPattern* config::Config::get_pattern(const std::string* type){
    for (unsigned int i = 0; i < patterns.size(); i++)
        if (patterns[i]->name == *type) return patterns[i];
    return nullptr;
}

bool config::Config::pattern_valid(std::string* value,
                                   const std::string* type,
                                   ConfigItem* cfg_node){
    CFGPattern* ptrn = get_pattern(type);
    if(ptrn == nullptr) return false;

    // check for special NON regex pattern
    if(ptrn->pattern.substr(0, 7) == ":pmcfg:"){

        // minimum size
        // enclosing brackets
        if ((ptrn->pattern.size() > 9) &&
            (ptrn->pattern[7] == '[') &&
            (ptrn->pattern[ptrn->pattern.size() - 1] == ']')) {

            std::string tmp_str = ptrn->pattern.substr(8, ptrn->pattern.size() - 9);
            ConfigItem *tmp_cfg = nullptr;

            // absolute starts with '/'
            if (tmp_str[0] == '/') {
                tmp_str.erase(0, 1);
                // get node list
                tmp_cfg = (*definition)(tmp_str.c_str());

                // relative
            } else {
                // get node list
                if ((cfg_node != nullptr) && (cfg_node->parent != nullptr)) {
                    tmp_cfg = (*cfg_node->parent)(tmp_str.c_str());
                }
            }

            // check if found
            if (tmp_cfg != nullptr) {
                for (unsigned int i = 0; i < tmp_cfg->children.size(); i++){
                    // try to match
                    if ((!tmp_cfg->children[i]->is_template) &&
                        (*value == tmp_cfg->children[i]->name)) {
                        return true;
                    }
                }
            }
        }

        return false;

    }else{
        std::regex regex(ptrn->pattern);
        if((*value)[0] == '"' && (*value)[value->size() - 1] == '"'){
            value->erase(value->begin(), value->begin() + 1);
            value->erase(value->end() - 1, value->end());
        }

        return std::regex_match(*value, regex);

    }

}



void config::Config::add_pattern(CFGPattern* ptrn){
    patterns.push_back(ptrn);
}
