/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <getopt.h>
#include <regex>
#include "sysagent.h"

// filter for scandir
using fs_dir_filter = int (*)(const struct dirent*);

SysagentdDescriptor::SysagentdDescriptor(const char *_type, const char *_desc)
    : mink::DaemonDescriptor(_type, nullptr, _desc) {

    config = new config::Config();

    // set daemon params
    set_param(0, config);

    // default extra param values
    // --gdt-streams
    dparams.set_int(0, 1000);
    // --gdt-stimeout
    dparams.set_int(1, 5);
    // --gdt-smsg-pool
    dparams.set_int(2, 1000);
    // --gdt-sparam-pool
    dparams.set_int(3, 5000);
}

SysagentdDescriptor::~SysagentdDescriptor(){
    // free routing deamons address strings
    std::all_of(rtrd_lst.cbegin(), rtrd_lst.cend(), [](std::string *s) {
        delete s;
        return true;
    });
}

void SysagentdDescriptor::print_help(){
    std::cout << daemon_type << " - " << daemon_description << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -?\thelp" << std::endl;
    std::cout << " -i\tunique daemon id" << std::endl;
    std::cout << " -c\trouter daemon address (ipv4:port)" << std::endl;
    std::cout << " -p\tplugins path" << std::endl;
    std::cout << " -D\tstart in debug mode" << std::endl;
    std::cout << std::endl;
    std::cout << "GDT Options:" << std::endl;
    std::cout << "=============" << std::endl;
    std::cout << " --gdt-streams\t\tGDT Session stream pool\t\t(default = 1000)"
              << std::endl;
    std::cout
        << " --gdt-stimeout\tGDT Stream timeout in seconds\t\t(default = 5)"
        << std::endl;

}

void SysagentdDescriptor::init(){
    init_gdt();
    init_cfg(true);
    init_plugins(plg_dir.c_str());
}

void SysagentdDescriptor::process_args(int argc, char **argv){
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
    int opt;
    int option_index = 0;
    struct option long_options[] = {{"gdt-streams", required_argument, 0, 0},
                                    {"gdt-stimeout", required_argument, 0, 0},
                                    {0, 0, 0, 0}};

    if (argc < 5) {
        print_help();
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt_long(argc, argv, "?c:i:p:D", long_options,
                              &option_index)) != -1) {
        switch (opt) {
        // long options
        case 0:
            if (long_options[option_index].flag != 0)
                break;
            switch (option_index) {
            // gdt-streams
            case 0:
                dparams.set_int(0, atoi(optarg));
                break;

            // gdt-stimeout
            case 1:
                dparams.set_int(1, atoi(optarg));
                break;

            default:
                break;
            }
            break;

        // help
        case '?':
            print_help();
            exit(EXIT_FAILURE);

        // daemon id
        case 'i':
            if (set_daemon_id(optarg) > 0) {
                std::cout << "ERROR: Maximum size of daemon id string is "
                             "15 characters!"
                          << std::endl;
                exit(EXIT_FAILURE);
            }
            break;

        // router daemon address
        case 'c':
            // check pattern (ipv4:port)
            // check if valid
            if (!std::regex_match(optarg, addr_regex)) {
                std::cout << "ERROR: Invalid daemon address format '"
                          << optarg << "'!" << std::endl;
                exit(EXIT_FAILURE);

            } else {
                rtrd_lst.push_back(new std::string(optarg));
            }
            break;

        // plugins directory
        case 'p':
            plg_dir.assign(optarg);
            break;

        // debug mode
        case 'D':
            set_log_level(mink::LLT_DEBUG);
            break;

        default:
            break;
        }
    }

    // check mandatory id
    if (strlen(get_daemon_id()) == 0) {
        std::cout << "ERROR: Daemon id not defined!" << std::endl;
        exit(EXIT_FAILURE);
    }
}

int SysagentdDescriptor::init_cfg(bool _proc_cfg) const {

    return 0;

}

static char** fs_readdir(const char* dir, size_t* size, fs_dir_filter filter){
    // null check
    if(!(dir && size)) return nullptr;
    // vars
    char** res = nullptr;
    struct dirent** fnames = nullptr;
    // scan dir
    int n = scandir(dir, &fnames, filter, &alphasort);
    if(n >= 0){
        *size = n;
        // alloc res
        res = (char**)malloc(sizeof(char*) * n);
        // loop results
        for(int i = 0; i<n; i++){
            res[i] = strdup(fnames[i]->d_name);
            free(fnames[i]);
        }
    }else *size = 0;
    free(fnames);
    return res;
}


void SysagentdDescriptor::init_plugins(const char *pdir){
    int pdl;
    // plugin dir missing, try default
    if (!pdir) {
        return;
    } else
        pdl = strlen(pdir);

    // read plugin dir
    size_t rl;
    char** lst = fs_readdir(pdir, &rl, nullptr);
    if (lst == nullptr) return;

    // copy dir path str
    char* plg_fname = strdup(pdir);
    int l;
    // loop results
    for (int i = 0; i < rl; i++) {
        // only .so files
        if (strstr(lst[i], ".so")) {
            // concat dir path and file path
            l = strlen(lst[i]);
            plg_fname = (char*)realloc(plg_fname, pdl + l + 2);
            strcpy(&plg_fname[pdl], "/");
            strcpy(&plg_fname[pdl + 1], lst[i]);
            // load plugin
            if (plg_mngr.load(plg_fname))
                std::cout << "Loading plugin [" << lst[i] << "]..."
                          << std::endl;
            else
                std::cout << "Cannot load plugin [" << lst[i]
                          << "], mandatory methods not found!" << std::endl;
        }
        // free item
        free(lst[i]);
    }
    // free mem
    free(lst);
    free(plg_fname);


}

void SysagentdDescriptor::init_gdt(){
    // service message manager
    gdtsmm = new gdt::ServiceMsgManager(&idt_map,
                                        nullptr,
                                        nullptr,
                                        dparams.get_pval<int>(2),
                                        dparams.get_pval<int>(3));

    // set daemon params
    set_param(0, config);
    set_param(1, gdtsmm);

    // set service message handlers
    gdtsmm->set_new_msg_handler(&ev_srvcm_rx);
    gdtsmm->set_msg_err_handler(&ev_srvcm_rx.msg_err);

    // start GDT session
    gdts = gdt::init_session(get_daemon_type(),
                             get_daemon_id(),
                             dparams.get_pval<int>(0),
                             dparams.get_pval<int>(1),
                             false,
                             dparams.get_pval<int>(1));

    // connect to routing daemons
    std::smatch grps;
    std::regex rgx("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");


    // loop routing daemons
    for (size_t i = 0; i < rtrd_lst.size(); i++) {
        // separate IP and PORT
        if (!std::regex_search(*rtrd_lst[i], grps, rgx))
            continue;
        // connect to routing daemon
        gdt::GDTClient *gdtc = gdts->connect(grps[1].str().c_str(),
                                             atoi(grps[2].str().c_str()),
                                             16,
                                             nullptr,
                                             0);

        // setup client for service messages
        if (gdtc!= nullptr) {
            // setup service message event handlers
            gdtsmm->setup_client(gdtc);
        }
    }
}

void SysagentdDescriptor::terminate(){
    delete config;

}
