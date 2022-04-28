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

    // ignore SIGPIPE
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

#ifdef MINK_ENABLE_CONFIGD
    config = new config::Config();
    // set daemon params
    set_param(0, config);
#endif
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
    try {
        delete static_cast<PluginsConfig *>(dparams.get_pval<void *>(4));
    } catch (std::exception &e) {
        // pass
    }
    delete gdtsmm;
}

void SysagentdDescriptor::print_help(){
    std::cout << daemon_type << " - " << daemon_description << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -?\thelp" << std::endl;
    std::cout << " -i\tunique daemon id" << std::endl;
    std::cout << " -h\tlocal IPv4 address" << std::endl;
    std::cout << " -c\trouter daemon address (ipv4:port)" << std::endl;
    std::cout << " -p\tplugins path" << std::endl;
    std::cout << " -s\tpath to sqlite database file" << std::endl;
    std::cout << " -D\tstart in debug mode" << std::endl;
    std::cout << std::endl;
    std::cout << "Plugins:" << std::endl;
    std::cout << "=============" << std::endl;
    std::cout << " --plugins-cfg      Plugins configuration file"
              << std::endl;
    std::cout << std::endl;
    std::cout << "GDT Options:" << std::endl;
    std::cout << "=============" << std::endl;
    std::cout << " --gdt-streams      GDT Session stream pool            (default = 1000)"
              << std::endl;
    std::cout << " --gdt-stimeout     GDT Stream timeout in seconds      (default = 5)"
              << std::endl;
    std::cout << " --gdt-stimeout     GDT Stream timeout in seconds      (default = 5)"
              << std::endl;
    std::cout << " --gdt-smsg-pool    GDT Service message pool           (default = 1000)"
              << std::endl;
    std::cout << " --gdt-sparam-pool  GDT Service message parameter pool (default = 5000)"
              << std::endl;

}

void SysagentdDescriptor::init() {
    init_gdt();
#ifdef MINK_ENABLE_CONFIGD
    if (init_cfg(true)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "Cannot find CFGD connection, terminating...");
        exit(EXIT_FAILURE);
    }
#endif
    init_plugins(plg_dir.c_str());
}

void SysagentdDescriptor::process_args(int argc, char **argv){
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
    std::regex ipv4_regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    int opt;
    int option_index = 0;
    struct option long_options[] = {{"gdt-streams", required_argument, 0, 0},
                                    {"gdt-stimeout", required_argument, 0, 0},
                                    {"gdt-smsg-pool", required_argument, 0, 0},
                                    {"gdt-sparam-pool", required_argument, 0, 0},
                                    {"plugins-cfg", required_argument, 0, 0},
                                    {0, 0, 0, 0}};

    if (argc < 5) {
        print_help();
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt_long(argc, argv, "?c:i:h:p:s:D", long_options,
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

            // gdt-smsg-pool
            case 2:
                dparams.set_int(2, atoi(optarg));
                break;

            // gdt-sparam-pool
            case 3:
                dparams.set_int(3, atoi(optarg));
                break;

            // plugins-cfg
            case 4: {
                try {
                    // check file size
                    int sz = mink_utils::get_file_size(optarg);
                    if ((sz <= 0)) {
                        throw std::invalid_argument("invalid filesize");
                    }
                    // cfg object
                    PluginsConfig *pcfg = new PluginsConfig();
                    pcfg->buff.resize(sz + 1);
                    // read data
                    if(mink_utils::load_file(optarg, pcfg->buff.data(), &sz)){
                        throw std::invalid_argument("cannot read data");
                    }
                    // verify JSON
                    pcfg->cfg = json::parse(pcfg->buff);
                    dparams.set_pointer(4, pcfg);

                } catch (std::exception &e) {
                    std::cout << "ERROR: Invalid plugins configuration file: "
                              << e.what() << std::endl;
                    exit(EXIT_FAILURE);
                }
                break;
            }

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
                rtrd_lst.push_back(std::string(optarg));
            }
            break;

        // local ip
        case 'h':
            if (!std::regex_match(optarg, ipv4_regex)) {
                std::cout << "ERROR: Invalid local IPv4 address format '"
                          << optarg << "'!" << std::endl;
                exit(EXIT_FAILURE);

            } else {
                local_ip.assign(optarg);
            }

            break;

        // plugins directory
        case 'p':
            plg_dir.assign(optarg);
            break;

        // sqlite database
        case 's':
            try {
                dbm.connect(optarg);
            } catch (std::invalid_argument &e) {
                std::cout << "ERROR: Invalid db filename!" << std::endl;
                exit(EXIT_FAILURE);
            }
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
#ifdef MINK_ENABLE_CONFIGD
void SysagentdDescriptor::process_cfg() {
    // reserved
}

int SysagentdDescriptor::init_cfg(bool _proc_cfg) {
    // log
    mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                              "Starting CFGD registration procedure...");

    // cfgd id buffer
    char cfgdid[16];

    // loop routing daemons
    unsigned int cc = gdts->get_client_count();
    for (unsigned int i = 0; i < cc; i++) {
        // get client
        gdt::GDTClient *gdtc = gdts->get_client(i);
        // sanity check
        if(!(gdtc && gdtc->is_registered())) {
            // log
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "Error while connecting to CFGD [%s:%d]",
                                      gdtc->get_end_point_address(),
                                      gdtc->get_end_point_port());
            continue;

        }
        // log
        mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                  "Connection established, L3 address = "
                                  "[%s:%d], GDT address = [%s:%s]",
                                  gdtc->get_end_point_address(),
                                  gdtc->get_end_point_port(),
                                  gdtc->get_end_point_daemon_type(),
                                  gdtc->get_end_point_daemon_id());

        // check for active configd
        if (cfgd_active.get())
            continue;

        // user login
        if (config::user_login(config,
                               gdtc,
                               nullptr,
                               cfgdid,
                               &cfgd_uid)) {
            // log
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "Error while trying to authenticate "
                                      "user [%s] with CFGD [%s:%d]",
                                      cfgd_uid.user_id,
                                      gdtc->get_end_point_address(),
                                      gdtc->get_end_point_port());
            continue;
        }
        // save cfgd id
        cfgd_id.assign(cfgdid);

        // sanity check
        if (strlen(cfgdid) <= 0) {
            // log
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "Error while trying to find CFGD id via "
                                      "GDT connection, L3 address = [%s:%d], "
                                      "GDT address = [%s:%s]",
                                      gdtc->get_end_point_address(),
                                      gdtc->get_end_point_port(),
                                      gdtc->get_end_point_daemon_type(),
                                      gdtc->get_end_point_daemon_id());
            continue;
        }
        // save conn pointer
        cfgd_gdtc = gdtc;

        // log
        mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                  "User [%s] successfully authenticated "
                                  "with CFGD [%s]",
                                  cfgd_uid.user_id,
                                  cfgdid);

        // create hbeat events
        EVHbeatRecv *hb_recv = new EVHbeatRecv();
        EVHbeatMissed *hb_missed = new EVHbeatMissed(&cfgd_active);
        EVHbeatCleanup *hb_cleanup = new EVHbeatCleanup(hb_recv, hb_missed);

        // init hbeat
        hbeat = gdt::init_heartbeat("config_daemon",
                                    cfgdid,
                                    gdtc,
                                    5,
                                    hb_recv,
                                    hb_missed,
                                    hb_cleanup);

        // err check
        if(!hbeat){
            // free
            delete hb_recv;
            delete hb_missed;
            delete hb_cleanup;
            continue;
        }

        // cfgd active
        cfgd_active.comp_swap(false, true);
        // log
        mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                  "Starting GDT HBEAT for config daemon "
                                  "[%s], L3 address = [%s:%d]",
                                  cfgdid,
                                  gdtc->get_end_point_address(),
                                  gdtc->get_end_point_port());

        // ok
        return 0;
    }
    // err
    return 1;
}
#endif

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

static void rtrds_connect(SysagentdDescriptor *d){
    // connect to routing daemons
    std::smatch regex_groups;
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");


    // loop routing daemons
    for (size_t i = 0; i < d->rtrd_lst.size(); i++) {
        // separate IP and PORT
        if (!std::regex_match(d->rtrd_lst[i], regex_groups, addr_regex))
            continue;
        // connect to routing daemon
        gdt::GDTClient *gdtc = d->gdts->connect(regex_groups[1].str().c_str(),
                                                atoi(regex_groups[2].str().c_str()),
                                                16,
                                                (d->local_ip.empty() ? nullptr : d->local_ip.c_str()),
                                                0);

        // setup client for service messages
        if (gdtc!= nullptr) {
            d->rtrd_gdtc = gdtc;
            // setup service message event handlers
            d->gdtsmm->setup_client(gdtc);
        }
    }
}


void SysagentdDescriptor::init_gdt(){
#ifdef MINK_ENABLE_CONFIGD
    // handler for non service message messages
    non_srvc_hdnlr = config::create_cfg_event_handler(config);
#endif

    // service message manager
    gdtsmm = new gdt::ServiceMsgManager(&idt_map,
                                        nullptr,
#ifdef MINK_ENABLE_CONFIGD
                                        non_srvc_hdnlr,
#else
                                        nullptr,
#endif
                                        dparams.get_pval<int>(2),
                                        dparams.get_pval<int>(3));

    // set daemon params
#ifdef MINK_ENABLE_CONFIGD
    set_param(0, config);
#endif
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
    rtrds_connect(this);

    // try to connect if unsuccessful
    while (gdts->get_client_count() == 0 &&
           !mink::CURRENT_DAEMON->DAEMON_TERMINATED) {

        mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                 "Cannot connect to routingd, trying again...");
        rtrds_connect(this);
        sleep(2);
    }
}

void SysagentdDescriptor::terminate(){
    gdt::destroy_session(gdts);
#ifdef MINK_ENABLE_CONFIGD
    delete config;
#endif

}
