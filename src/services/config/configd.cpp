/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <antlr_utils.h>
#include <atomic.h>
#include <regex>
#include <mink_config.h>
#include <daemon.h>
#include <events.h>
#include <getopt.h>
#include <mink_utils.h>
#include <gdt.h>
#include <gdt_stats.h>
#include <sstream>

// daemon name and description
#define DAEMON_TYPE "config_daemon"
#define DAEMON_DESCRIPTION "MINK Configuration daemon"

// config daemon descriptor definition
class ConfigDaemonDescriptor : public mink::DaemonDescriptor {
private:
    // get thread count
    unsigned int get_thread_count() { return thread_count.get(); }
    // inc thread count
    unsigned int inc_thread_count() { return thread_count.add_fetch(1); }
    // dec thread count
    unsigned int dec_thread_count() { return thread_count.sub_fetch(1); }

    // members
    // extra options
    mink_utils::VariantParamMap<uint32_t> extra_params;
    pthread_t timeout_t;
    mink::Atomic<int> thread_count;
    bool router;

public:
    // constructor
    ConfigDaemonDescriptor(const char *_type, const char *_desc)
        : mink::DaemonDescriptor(_type, NULL, _desc), timeout_t(0) {
        gdt_port = 0;
        gdts = NULL;
        new_client = NULL;
        client_done = NULL;
        client_down = NULL;
        user_timeout = 60;
        router = false;
        // create commit-log dir
        mkdir("commit-log", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        // default extra param values
        // --gdt-streams
        extra_params.set_int(0, 1000);
        // --gdt-stimeout
        extra_params.set_int(1, 5);
    }

    ~ConfigDaemonDescriptor() {
        // free routing deamons address strings
        for (unsigned int i = 0; i < routing_daemons.size(); i++)
            delete routing_daemons[i];
        // free config deamons id strings
        for (unsigned int i = 0; i < config_daemons.size(); i++)
            delete config_daemons[i];
    }
    // argument processor
    void process_args(int argc, char **argv) {
        std::regex addr_regex(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
        int option_index = 0;
        struct option long_options[] = {
            {"gdt-streams", required_argument, 0, 0},
            {"gdt-stimeout", required_argument, 0, 0},
            {0, 0, 0, 0}};

        if (argc < 9) {
            print_help();
            exit(EXIT_FAILURE);
        } else {
            int opt;
            while ((opt = getopt_long(argc, argv, "?p:i:d:c:r:n:t:DR",
                                      long_options, &option_index)) != -1) {
                switch (opt) {
                // long options
                case 0:
                    if (long_options[option_index].flag != 0)
                        break;
                    switch (option_index) {
                    // gdt-streams
                    case 0:
                        extra_params.set_int(0, atoi(optarg));
                        break;

                    // gdt-stimeout
                    case 1:
                        extra_params.set_int(1, atoi(optarg));
                        break;
                    }
                    break;

                // help
                case '?':
                    print_help();
                    exit(EXIT_FAILURE);

                // gdt port
                case 'p':
                    gdt_port = atoi(optarg);
                    break;

                // daemon id
                case 'i':
                    if (set_daemon_id(optarg) > 0) {
                        std::cout << "ERROR: Maximum size of daemon id string "
                                     "is 15 characters!"
                                  << std::endl;
                        exit(EXIT_FAILURE);
                    }
                    break;

                // config definition
                case 'd':
                    cfg_def_str = optarg;
                    set_param(0, &cfg_def_str);
                    break;

                // config contents
                case 'c':
                    cfg_cnt_str = optarg;
                    set_param(1, &cfg_cnt_str);
                    break;

                // user timeout
                case 't':
                    user_timeout = atoi(optarg);
                    if (user_timeout == 0)
                        user_timeout = 60;
                    break;

                // routing daemon address
                case 'r':
                    // check pattern (ipv4:port)
                    // check if valid
                    if (!std::regex_match(optarg, addr_regex)) {
                        std::cout << "ERROR: Invalid daemon address format '"
                                  << optarg << "'!" << std::endl;
                        exit(EXIT_FAILURE);

                    } else {
                        routing_daemons.push_back(new std::string(optarg));
                    }
                    break;

                // other config daemon id
                case 'n':
                    config_daemons.push_back(new std::string(optarg));
                    break;

                // debug mode
                case 'D':
                    set_log_level(mink::LLT_DEBUG);
                    break;

                // router mode
                case 'R':
                    router = true;
                    break;
                }
            }
            // check mandatory port
            if (gdt_port == 0) {
                std::cout << "ERROR: GDT server port not defined!"
                          << std::endl;
                exit(EXIT_FAILURE);
            }

            // check mandatory id
            if (strnlen(get_daemon_id(), 15) == 0) {
                std::cout << "ERROR: Daemon id not defined!" << std::endl;
                exit(EXIT_FAILURE);
            }

            // check configuration definition
            if (cfg_def_str == "") {
                std::cout << "ERROR: Configuration definition file not defined!"
                          << std::endl;
                exit(EXIT_FAILURE);
            }

            // check configuration contents
            if (cfg_cnt_str == "") {
                std::cout << "ERROR: Configuration contents file not defined!"
                          << std::endl;
                exit(EXIT_FAILURE);
            }
            // add config daemon id list as daemon param
            set_param(2, &config_daemons);
        }
    }
    // command line options
    void print_help() {
        std::cout << daemon_type << " - " << daemon_description << std::endl;
        std::cout << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << " -?\thelp" << std::endl;
        std::cout << " -i\tunique daemon id" << std::endl;
        std::cout << " -p\tGDT inbound port" << std::endl;
        std::cout << " -d\tconfiguration definition file" << std::endl;
        std::cout << " -c\tconfiguration contents file" << std::endl;
        std::cout << " -r\trouting daemon address (ipv4:port)" << endl;
        std::cout << " -n\tother config daemon id" << endl;
        std::cout << " -t\tuser timeout in seconds" << std::endl;
        std::cout << " -D\tdebug mode" << std::endl;
        std::cout << " -R\tenable routing" << std::endl;
        std::cout << std::endl;
        std::cout << "GDT Options:" << std::endl;
        std::cout << "=============" << std::endl;
        std::cout
            << " --gdt-streams\t\tGDT Session stream pool\t\t(default = 1000)"
            << std::endl;
        std::cout << " --gdt-stimeout\tGDT Stream timeout in "
                     "seconds\t\t(default = 5)"
                  << std::endl;
    }

    // load and init configuration
    void init_config() {
        // load definition
        int fsize = mink_utils::get_file_size(cfg_def_str.c_str());
        // check if configuration definition file exists
        if (fsize <= 0) {
            std::cout << "ERROR: Invalid configuration definition file!"
                      << std::endl;
            exit(EXIT_FAILURE);
        }
        // load definition
        char *fbuff = new char[fsize + 1];
        bzero(fbuff, fsize + 1);
        mink_utils::load_file(cfg_def_str.c_str(), fbuff, &fsize);

        // create parser
        antlr::MinkParser *pmp = antlr::create_parser();
        pANTLR3_INPUT_STREAM input = pmp->input;
        pminkLexer lxr = pmp->lexer;
        pANTLR3_COMMON_TOKEN_STREAM tstream = pmp->tstream;
        pminkParser psr = pmp->parser;
        minkParser_input_return ast;
        minkParser_inputConfig_return_struct ast_cfg;

        // reset error state
        lxr->pLexer->rec->state->errorCount = 0;
        psr->pParser->rec->state->errorCount = 0;
        // set input stream
        input->reuse(input,
                     (unsigned char *)fbuff,
                     fsize,
                     (unsigned char *)"file_stream");
        // token stream
        tstream->reset(tstream);
        // definition ast
        ast = psr->input(psr);
        // syntax err check (phase one of validation)
        int err_c = lxr->pLexer->rec->getNumberOfSyntaxErrors(lxr->pLexer->rec);
        err_c += psr->pParser->rec->getNumberOfSyntaxErrors(psr->pParser->rec);
        if (err_c > 0) {
            std::cout << "ERROR: Invalid configuration definition syntax!"
                      << std::endl;
            exit(EXIT_FAILURE);
        }

        // process definition
        antlr::process_config_def(ast.tree, &cfg_def);

        // phase two of validation (template check)
        if (!config.validate_definition(&cfg_def)) {
            std::cout
                << "ERROR: Invalid template found in configuration definition!"
                << std::endl;
            exit(EXIT_FAILURE);
        }

        // load definition
        config.load_definition(&cfg_def);

        // process data patterns
        antlr::config_process_patterns(ast.tree, &config);

        // free definition buffer
        delete[] fbuff;

        // free parser
        antlr::free_mem(pmp);

        // check if configuration contents file exists
        fsize = mink_utils::get_file_size(cfg_cnt_str.c_str());
        if (fsize > 0) {
            // create parser
            pmp = antlr::create_parser();
            input = pmp->input;
            lxr = pmp->lexer;
            tstream = pmp->tstream;
            psr = pmp->parser;
            // init file buffer
            fbuff = new char[fsize + 1];
            bzero(fbuff, fsize + 1);
            // load contents
            mink_utils::load_file(cfg_cnt_str.c_str(), fbuff, &fsize);
            // reset error state
            lxr->pLexer->rec->state->errorCount = 0;
            psr->pParser->rec->state->errorCount = 0;
            input->reuse(input, 
                         (unsigned char *)fbuff, 
                         fsize,
                         (unsigned char *)"file_stream");
            // token stream
            tstream->reset(tstream);
            // contents ast
            ast_cfg = psr->inputConfig(psr);
            // err check
            int err_c = lxr->pLexer
                           ->rec
                           ->getNumberOfSyntaxErrors(lxr->pLexer->rec);
            err_c += psr->pParser
                        ->rec
                        ->getNumberOfSyntaxErrors(psr->pParser->rec);
            if (err_c > 0) {
                std::cout << "ERROR: Invalid configuration contents syntax!"
                          << std::endl;
                exit(EXIT_FAILURE);
            }
            // process contents
            antlr::process_config(ast_cfg.tree, &cfg_cnt);
            // free file buffer
            delete[] fbuff;
            // free parser
            antlr::free_mem(pmp);
            // merge contents with definition
            int res =
                config.merge(config.get_definition_root(), &cfg_cnt, false);
            // error check
            if (res != 0)
                std::cout << "ERROR: Cannot merge configuration contents and "
                             "definition!"
                          << std::endl;
        }
        // init user timeout thread
        if (pthread_create(&timeout_t, NULL, &timeout_loop, this) == 0) {
            pthread_setname_np(timeout_t, "cfg_usr_timeout");
            inc_thread_count();
        }
    }

    // terminate event
    void terminate() {
        // wait for threads to finish
        timespec st = {0, 100000000};
        while (get_thread_count() > 0) {
            nanosleep(&st, NULL);
        }
        // stop GDT server
        gdts->stop_server();

        // destroy GDT session, free memory
        gdt::destroy_session(gdts);
        // free events
        delete new_client;
        delete client_done;
        delete client_down;
    }

    // user timeout thread loop
    static void *timeout_loop(void *args) {
        if (args != NULL) {
            ConfigDaemonDescriptor *dd = static_cast<ConfigDaemonDescriptor *>(args);
            time_t tm_now;
            config::UserId usr_id;
            config::UserInfo *usr_info;
            std::vector<config::UserId> del_lst;
            int total_sleep = 0;
            // loop
            while (!mink::DaemonDescriptor::DAEMON_TERMINATED) {
                // sleep 1 sec
                sleep(1);
                ++total_sleep;
                // check if user timeout has been reached
                if (total_sleep < dd->user_timeout)
                    continue;
                // reset current timeout
                total_sleep = 0;
                // current timestamp
                tm_now = time(NULL);
                // lock config
                dd->config.lock();
                // get user map
                std::map<config::UserId, config::UserInfo *,
                         config::UserIdCompare> *usr_map =
                    dd->config.get_usr_path_map();
                // define iterator type
                typedef std::map<config::UserId, config::UserInfo *,
                                 config::UserIdCompare>::iterator it_type;
                del_lst.clear();
                // loop
                for (it_type it = usr_map->begin(); it != usr_map->end();
                     ++it) {
                    usr_id = it->first;
                    usr_info = it->second;
                    // timeout found
                    if (tm_now - usr_info->timestamp >= dd->user_timeout) {
                        // check if current user started transaction
                        bool pretend = (dd->config.get_transaction_owner() != usr_id &&
                                        dd->config.transaction_started()
                                        ? true
                                        : false);
                        if (!pretend) {
                            // discard changes
                            dd->config.discard(dd->config.get_definition_root());
                            // end transaction
                            dd->config.end_transaction();
                        }
                        // remove user later
                        del_lst.push_back(usr_id);
                    }
                }
                // remove users tagged for deletion
                for (unsigned int i = 0; i < del_lst.size(); i++)
                    dd->config.remove_wn_user(&del_lst[i]);

                // unlock config
                dd->config.unlock();
            }

            // detach thread
            pthread_detach(dd->timeout_t);
            dd->timeout_t = 0;
            dd->dec_thread_count();
        }

        return NULL;
    }

    void init_gdt() {
        // start GDT session
        gdts = gdt::init_session(get_daemon_type(),
                                 get_daemon_id(),
                                 (int)*extra_params.get_param(0),
                                 (int)*extra_params.get_param(1),
                                 router,
                                 (int)*extra_params.get_param(1));

        // accept connections (server mode)
        gdts->start_server(NULL, gdt_port);
        // set callbacks
        new_client = new NewClient(&config);
        client_done = new ClientDone(&config);
        client_down = new ClientDown(&config);
        gdts->set_callback(gdt::GDT_ET_CLIENT_NEW, new_client);
        gdts->set_callback(gdt::GDT_ET_CLIENT_TERMINATED, client_done);
        gdts->set_callback(gdt::GDT_ET_CLIENT_TERMINATING, client_down);
        gdts->set_callback(gdt::GDT_ET_CLIENT_RECONNECTING, client_down);

        // connect to routing daemons
        std::smatch regex_groups;
        std::regex addr_regex(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");

        // loop routing daemons
        for (unsigned int i = 0; i < routing_daemons.size(); i++) {
            // separate IP and PORT
            std::regex_search(*routing_daemons[i], regex_groups, addr_regex);
            // connect to routing daemon
            gdt::GDTClient *gdt_client = gdts->connect(regex_groups[1].str().c_str(),
                                                       atoi(regex_groups[2].str().c_str()),
                                                       16,
                                                       NULL,
                                                       0);
            // null check
            if (gdt_client != NULL) {
                // check if registration was successful
                if (gdt_client->is_registered())
                    gdt_client->set_callback(gdt::GDT_ET_STREAM_NEW,
                                              &new_client->new_stream);
            }
        }
    }

    // GDT New Client event
    NewClient *new_client;
    // GDT Client terminated event
    ClientDone *client_done;
    // GDT Client down (terminating and re-connecting)
    ClientDown *client_down;
    // GDT session
    gdt::GDTSession *gdts;
    // GDT port
    int gdt_port;
    // user idle timeout
    int user_timeout;
    // config def
    std::string cfg_def_str;
    // config contents
    std::string cfg_cnt_str;
    // routing daemons
    std::vector<std::string *> routing_daemons;
    // config daemons
    std::vector<std::string *> config_daemons;
    // configuration definition
    config::ConfigItem cfg_def;
    // configuration contents
    config::ConfigItem cfg_cnt;
    // config handler
    config::Config config;
};

// main
int main(int argc, char **argv) {
    // create daemon
    ConfigDaemonDescriptor dd(DAEMON_TYPE, DAEMON_DESCRIPTION);
    // process arguments
    dd.process_args(argc, argv);
    // init config
    dd.init_config();
    // init GDT
    dd.init_gdt();
    // init/start daemon
    // mink::daemon_init(&dd);
    mink::daemon_start(&dd);
    signal(SIGTERM, &mink::signal_handler);
    // loop until terminated
    mink::daemon_loop(&dd);
    // normal exit
    return 0;
}

