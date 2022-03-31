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
#include <routing.h>
#include <thread>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

RoutingdDescriptor::RoutingdDescriptor(const char *_type, 
                                       const char *_desc) : mink::DaemonDescriptor(_type, nullptr, _desc),
                                                            gdts(nullptr),
                                                            gdt_stats(nullptr),
                                                            gdt_port(0) {
#ifdef MINK_ENABLE_CONFIGD
    config = new config::Config();
    memset(cfgd_id, 0, sizeof(cfgd_id));

    // set daemon params
    set_param(0, config);
#endif
    // default extra param values
    // --gdt-streams
    extra_params.set_int(0, 1000);
    // --gdt-stimeout
    extra_params.set_int(1, 5);
}

RoutingdDescriptor::~RoutingdDescriptor() {
#ifdef MINK_ENABLE_CONFIGD
    // free routing deamons address strings
    std::all_of(config_daemons.cbegin(), config_daemons.cend(),
                [](std::string *cd) {
                    delete cd;
                    return true;
                });
#endif
}

void RoutingdDescriptor::process_args(int argc, char **argv) {
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
    std::regex ipv4_regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    int option_index = 0;
    struct option long_options[] = {{"gdt-streams", required_argument, 0, 0},
                                    {"gdt-stimeout", required_argument, 0, 0},
                                    {0, 0, 0, 0}};

    if (argc < 5) {
        print_help();
        exit(EXIT_FAILURE);
    } else {
        int opt;
        while ((opt = getopt_long(argc, argv, "?p:c:i:h:DN", long_options,
                                  &option_index)) != -1) {
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


            // config daemon address
            case 'c':
#ifdef MINK_ENABLE_CONFIGD
                // check pattern (ipv4:port)
                // check if valid
                if (!std::regex_match(optarg, addr_regex)) {
                    std::cout << "ERROR: Invalid daemon address format '"
                              << optarg << "'!" << std::endl;
                    exit(EXIT_FAILURE);

                } else {
                    config_daemons.push_back(new std::string(optarg));
                }
#endif
                break;

            // gdt port
            case 'p':
                gdt_port = atoi(optarg);
                break;

            // debug mode
            case 'D':
                set_log_level(mink::LLT_DEBUG);
                break;

            // interface monitor
            case 'N':
                if_monitor = true;
                break;

            default:
                break;
            }
        }

        // check mandatory id
        if (strnlen(get_daemon_id(), 15) == 0) {
            std::cout << "ERROR: Daemon id not defined!" << std::endl;
            exit(EXIT_FAILURE);
        }

        // port
        if (gdt_port == 0) {
            std::cout << "ERROR: GDT IN port not defined!" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}

void RoutingdDescriptor::print_help() {
    std::cout << daemon_type << " - " << daemon_description << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -?\thelp" << std::endl;
    std::cout << " -i\tunique daemon id" << std::endl;
#ifdef MINK_ENABLE_CONFIGD
    std::cout << " -c\tconfig daemon address (ipv4:port)" << std::endl;
#endif
    std::cout << " -p\tGDT inbound port" << std::endl;
    std::cout << " -h\tlocal IPv4 address" << std::endl;
    std::cout << " -D\tstart in debug mode" << std::endl;
    std::cout << " -N\tenable interface monitor" << std::endl;
    std::cout << std::endl;
    std::cout << "GDT Options:" << std::endl;
    std::cout << "=============" << std::endl;
    std::cout << " --gdt-streams\t\tGDT Session stream pool\t\t(default = 1000)"
              << std::endl;
    std::cout
        << " --gdt-stimeout\tGDT Stream timeout in seconds\t\t(default = 5)"
        << std::endl;
}

static void parseRtattr(struct rtattr **tb, 
                        int max, 
                        struct rtattr *rta,
                        int len) {

    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }
}


void RoutingdDescriptor::init() {
    // init gdt
    init_gdt();
#ifdef MINK_ENABLE_CONFIGD
    // init config
    if (init_config() != 0) {
        // log
        mink::CURRENT_DAEMON->log(mink::LLT_INFO,
            "Cannot find any valid config daemon connection for node [%s], "
            "using automatic configuration...",
            get_daemon_id());
        // not exiting since routingd is allowed to run without configd
        // connection
    }
#endif
    // accept connections (server mode)
    while (gdts->start_server((local_ip.empty() ? nullptr : local_ip.c_str()),
                              gdt_port) < 0 && !mink::CURRENT_DAEMON->DAEMON_TERMINATED) {
        mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                 "Cannot init SCTP server on node [%s], trying again...",
                                  get_daemon_id());
        sleep(2);
    }
    // local ip
    const char *lip = (local_ip.empty() ? nullptr : local_ip.c_str());

    // interface up/down handler
    std::thread if_thh([this, lip] {
        // check if inabled
        if (!if_monitor) return;
        // setup netlink
        const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd > 0) {
            struct sockaddr_nl sa = {0};

            sa.nl_family = AF_NETLINK;
            sa.nl_groups = RTNLGRP_LINK;
            bind(fd, (struct sockaddr *)&sa, sizeof(sa));

            struct sockaddr_nl local = {0};
            char buf[8192] = {0};
            struct iovec iov;
            iov.iov_base = buf;
            iov.iov_len = sizeof(buf);

            struct msghdr msg = {0};
            msg.msg_name = &local;
            msg.msg_namelen = sizeof(local);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED) {
                ssize_t status = recvmsg(fd, &msg, MSG_DONTWAIT);

                //  check status
                if (status < 0) {
                    if (errno == EINTR || errno == EAGAIN) {
                        sleep(1);
                        continue;
                    }
                    // failed to read nl msg
                    continue;
                }

                if (msg.msg_namelen != sizeof(local)) {
                    // invalid length
                    continue;
                }

                // message parser
                struct nlmsghdr *h;

                for (h = (struct nlmsghdr *)buf;
                     status >= (ssize_t)sizeof(*h);) {

                    int len = h->nlmsg_len;
                    int l = len - sizeof(*h);
                    char *ifName;

                    if ((l < 0) || (len > status)) {
                        continue;
                    }
                    if ((h->nlmsg_type == RTM_DELLINK) ||
                        (h->nlmsg_type == RTM_NEWLINK) ||
                        (h->nlmsg_type == RTM_DELADDR)) {

                        char *ifName;
                        struct ifinfomsg *ifi;
                        struct rtattr *tb[IFLA_MAX + 1];
                        ifi = (struct ifinfomsg *)NLMSG_DATA(h);
                        parseRtattr(tb, IFLA_MAX, IFLA_RTA(ifi), h->nlmsg_len);
                        if (tb[IFLA_IFNAME]) {
                            ifName = (char *)RTA_DATA(tb[IFLA_IFNAME]);
                        }
                        /*
                        if (ifi->ifi_flags & IFF_UP) {
                            std::cout << "Interfface UP" << std::endl;
                        } else {
                            std::cout << "Interfface DOWN" << std::endl;
                        }
                        */

                        switch (h->nlmsg_type) {
                            case RTM_DELADDR:
                            case RTM_DELLINK:
                            case RTM_NEWLINK:
                                gdts->stop_server();
                                gdt::destroy_session(gdts);
                                // start GDT session
                                gdts = gdt::init_session(get_daemon_type(), 
                                                         get_daemon_id(), 
                                                         (int)*extra_params.get_param(0),
                                                         (int)*extra_params.get_param(1), 
                                                         true, 
                                                         (int)*extra_params.get_param(1));
                                
                                // set routing algorighm
                                gdts->set_routing_algo(gdt::GDT_RA_WRR);
                                // start server 
                                gdts->start_server(lip, gdt_port);
                                // try again on error
                                while (gdts->start_server(lip, gdt_port) < 0 &&
                                       !mink::CURRENT_DAEMON->DAEMON_TERMINATED) {
                                    mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                        "Cannot init SCTP server on node [%s], "
                                        "trying again...", get_daemon_id());
                                    sleep(2);
                                }

                                break;
                        }
                    }
                    status -= NLMSG_ALIGN(len);
                    h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
                }
                sleep(1);
            }
       }
    });

    if_thh.detach();

    // connect stats with routing
    gdt::GDTClient *gdtc = gdt_stats->get_gdt_session()
                                    ->connect(lip,
                                              gdt_port,
                                              16,
                                              lip,
                                              0);
    if (gdtc != nullptr)
        gdt_stats->setup_client(gdtc);
}

#ifdef MINK_ENABLE_CONFIGD
void RoutingdDescriptor::process_config() {
    // create root node string
    std::string root_node_str(DAEMON_CFG_NODE);
    root_node_str.append(" ");
    root_node_str.append(daemon_id);

    // get node
    config::ConfigItem *root = (*config->get_definition_root())(root_node_str.c_str());
    config::ConfigItem *tmp_node = nullptr;

    // check if configuration exists
    if (root == nullptr) {
        mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                  "Configuration for node [%s] does not exist, "
                                  "using automatic routing...",
                                  get_daemon_id());
        return;
    }

    // process configuration
    mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                              "Configuration for node [%s] successfully received, processing...",
                              get_daemon_id());

    // asp list
    if ((*root)("destinations") == nullptr)
        mink::CURRENT_DAEMON->log(mink::LLT_WARNING,
                                  "Missing destination configuration node set for node [%s]!",
                                  get_daemon_id());
    else {
        tmp_node = (*root)("destinations");
        // setup config on chage events
        tmp_node->set_on_change_handler(&wrr_mod_handler, true);
        // check all nodes
        config::ConfigItem *dest_node_type = nullptr;
        for (unsigned int i = 0; i < tmp_node->children.size(); i++) {
            dest_node_type = tmp_node->children[i];
            mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                      "Processing configuration for "
                                      "destination type [%s] for node [%s]...",
                                      dest_node_type->name.c_str(), get_daemon_id());

            if ((*dest_node_type)("nodes") == nullptr) {
                mink::CURRENT_DAEMON->log(mink::LLT_WARNING,
                                          "Missing destination [%s] nodes configuration node set for "
                                          "node [%s]!",
                                          dest_node_type->name.c_str(), 
                                          get_daemon_id());
                continue;
            }

            // nodes
            config::ConfigItem *nodes = (*dest_node_type)("nodes");

            // process nodes
            config::ConfigItem *dest_node = nullptr;
            mink_utils::PooledVPMap<uint32_t> tmp_params;
            for (unsigned int j = 0; j < nodes->children.size(); j++) {
                dest_node = nodes->children[j];
                mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                          "Adding node [%s] to [%s] routing table with weight "
                                          "[%d]...",
                                          dest_node->name.c_str(), 
                                          dest_node_type->name.c_str(),
                                          dest_node->to_int("weight"), get_daemon_id());

                // set weight data
                tmp_params.set_int(0, dest_node->to_int("weight", 1));
                // add to routing handler
                gdts->get_routing_handler()->add_node(nullptr, 
                                                      dest_node_type->name.c_str(), 
                                                      dest_node->name.c_str(),
                                                      &tmp_params);
            }
        }
    }
}

int RoutingdDescriptor::init_config(bool _process_config) {
    // log
    mink::CURRENT_DAEMON->log(
        mink::LLT_DEBUG, "Starting config daemon registration procedure...");
    // loop routing daemons

    for (unsigned int i = 0; i < gdts->get_client_count(); i++) {
        // get client
        gdt::GDTClient *gdt_client = gdts->get_client(i);
        // null check
        if (gdt_client != nullptr && gdt_client->is_registered()) {
            // check only OUTBOUND
            if (gdt_client->direction != gdt::GDT_CD_OUTBOUND)
                continue;
            // log
            mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                      "Connection to remote daemon established, L3 address = "
                                      "[%s:%d], GDT address = [%s:%s]",
                                      gdt_client->get_end_point_address(),
                                      gdt_client->get_end_point_port(),
                                      gdt_client->get_end_point_daemon_type(),
                                      gdt_client->get_end_point_daemon_id());
            // check for active configd
            if (!cfgd_active.get()) {
                // user login
                if (config::user_login(config, 
                                       gdt_client, nullptr,
                                       (char *)cfgd_id, 
                                       &cfgd_uid) == 0) {
                    if (strnlen((char *)cfgd_id, sizeof(cfgd_id) - 1) > 0) {
                        // log
                        mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                                  "User [%s] successfully authenticated with config "
                                                  "daemon [%s]",
                                                  cfgd_uid.user_id, 
                                                  cfgd_id);
                        // notification request
                        if (config::notification_request(config, 
                                                         gdt_client, 
                                                         DAEMON_CFG_NODE, 
                                                         nullptr,
                                                         (char *)cfgd_id, 
                                                         &cfgd_uid, 
                                                         nullptr) == 0) {

                            // create hbeat events
                            auto hb_recv = new HbeatRecv();
                            auto hb_missed = new HbeatMissed(&cfgd_active);
                            auto hb_cleanup = new HbeatCleanup(hb_recv, hb_missed);

                            // init hbeat
                            hbeat = gdt::init_heartbeat("config_daemon", 
                                                        (char *)cfgd_id, 
                                                        gdt_client, 
                                                        5,
                                                        hb_recv, 
                                                        hb_missed, 
                                                        hb_cleanup);
                            if (hbeat != nullptr) {
                                cfgd_active.comp_swap(false, true);
                                // log
                                mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                                          "Starting GDT HBEAT for config daemon "
                                                          "[%s], L3 address = [%s:%d]",
                                                          cfgd_id,
                                                          gdt_client->get_end_point_address(),
                                                          gdt_client->get_end_point_port());

                                // free event memory on error
                            } else {
                                delete hb_recv;
                                delete hb_missed;
                                delete hb_cleanup;
                            }

                            // log
                            mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                                      "Registering notification request for node "
                                                      "path [%s] with config daemon [%s]",
                                                      DAEMON_CFG_NODE, 
                                                      cfgd_id);
                            // process config
                            if (_process_config)
                                process_config();

                            // stop if config daemon connected
                            // ok
                            return 0;

                        } else {
                            // log
                            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                                      "Error while requesting notifications from "
                                                      "config daemon [%s]!",
                                                      cfgd_id);
                        }

                    } else {
                        // log
                        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                                  "Error while trying to find config daemon id via "
                                                  "GDT connection, L3 address = [%s:%d], GDT address "
                                                  "= [%s:%s]",
                                                  gdt_client->get_end_point_address(),
                                                  gdt_client->get_end_point_port(),
                                                  gdt_client->get_end_point_daemon_type(),
                                                  gdt_client->get_end_point_daemon_id());
                    }

                } else {
                    // log
                    mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                              "Error while trying to authenticate user [%s] with "
                                              "config daemon [%s:%d]!",
                                              cfgd_uid.user_id, gdt_client->get_end_point_address(),
                                              gdt_client->get_end_point_port());
                }
            }

        } else {
            // log
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "Error while connecting to config daemon [%s:%d]!",
                                      (gdt_client ? gdt_client->get_end_point_address() : ""),
                                      (gdt_client ? gdt_client->get_end_point_port() : 0));
        }
    }

    // err
    return 5;
}
#endif

void RoutingdDescriptor::init_gdt() {
    // start GDT session
    gdts = gdt::init_session(get_daemon_type(), 
                             get_daemon_id(), 
                             (int)*extra_params.get_param(0),
                             (int)*extra_params.get_param(1), 
                             true, 
                             (int)*extra_params.get_param(1));

    // set routing algorighm
    gdts->set_routing_algo(gdt::GDT_RA_WRR);
    // set gdts pointer
#ifdef MINK_ENABLE_CONFIGD
    wrr_mod_handler.gdts = gdts;
#endif
    // gdt stats
    gdt_stats = new gdt::GDTStatsSession(5, gdts);
    // start stats
    gdt_stats->start();

    // init gdt stats
    gdt_stats->init_gdt_session_stats(gdts);

    // set params
    set_param(2, gdts);

    // connect to config daemons
    std::smatch regex_groups;
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");

#ifdef MINK_ENABLE_CONFIGD
    // loop config daemons
    std::all_of(config_daemons.cbegin(), config_daemons.cend(),
                [this, &regex_groups, &addr_regex](const std::string *cd) {
                    // separate IP and PORT
                    std::regex_search(*cd, regex_groups, addr_regex);
                    // connect to config daemon
                    gdts->connect(regex_groups[1].str().c_str(),
                                  atoi(regex_groups[2].str().c_str()), 
                                  16,
                                  nullptr, 
                                  0);

                    return true;
                });
#endif
}

void RoutingdDescriptor::terminate() {
    // stop server
    gdts->stop_server();
    // stop stats
    gdt_stats->stop();
    // destroy session, free memory
    gdt::destroy_session(gdts);
#ifdef MINK_ENABLE_CONFIGD
    // deallocate config memory
    if (config->get_definition_root() != nullptr)
        delete config->get_definition_root();
    // free config
    delete config;
#endif
    // gdt stats
    delete gdt_stats;
}

