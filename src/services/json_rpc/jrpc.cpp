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
#include <iostream>
#include "ws_server.h"
#include "jrpc.h"
#include <json_rpc.h>
#include <boost/asio/signal_set.hpp>
#include <gdt.pb.enums_only.h>
#include <config.h>

/**********************/
/* JsonRpcdDescriptor */
/**********************/
JsonRpcdDescriptor::JsonRpcdDescriptor(const char *_type, 
                                       const char *_desc)
    : mink::DaemonDescriptor(_type, nullptr, _desc) {

#ifdef ENABLE_CONFIGD
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
    // -S
    dparams.set_bool(4, false);
    // -u
    dparams.set_bool(5, false);
    // -t
    dparams.set_int(6, 3);
    dparams.set_int(7, 15);
}

JsonRpcdDescriptor::~JsonRpcdDescriptor(){
    delete gdtsmm;
}

void JsonRpcdDescriptor::process_args(int argc, char **argv){
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
    std::regex ipv4_regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    std::regex log_sec_regex("(\\d+):(\\d+)");
    int opt;
    int option_index = 0;
    struct option long_options[] = {{"gdt-streams", required_argument, 0, 0},
                                    {"gdt-stimeout", required_argument, 0, 0},
                                    {"gdt-smsg-pool", required_argument, 0, 0},
                                    {"gdt-sparam-pool", required_argument, 0, 0},
                                    {0, 0, 0, 0}};

    if (argc < 5) {
        print_help();
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt_long(argc, argv, "?c:h:i:w:s:C:DSt:u", long_options,
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

        // ws addr
        case 'w':
            // check pattern (ipv4:port)
            // check if valid
            if (!std::regex_match(optarg, addr_regex)) {
                std::cout << "ERROR: Invalid web socket address format '"
                          << optarg << "'!" << std::endl;
                exit(EXIT_FAILURE);

            } else {
                ws_addr.assign(optarg);
            }
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

        // certificates
        case 'C':
            try {
                // path and certificates
                std::string cpath(optarg);
                std::string f_cert(cpath + "/cert.pem");
                std::string f_key(cpath + "/key.pem");
                std::string f_dh(cpath + "/dh.pem");
                // check sizes
                int sz_cert = mink_utils::get_file_size(f_cert.c_str());
                int sz_key = mink_utils::get_file_size(f_key.c_str());
                int sz_dh = mink_utils::get_file_size(f_dh.c_str());

                if (!(sz_cert && sz_key && sz_dh))
                    throw std::invalid_argument("invalid file size");

                // setup buffers
                char b_cert[sz_cert];
                char b_key[sz_key];
                char b_dh[sz_dh];

                // load data
                if (mink_utils::load_file(f_cert.c_str(), b_cert, &sz_cert))
                    throw std::invalid_argument("invalid file size");

                if (mink_utils::load_file(f_key.c_str(), b_key, &sz_key))
                    throw std::invalid_argument("invalid file size");

                if (mink_utils::load_file(f_dh.c_str(), b_dh, &sz_dh))
                    throw std::invalid_argument("invalid file size");

                // save certs
                wss_cert.assign(b_cert, sz_cert);
                wss_key.assign(b_key, sz_key);
                wss_dh.assign(b_dh, sz_dh);

            } catch (std::exception &e) {
                std::cout << "ERROR: Cannot load certificates!" << std::endl;
                exit(EXIT_FAILURE);
            }

            break;

        // debug mode
        case 'D':
            set_log_level(mink::LLT_DEBUG);
            break;

        // single session mode
        case 'S':
            dparams.set_bool(4, true);
            break;

        // login attempts and ban time
        case 't': {
            std::smatch rgxg;
            std::string s(optarg);
            if (!std::regex_match(s, rgxg, log_sec_regex)) {
                std::cout << "ERROR: Invalid login counter format '" << optarg
                          << "'!" << std::endl;
                exit(EXIT_FAILURE);

            } else {
                dparams.set_int(6, std::stoi(rgxg[1]));
                dparams.set_int(7, std::stoi(rgxg[2]));
            }
            break;
        }

        // enable unencrypted ws
        case 'u':
            dparams.set_bool(5, true);
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

    // check certificates
    if (wss_cert.empty() || wss_key.empty() || wss_dh.empty()) {
        std::cout << "ERROR: Missing certificates!" << std::endl;
        exit(EXIT_FAILURE);
    }
}

void JsonRpcdDescriptor::print_help(){
    std::cout << daemon_type << " - " << daemon_description << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -?\thelp" << std::endl;
    std::cout << " -i\tunique daemon id" << std::endl;
    std::cout << " -c\trouter daemon address (ipv4:port)" << std::endl;
    std::cout << " -h\tlocal IPv4 address" << std::endl;
    std::cout << " -w\tWebSocket server IPv4 address (ipv4:port)" << std::endl;
    std::cout << " -s\tpath to sqlite database file" << std::endl;
    std::cout << " -C\tcertificates path (key.pem, cert.pem, dh.pem)" << std::endl;
    std::cout << " -D\tstart in debug mode" << std::endl;
    std::cout << " -S\tsingle session mode" << std::endl;
    std::cout << " -t\tlogin counter value (max_attempts:ban_time_in_minutes)" << std::endl;
    std::cout << " -u\tenable unencrypted WebSocket (ws://)" << std::endl;
    std::cout << std::endl;
    std::cout << "GDT Options:" << std::endl;
    std::cout << "=============" << std::endl;
    std::cout << " --gdt-streams     GDT Session stream pool            (default = 1000)"
              << std::endl;
    std::cout << " --gdt-stimeout    GDT Stream timeout in seconds      (default = 5)"
              << std::endl;
    std::cout << " --gdt-smsg-pool   GDT Service message pool           (default = 1000)"
              << std::endl;
    std::cout << " --gdt-sparam-pool GDT Service message parameter pool (default = 5000)"
              << std::endl;
}

static void rtrds_connect(JsonRpcdDescriptor *d){
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

void JsonRpcdDescriptor::init_gdt(){
    // service message manager
    gdtsmm = new gdt::ServiceMsgManager(&idt_map, 
                                        nullptr, 
                                        nullptr,
                                        dparams.get_pval<int>(2),
                                        dparams.get_pval<int>(3));

    // set daemon params
#ifdef ENABLE_CONFIGD
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

static void load_wss_certs(boost::asio::ssl::context &ctx,
                           const std::string &cert, 
                           const std::string &key,
                           const std::string &dh) {
    /*
        openssl dhparam -out dh.pem 2048
        openssl req -newkey rsa:2048 \
                    -nodes \
                    -keyout key.pem -x509 -days 10000 \
                    -out cert.pem \
                    -subj "/CN=www.example.com"
    */

    ctx.set_password_callback(
        [](std::size_t, boost::asio::ssl::context_base::password_purpose) {
            return "n/a";
        });

    ctx.set_options(boost::asio::ssl::context::default_workarounds |
                    boost::asio::ssl::context::no_sslv2 |
                    boost::asio::ssl::context::no_tlsv1 |
                    boost::asio::ssl::context::no_tlsv1_1 |
#ifndef ENABLE_TLSV12
                    boost::asio::ssl::context::no_tlsv1_2 |
#endif
                    boost::asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain(boost::asio::buffer(cert.data(), cert.size()));

    ctx.use_private_key(boost::asio::buffer(key.data(), 
                        key.size()),
                        boost::asio::ssl::context::file_format::pem);

    ctx.use_tmp_dh(boost::asio::buffer(dh.data(), dh.size()));
}


void JsonRpcdDescriptor::init_wss(const std::string &ws_addr){
    try{
        auto const addr = net::ip::make_address(ws_addr.substr(0, ws_addr.find(":")));
        auto const th_nr = 1;
        auto const droot = std::make_shared<std::string>("/");
        // get port
        uint16_t port = std::stoi(ws_addr.substr(ws_addr.find(":") + 1));

        // The io_context is required for all I/O
        net::io_context ioc{th_nr};

        //ssl context
        ssl::context ctx{ssl::context::tls_server};

        // This holds the self-signed certificate used by the server
        load_wss_certs(ctx, wss_cert, wss_key, wss_dh);

        // Create and launch a listening port
        std::make_shared<Listener>(ioc,
                                   ctx,
                                   tcp::endpoint{addr, port},
                                   droot)->run();
        // Run the I/O service on the requested number of threads
        //std::vector<std::thread> v;
        //v.reserve(th_nr);
        //for (auto i = th_nr- 1; i > 0; --i)
        //    v.emplace_back([&ioc] { ioc.run(); });

        // Construct a signal set registered for process termination.
        boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);

        // Start an asynchronous wait for one of the signals to occur.
        signals.async_wait([&ioc](const boost::system::error_code error, int signum) {
            ioc.stop();
        });

        ioc.run();
    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                  "Cannot create web socket listener: %s", 
                                  e.what());
        exit(EXIT_FAILURE);
    }

    DaemonDescriptor::DAEMON_TERMINATED = true;
}

#ifdef ENABLE_CONFIGD
int JsonRpcdDescriptor::init_cfg(bool _proc_cfg) const {
    // reserved
    return 0;
}
#endif

void JsonRpcdDescriptor::init(){
#ifdef ENABLE_CONFIGD
    init_cfg(true);
#endif
    init_gdt();
    init_wss(ws_addr);
}


#ifdef ENABLE_CONFIGD
void JsonRpcdDescriptor::process_cfg(){
    // reserved
}
#endif

void JsonRpcdDescriptor::terminate(){
    gdt::destroy_session(gdts);
#ifdef ENABLE_CONFIGD
    // deallocate config memory
    if (config->get_definition_root() != nullptr)
        delete config->get_definition_root();
    // free config
    delete config;
#endif
}

