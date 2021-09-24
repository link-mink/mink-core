/*
 *            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * Copyright (C) 2021  Damir Franusic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <getopt.h>
#include <regex>
#include "grpc.h"

GrpcdDescriptor::GrpcdDescriptor(const char *_type,
                                 const char *_desc)
    : mink::DaemonDescriptor(_type, NULL, _desc) {
    gdts = NULL;
    hbeat = NULL;
    gdt_stats = NULL;
    cfgd_gdtc = NULL;
    rtrd_gdtc = NULL;
    config = new config::Config();
    bzero(cfgd_id, sizeof(cfgd_id));

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

GrpcdDescriptor::~GrpcdDescriptor(){
    // free routing deamons address strings
    for (unsigned int i = 0; i < rtrd_lst.size(); i++)
        delete rtrd_lst[i];
}


void GrpcdDescriptor::print_help(){
    std::cout << daemon_type << " - " << daemon_description << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -?\thelp" << std::endl;
    std::cout << " -i\tunique daemon id" << std::endl;
    std::cout << " -c\trouter daemon address (ipv4:port)" << std::endl;
    std::cout << " -w\tHTTP server port" << std::endl;
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

int GrpcdDescriptor::init_grpc() {
    GdtGrpcServer s;
    s.run();
    return 0;
}

void GrpcdDescriptor::init(){
    init_cfg(true);
    init_gdt();
    if(init_grpc()){
        // log
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "Cannot start HTTP server");
        exit(EXIT_FAILURE);
    }

}

void GrpcdDescriptor::process_args(int argc, char **argv){
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
    int opt;
    int option_index = 0;
    struct option long_options[] = {{"gdt-streams", required_argument, 0, 0},
                                    {"gdt-stimeout", required_argument, 0, 0},
                                    {0, 0, 0, 0}};

    if (argc < 5) {
        print_help();
        exit(EXIT_FAILURE);
        return;
    }

    while ((opt = getopt_long(argc, argv, "?c:i:w:D", long_options,
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

        // grpc port
        case 'w':
            if (atoi(optarg) <= 0) {
                std::cout << "ERROR: Invalid grpc port!" << std::endl;
                exit(EXIT_FAILURE);
            }
            grpc_port = atoi(optarg);
            break;

        // debug mode
        case 'D':
            set_log_level(mink::LLT_DEBUG);
            break;
        }
    }

    // check mandatory id
    if (strlen(get_daemon_id()) == 0) {
        std::cout << "ERROR: Daemon id not defined!" << std::endl;
        exit(EXIT_FAILURE);
    }


}

int GrpcdDescriptor::init_cfg(bool _proc_cfg){
    cpool.init(100);
    cpool.construct_objects();
    // pools and timeouts
    mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                              "Setting correlation pool size to [%d]...",
                               cpool.get_chunk_count());
    return 0;

}

void GrpcdDescriptor::init_gdt(){
    // service message manager
    gdtsmm = new gdt::ServiceMsgManager(&idt_map, 
                                        NULL, 
                                        NULL,
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
    std::smatch regex_groups;
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");


    // loop routing daemons
    for (size_t i = 0; i < rtrd_lst.size(); i++) {
        // separate IP and PORT
        if (!std::regex_match(*rtrd_lst[i], regex_groups, addr_regex))
            continue;
        // connect to routing daemon
        gdt::GDTClient *gdtc = gdts->connect(regex_groups[1].str().c_str(),
                                             atoi(regex_groups[2].str().c_str()), 
                                             16, 
                                             NULL, 
                                             0);

        // setup client for service messages
        if (gdtc!= NULL) {
            // setup service message event handlers
            gdtsmm->setup_client(gdtc);
        }
    }


}

void GrpcdDescriptor::terminate(){
    delete config;

}


void GrpcdDescriptor::cmap_process_timeout(){
    typedef mink_utils::CorrelationMap<GrpcPayload*>::cmap_it_type cmap_it_type;
    // lock
    cmap.lock();
    // current ts
    time_t now = time(NULL);
    // loop
    for (cmap_it_type it = cmap.begin(), it_next = it; it != cmap.end();
         it = it_next) {
        // next
        ++it_next;

        // calculate timeout
        if(now - it->second.ts <= it->second.data_timeout) continue;
        // payload
        GrpcPayload *pld = it->second.data;
        // remove from list
        cmap.remove(it);
        // call data pointer
        RPCBase *c = pld->cdata;
        // send grpc reply
        c->status_ = RPCBase::FINISH;
        c->responder_.Finish(c->reply_, grpc::Status(grpc::ABORTED, ""), c);

        std::cout << "!! TIMEOUT!!: " << c << std::endl;
        // dealloc
        cpool.deallocate_constructed(pld);


    }
    // unlock
    cmap.unlock();
}
