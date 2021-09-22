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
#include <gdt.h>
#include <gdt_stats.h>
#include <getopt.h>
#include <iomanip>
#include <mink_utils.h>
#include <sstream>
#include <regex>
#include <time.h>

void print_help() {
    std::cout << "gdttrapc - MINK GDT trap client" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -c\ttarget daemon address (ipv4:port)" << std::endl;
    std::cout << " -t\ttarget daemon type" << std::endl;
    std::cout << " -i\ttarget daemon id" << std::endl;
    std::cout << " -s\ttarget trap id (0 for ALL)" << std::endl;
    std::cout << " -a\tunique client id" << std::endl;
    std::cout << std::endl;
    std::cout << "GDT Options:" << std::endl;
    std::cout << "=============" << std::endl;
    std::cout << " --gdt-streams\t\tGDT Session stream pool\t\t(default = 10)"
              << std::endl;
    std::cout
        << " --gdt-stimeout\tGDT Stream timeout in seconds\t\t(default = 5)"
        << std::endl;
    std::cout << " --gdt-smsg-pool\tGDT Service message pool\t\t(default = 10)"
              << std::endl;
    std::cout << " --gdt-sparam-pool\tGDT Service message parameter "
                 "pool\t(default = 1000)"
              << std::endl;
}

class TrapVal {
public:
    TrapVal() : value(0) {
        // bzero(desc, sizeof(desc));
    }
    // char desc[81];
    uint64_t value;
};

class AllDone : public gdt::GDTCallbackMethod {
public:
    AllDone() { sem_init(&signal, 0, 0); }
    ~AllDone() { sem_destroy(&signal); }

    // event handler method
    void run(gdt::GDTCallbackArgs *args) { sem_post(&signal); }

    // signal
    sem_t signal;
};

class TrapDone : public gdt::GDTCallbackMethod {
public:
    // event handler method
    void run(gdt::GDTCallbackArgs *args) {
        gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(
            gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_STREAM);
        asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(
            gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_IN_MSG);
        uint64_t *in_sess = (uint64_t *)args->get_arg(
            gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_IN_MSG_ID);

        // check for timeout error
        if (in_msg == NULL) {
            adone.run(args);
            return;
        }

        // check for error
        if (in_msg->_header->_status != NULL) {
            if (in_msg->_header->_status->has_linked_data(*in_sess)) {
                if (in_msg->_header->_status->linked_node->tlv->value[0] != 0) {
                    adone.run(args);
                    return;
                }
            }
        }
        // wait until stream complete was properly sent
        stream->set_callback(gdt::GDT_ET_PAYLOAD_SENT, &adone);
    }

    AllDone adone;
    std::map<std::string, TrapVal *> *traps;
};

class TrapNext : public gdt::GDTCallbackMethod {
public:
    // event handler method
    void run(gdt::GDTCallbackArgs *args) {
        gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(
            gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_STREAM);
        asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(
            gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_IN_MSG);
        uint64_t *in_sess = (uint64_t *)args->get_arg(
            gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_IN_MSG_ID);
        char *tmp_val = NULL;
        int tmp_val_l = 0;
        std::string tmp_sid;
        uint64_t *tmp_svalp;
        uint64_t tmp_sval;
        TrapVal *trap_val;

        // check for body
        if (in_msg->_body != NULL) {
            // check for config message
            if (in_msg->_body->_stats->has_linked_data(*in_sess)) {
                // check for GET action
                if (in_msg->_body->_stats->_stats_action->linked_node->tlv
                        ->value[0] == asn1::StatsAction::_sa_result) {
                    // check for params part
                    if (in_msg->_body->_stats->_params != NULL) {
                        if (in_msg->_body->_stats->_params->has_linked_data(
                                *in_sess)) {
                            // process params
                            for (unsigned int i = 0;
                                 i < in_msg->_body->_stats->_params->children
                                         .size();
                                 i++) {
                                // check for current session
                                if (in_msg->_body->_stats->_params->get_child(i)
                                        ->has_linked_data(*in_sess)) {
                                    // check param id, convert from big endian
                                    // to host
                                    uint32_t *param_id =
                                        (uint32_t *)in_msg->_body->_stats
                                            ->_params->get_child(i)
                                            ->_id->linked_node->tlv->value;
                                    // check for value
                                    if (in_msg->_body->_stats->_params
                                            ->get_child(i)
                                            ->_value != NULL) {
                                        // check if value exists in current
                                        // session
                                        if (in_msg->_body->_stats->_params
                                                ->get_child(i)
                                                ->_value->has_linked_data(
                                                    *in_sess)) {
                                            // check if child exists
                                            if (in_msg->_body->_stats->_params
                                                    ->get_child(i)
                                                    ->_value->get_child(0) !=
                                                NULL) {
                                                // check if child exists in
                                                // current sesion
                                                if (in_msg->_body->_stats
                                                        ->_params->get_child(i)
                                                        ->_value->get_child(0)
                                                        ->has_linked_data(
                                                            *in_sess)) {
                                                    // set tmp values
                                                    tmp_val =
                                                        (char *)in_msg->_body
                                                            ->_stats->_params
                                                            ->get_child(i)
                                                            ->_value
                                                            ->get_child(0)
                                                            ->linked_node->tlv
                                                            ->value;
                                                    tmp_val_l =
                                                        in_msg->_body->_stats
                                                            ->_params
                                                            ->get_child(i)
                                                            ->_value
                                                            ->get_child(0)
                                                            ->linked_node->tlv
                                                            ->value_length;

                                                    // match param
                                                    switch (
                                                        be32toh(*param_id)) {
                                                    // config item count
                                                    case asn1::ParameterType::
                                                        _pt_mink_stats_id:
                                                        // tmp_ivp =
                                                        // (uint32_t*)tmp_val;
                                                        // tmp_sid = *tmp_ivp;
                                                        tmp_sid.assign(
                                                            tmp_val, tmp_val_l);
                                                        break;

                                                    case asn1::ParameterType::
                                                        _pt_mink_stats_value:
                                                        tmp_svalp =
                                                            (uint64_t *)tmp_val;
                                                        tmp_sval =
                                                            be64toh(*tmp_svalp);
                                                        trap_val =
                                                            new TrapVal();
                                                        trap_val->value =
                                                            tmp_sval;
                                                        // memcpy(trap_val->desc,
                                                        // tmp_val, tmp_val_l);
                                                        (*tdone->traps)
                                                            [tmp_sid] =
                                                                trap_val;

                                                        break;
                                                        /*
                                                    case
                                                    asn1::ParameterType::_pt_mink_stats_description:
                                                        trap_val = new
                                                    TrapVal(); trap_val->value =
                                                    tmp_sval;
                                                        //memcpy(trap_val->desc,
                                                    tmp_val, tmp_val_l);
                                                        (*tdone->traps)[tmp_sid]
                                                    = trap_val; break;
                                                    */
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // not stats request
                } else {
                    stream->end_sequence();
                }
            }
        }

        // continue
        stream->continue_sequence();
    }

    TrapDone *tdone;
};

int main(int argc, char **argv) {
    int opt;
    std::regex addr_regex("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d+)");
    std::string dm_type;
    std::string dm_id;
    std::string dm_addr;
    std::string client_id;
    std::smatch regex_groups;
    std::map<std::string, TrapVal *> traps;
    int option_index = 0;
    struct option long_options[] = {
        {"gdt-streams", required_argument, 0, 0},
        {"gdt-stimeout", required_argument, 0, 0},
        {"gdt-smsg-pool", required_argument, 0, 0},
        {"gdt-sparam-pool", required_argument, 0, 0},
        {0, 0, 0, 0}};
    // extra options
    mink_utils::VariantParamMap<uint32_t> extra_params;

    // default extra param values
    // --gdt-streams
    extra_params.set_int(0, 10);
    // --gdt-stimeout
    extra_params.set_int(1, 5);
    // --gdt-smsg-pool
    extra_params.set_int(2, 10);
    // --gdt-sparam-pool
    extra_params.set_int(3, 1000);

    // argc check
    if (argc < 11) {
        print_help();
        return 1;
    } else {
        while ((opt = getopt_long(argc, argv, "c:t:i:s:a:", long_options,
                                  &option_index)) != -1) {
            // while ((opt = getopt(argc, argv, "c:t:i:s:a:")) != -1) {
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

                // gdt-smsg-pool
                case 2:
                    extra_params.set_int(2, atoi(optarg));
                    break;

                // gdt-sparam-pool
                case 3:
                    extra_params.set_int(3, atoi(optarg));
                    break;
                }
                break;

            // client id
            case 'a':
                client_id = optarg;
                if (client_id.size() > 10) {
                    std::cout << "ERROR: Maximum size of client id string is "
                                 "10 characters!"
                              << std::endl;
                    exit(EXIT_FAILURE);
                }
                break;

            // target daemon id
            case 'i':
                dm_id = optarg;
                if (dm_id.size() > 15) {
                    std::cout << "ERROR: Maximum size of daemon id string is "
                                 "15 characters!"
                              << std::endl;
                    exit(EXIT_FAILURE);
                }
                break;

            // target daemon type
            case 't':
                dm_type = optarg;
                if (dm_type.size() > 15) {
                    std::cout << "ERROR: Maximum size of daemon type string is "
                                 "15 characters!"
                              << std::endl;
                    exit(EXIT_FAILURE);
                }
                break;

            // target trap id
            case 's':
                // traps[htobe32(atoi(optarg))] = NULL;
                traps[optarg] = NULL;
                break;

            // config daemon address
            case 'c':
                // check pattern (ipv4:port)
                // check if valid
                if (!std::regex_match(optarg, addr_regex)) {
                    std::cout << "ERROR: Invalid daemon address format '"
                              << optarg << "'!" << std::endl;
                    exit(EXIT_FAILURE);
                }
                dm_addr = optarg;
                // separate IP and PORT
                std::regex_search(dm_addr, regex_groups, addr_regex);
                break;
            }
        }
        // client id check
        if (client_id == "") {
            std::cout << "ERROR: Client id missing!" << std::endl;
            exit(EXIT_FAILURE);
        }

        // id check
        if (dm_id == "") {
            std::cout << "ERROR: Target daemon id missing!" << std::endl;
            exit(EXIT_FAILURE);
        }

        // type check
        if (dm_type == "") {
            std::cout << "ERROR: Target daemon type missing!" << std::endl;
            exit(EXIT_FAILURE);
        }

        // trap check
        if (traps.size() == 0) {
            std::cout << "ERROR: Target trap id missing!" << std::endl;
            exit(EXIT_FAILURE);
        }
        // addr check
        if (dm_addr == "") {
            std::cout << "ERROR: Target daemon address missing!" << std::endl;
            exit(EXIT_FAILURE);
        }
        // update daemon type and id
        dm_type.insert(0, "%");
        dm_id.insert(0, "%");

        // get pid and generate daemon id
        pid_t pd = getpid();
        std::ostringstream tmp_id;
        tmp_id << client_id << pd;

        // start GDT session
        gdt::GDTSession *gdts = gdt::init_session(
            "gdttrapc", tmp_id.str().c_str(), (int)*extra_params.get_param(0),
            (int)*extra_params.get_param(1), false,
            (int)*extra_params.get_param(1));

        // gdt::GDTSession* gdts = gdt::init_session("gdttrapc",
        // tmp_id.str().c_str() , 10, 1, false, 1);
        // connect
        gdt::GDTClient *gdt_client =
            gdts->connect(regex_groups[1].str().c_str(),
                          atoi(regex_groups[2].str().c_str()), 16, NULL, 0);

        // check client
        if (gdt_client != NULL) {
            TrapNext tnext;
            TrapDone tdone;
            tnext.tdone = &tdone;
            tdone.traps = &traps;

            // start new GDT stream
            gdt::GDTStream *gdt_stream = gdt_client->new_stream(
                dm_type.c_str(), dm_id.c_str(), NULL, &tnext);
            // if stream cannot be created, return err
            if (gdt_stream == NULL) {
                std::cout << "ERROR: Cannot allocate GDT stream!" << std::endl;
                exit(EXIT_FAILURE);
            }
            // set end event handler
            gdt_stream->set_callback(gdt::GDT_ET_STREAM_END, &tdone);
            gdt_stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT, &tdone);

            // create body
            asn1::GDTMessage *gdtm = gdt_stream->get_gdt_message();
            // prepare body
            if (gdtm->_body != NULL) {
                gdtm->_body->unlink(1);
                gdtm->_body->_stats->set_linked_data(1);

            } else {
                gdtm->set_body();
                gdtm->prepare();
            }

            // ids
            uint32_t pt_stats_id =
                htobe32(asn1::ParameterType::_pt_mink_stats_id);
            uint32_t stats_action = asn1::StatsAction::_sa_request;

            // set params
            if (gdtm->_body->_stats->_params == NULL) {
                gdtm->_body->_stats->set_params();
                // set children, allocate more
                for (unsigned int i = 0; i < traps.size(); i++) {
                    gdtm->_body->_stats->_params->set_child(i);
                    gdtm->_body->_stats->_params->get_child(i)->set_value();
                    gdtm->_body->_stats->_params->get_child(i)
                        ->_value->set_child(0);
                }
                // prepare
                gdtm->prepare();

                // unlink params before setting new ones
            } else {
                unsigned int cc = gdtm->_body->_stats->_params->children.size();
                if (cc < traps.size()) {
                    // set children, allocate more
                    for (unsigned int i = cc; i < traps.size(); i++) {
                        gdtm->_body->_stats->_params->set_child(i);
                        gdtm->_body->_stats->_params->get_child(i)->set_value();
                        gdtm->_body->_stats->_params->get_child(i)
                            ->_value->set_child(0);
                    }
                    // prepare
                    gdtm->prepare();

                } else if (cc > traps.size()) {
                    // remove extra children if used in some other session, only
                    // 2 needed
                    for (unsigned int i = traps.size(); i < cc; i++)
                        gdtm->_body->_stats->_params->get_child(i)->unlink(1);
                }
            }

            // set stats action
            gdtm->_body->_stats->_stats_action->set_linked_data(
                1, (unsigned char *)&stats_action, 1);

            // trap ids
            typedef std::map<std::string, TrapVal *>::iterator it_type;
            it_type it = traps.begin();
            for (unsigned int i = 0; i < traps.size(); i++) {
                // stats id
                gdtm->_body->_stats->_params->get_child(i)
                    ->_id->set_linked_data(1, (unsigned char *)&pt_stats_id,
                                           sizeof(uint32_t));
                gdtm->_body->_stats->_params->get_child(i)
                    ->_value->get_child(0)
                    ->set_linked_data(1, (unsigned char *)it->first.c_str(),
                                      it->first.length());
                ++it;
            }

            // start stream
            gdt_stream->send();

            // wait for signal
            timespec ts;
            clock_gettime(0, &ts);
            ts.tv_sec += 10;
            // int sres = sem_timedwait(&tdone.adone.signal, &ts);
            int sres = sem_wait(&tdone.adone.signal);
            // error check
            if (sres == -1) {
                std::cout << "ERROR: Timeout while waiting for data!"
                          << std::endl;
                exit(EXIT_FAILURE);
            }

            unsigned int max_id_size = 0;
            // get max id size
            for (it_type it = traps.begin(); it != traps.end(); it++)
                if (it->first != "0") {
                    if (it->first.length() > max_id_size)
                        max_id_size = it->first.length();
                }

            // print result
            std::cout << std::setw(max_id_size) << "Trap Id" << std::setw(30)
                      << "Trap Value"
                      << std::endl;
            std::cout << std::setfill('-') << std::setw(max_id_size + 30) << '-'
                      << std::endl;
            std::cout << std::setfill(' ');

            // loop traps
            for (it_type it = traps.begin(); it != traps.end(); it++)
                if (it->first != "0") {
                    if (it->second != NULL) {
                        std::cout << std::setw(max_id_size) << it->first << std::setw(30)
                                  << it->second->value
                                  << std::endl;
                        delete it->second;

                        // no data available
                    } else {
                        std::cout << std::setw(max_id_size) << it->first << std::setw(30)
                                  << std::endl;
                    }
                }
        }
        // free GDT session
        gdt::destroy_session(gdts);
    }
    return 0;
}
