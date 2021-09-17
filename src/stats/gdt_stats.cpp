/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <gdt_stats.h>

void gdt::TrapClientDone::run(gdt::GDTCallbackArgs *args) {
    // implemented in derived classes
}

void gdt::TrapClientNew::run(gdt::GDTCallbackArgs *args) {
    auto client = (gdt::GDTClient *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_CLIENT);
    client->set_callback(gdt::GDT_ET_STREAM_NEW, &snew);
}

gdt::TrapStreamNew::TrapStreamNew() : trap_count(0),
                                      stats_action(asn1::StatsAction::_sa_result),
                                      ss(nullptr),
                                      snew(nullptr) {
    pt_stats_id = htobe32(asn1::ParameterType::_pt_mink_stats_id);
    pt_stats_count = htobe32(asn1::ParameterType::_pt_mink_stats_count);
    pt_stats_value = htobe32(asn1::ParameterType::_pt_mink_stats_value);
    pt_stats_desc = htobe32(asn1::ParameterType::_pt_mink_stats_description);
}

void gdt::TrapStreamNext::run(gdt::GDTCallbackArgs *args) {
    auto stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    auto include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                              gdt::GDT_CB_ARG_BODY);

    // check for trap ids
    if (sdone.snew->trap_iter != sdone.snew->traps.end()) {
        // prepare body
        if (gdtm->_body != nullptr) {
            gdtm->_body->unlink(1);
            gdtm->_body->_stats->set_linked_data(1);

        } else {
            gdtm->set_body();
            gdtm->prepare();
        }

        asn1::StatsMessage *sm = gdtm->_body->_stats;
        asn1::Parameters *p = nullptr;

        // set params
        if (sm->_params == nullptr) {
            sm->set_params();
            p = sm->_params;
            // set children, allocate more
            for (int i = 0; i < 2; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        } else {
            p = sm->_params;
            int cc = p->children.size();
            if (cc < 2) {
                // set children, allocate more
                for (int i = cc; i < 3; i++) {
                    p->set_child(i);
                    p->get_child(i)->set_value();
                    p->get_child(i)->_value->set_child(0);
                }
                // prepare
                gdtm->prepare();

            } else if (cc > 2) {
                // remove extra children if used in some other session, only 4
                // needed
                for (int i = 2; i < cc; i++) p->get_child(i)->unlink(1);
            }
        }

        // set stats action
        sm->_stats_action
          ->set_linked_data(1, (unsigned char *)&sdone.snew->stats_action, 1);

        // stats id
        p->get_child(0)
         ->_id
         ->set_linked_data(1,
                           (unsigned char *)&sdone.snew->pt_stats_id,
                           sizeof(uint32_t));
        p->get_child(0)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)sdone.snew->trap_iter->first.label.c_str(),
                           sdone.snew->trap_iter->first.label.length());

        // stats value
        p->get_child(1)
         ->_id
         ->set_linked_data(1,
                           (unsigned char *)&sdone.snew->pt_stats_value,
                           sizeof(uint32_t));
        p->get_child(1)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)&sdone.snew->trap_iter->second,
                           sizeof(uint64_t));

        // include body
        *include_body = true;

        // continue stream
        stream->continue_sequence();

        // next index
        ++sdone.snew->trap_iter;

        // end stream
    } else
        stream->end_sequence();
}

void gdt::TrapStreamNew::run(gdt::GDTCallbackArgs *args) {
    auto stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    auto include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                              gdt::GDT_CB_ARG_BODY);
    auto in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                    gdt::GDT_CB_ARG_IN_MSG);
    auto in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                             gdt::GDT_CB_ARG_IN_MSG_ID);
    char *tmp_val = nullptr;
    int tmp_val_l = 0;

    // stream new fork
    snew = new TrapStreamNew();
    snew->snext.sdone.snew = snew;
    snew->ss = ss;
    asn1::StatsMessage *sm =nullptr;
    asn1::Parameters *p = nullptr;

    // set events
    stream->set_callback(gdt::GDT_ET_STREAM_NEXT, &snew->snext);
    stream->set_callback(gdt::GDT_ET_STREAM_END, &snew->snext.sdone);
    stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT, &snew->snext.sdone);


    // check for body
    if (!in_msg->_body) goto check_traps;
    // check for config message
    if (!in_msg->_body->_stats->has_linked_data(*in_sess)) goto check_traps;
    // check for GET action
    sm = in_msg->_body->_stats;
    if (sm->_stats_action
          ->linked_node
          ->tlv
          ->value[0] != asn1::StatsAction::_sa_request) {

        stream->end_sequence();
        return;
    }
    // check for params part
    if (!sm->_params) goto check_traps;
    p = sm->_params;
    if (!p->has_linked_data(*in_sess)) goto check_traps;



    // process params
    for (unsigned int i = 0; i < p->children.size(); i++) {
        // check for current session
        if (!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if (!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if (!p->get_child(i)
              ->_value->has_linked_data(*in_sess)) continue;
        // check if child exists
        if (!p->get_child(i)
             ->_value->get_child(0)) continue;
        // check if child exists in current
        // sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(*in_sess)) continue;


        // check param id, convert from big endian to
        // host
        auto param_id = (uint32_t *)p->get_child(i)
                                     ->_id
                                     ->linked_node
                                     ->tlv
                                     ->value;

        // set tmp values
        tmp_val = (char *)p->get_child(i)
                           ->_value
                           ->get_child(0)
                           ->linked_node
                           ->tlv
                           ->value;

        tmp_val_l = p->get_child(i)
                     ->_value
                     ->get_child(0)
                     ->linked_node
                     ->tlv
                     ->value_length;

        TrapId tmp_trap_id;
        // match param
        switch (be32toh(*param_id)) {
            // config item count
            case asn1::ParameterType::_pt_mink_stats_id:
                tmp_trap_id.label.assign(tmp_val, tmp_val_l);

                // lock
                ss->lock();

                // check for special 0 (ALL)
                // id
                if (tmp_trap_id.label == "0") {
                    std::map<gdt::TrapId, gdt::GDTTrapHandler *, gdt::TrapIdCompare>
                        *tmp_map = ss->get_trap_map();
                    for (auto it = tmp_map->begin(); it != tmp_map->end();
                         ++it) {
                        tmp_trap_id = it->first;
                        snew->traps[tmp_trap_id] = htobe64(it->second->value);
                    }

                    // normal id
                } else {
                    // check if trap exists
                    const GDTTrapHandler *tmp_trph = ss->get_trap(&tmp_trap_id, true);
                    if (tmp_trph != nullptr) {
                        snew->traps[tmp_trap_id] = htobe64(tmp_trph->value);
                    }
                }

                // unlock
                ss->unlock();
                break;

            default:
                break;
        }
    }

check_traps:
    // no traps
    if (snew->traps.empty()) {
        stream->end_sequence();
        return;
    }

    // set iterator
    snew->trap_iter = snew->traps.begin();

    // prepare body
    if (gdtm->_body != nullptr) {
        gdtm->_body->unlink(1);
        gdtm->_body->_stats->set_linked_data(1);

    } else {
        gdtm->set_body();
        gdtm->prepare();
    }
    sm = gdtm->_body->_stats;
    // set params
    if (sm->_params == nullptr) {
        sm->set_params();
        p = sm->_params;
        // set children, allocate more
        for (int i = 0; i < 1; i++) {
            p->set_child(i);
            p->get_child(i)->set_value();
            p->get_child(i)->_value->set_child(0);
        }
        // prepare
        gdtm->prepare();

        // unlink params before setting new ones
    } else {
        p = sm->_params;
        int cc = p->children.size();
        if (cc < 1) {
            // set children, allocate more
            for (int i = cc; i < 1; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

        } else if (cc > 1) {
            // remove extra children if used in some other session, only 4
            // needed
            for (int i = 1; i < cc; i++) p->get_child(i)->unlink(1);
        }
    }

    // set stats action
    sm->_stats_action->set_linked_data(1, (unsigned char *)&stats_action, 1);

    // stats count
    snew->trap_count = htobe32(snew->traps.size());
    p->get_child(0)
     ->_id
     ->set_linked_data(1, (unsigned char *)&pt_stats_count, sizeof(uint32_t));

    p->get_child(0)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)&snew->trap_count, sizeof(uint32_t));

    // include body
    *include_body = true;

    // continue stream
    stream->continue_sequence();

}

void gdt::TrapStreamDone::run(gdt::GDTCallbackArgs *args) { delete snew; }

gdt::GDTTrapHandler::~GDTTrapHandler() = default;

void gdt::GDTTrapHandler::run() {
    // implemented in derived classes
}

bool gdt::TrapIdCompare::operator()(const TrapId &x, const TrapId &y) const {
    return x.label < y.label;
}

gdt::TrapId::TrapId(const char *_label) {
    if (_label != nullptr)
        label.assign(_label);
}

gdt::TrapId::TrapId(const std::string &_label) { label.assign(_label); }

// GDTStatsHandler
gdt::GDTStatsHandler::GDTStatsHandler(mink::Atomic<uint64_t> *_sval_p)
    : sval_p(_sval_p) {}

void gdt::GDTStatsHandler::run() { value = sval_p->get(); }

// GDTStatsClientCreated
void gdt::GDTStatsClientCreated::run(GDTCallbackArgs *args) {
    auto gdtc = (GDTClient *)args->get_arg(GDT_CB_INPUT_ARGS, 
                                           GDT_CB_ARG_CLIENT);
    std::string tmp;

    // in stats
    tmp.assign("GDT_IN_");
    tmp.append(gdtc->get_end_point_daemon_type());
    tmp.append("_");
    tmp.append(gdtc->get_end_point_daemon_id());
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_PACKETS")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->packets));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_BYTES")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->bytes));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAMS")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->streams));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_BYTES")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->stream_bytes));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_ERR")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->stream_errors));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_DISCARDED")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->discarded));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_MALFORMED")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->malformed));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_SOCKET_ERR")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->socket_errors));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_POOL_ERR")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->strm_alloc_errors));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_TIMEOUT")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->strm_timeout));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_LOOPBACK")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_INBOUND_STATS)->strm_loopback));

    // out stats
    tmp.assign("GDT_OUT_");
    tmp.append(gdtc->get_end_point_daemon_type());
    tmp.append("_");
    tmp.append(gdtc->get_end_point_daemon_id());
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_PACKETS")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->packets));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_BYTES")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->bytes));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAMS")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->streams));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_BYTES")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->stream_bytes));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_ERR")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->stream_errors));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_DISCARDED")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->discarded));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_MALFORMED")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->malformed));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_SOCKET_ERR")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->socket_errors));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_POOL_ERR")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->strm_alloc_errors));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_TIMEOUT")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->strm_timeout));
    gdt_stats->add_trap(gdt::TrapId(std::string(tmp + "_STREAM_LOOPBACK")),
                        new GDTStatsHandler(&gdtc->get_stats(GDT_OUTBOUND_STATS)->strm_loopback));
}

// GDTStatsClientDestroyed
void gdt::GDTStatsClientDestroyed::run(GDTCallbackArgs *args) {
    auto gdtc = (GDTClient *)args->get_arg(GDT_CB_INPUT_ARGS,
                                           GDT_CB_ARG_CLIENT);
    std::string tmp;

    // in stats
    tmp.assign("GDT_IN_");
    tmp.append(gdtc->get_end_point_daemon_type());
    tmp.append("_");
    tmp.append(gdtc->get_end_point_daemon_id());
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_PACKETS")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_BYTES")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAMS")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_BYTES")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_ERR")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_DISCARDED")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_MALFORMED")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_SOCKET_ERR")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_POOL_ERR")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_TIMEOUT")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_LOOPBACK")));

    // out stats
    tmp.assign("GDT_OUT_");
    tmp.append(gdtc->get_end_point_daemon_type());
    tmp.append("_");
    tmp.append(gdtc->get_end_point_daemon_id());
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_PACKETS")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_BYTES")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAMS")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_BYTES")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_ERR")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_DISCARDED")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_MALFORMED")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_SOCKET_ERR")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_POOL_ERR")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_TIMEOUT")));
    delete gdt_stats->remove_trap(gdt::TrapId(std::string(tmp + "_STREAM_LOOPBACK")));
}

// GDTStatsSession
gdt::GDTStatsSession::GDTStatsSession(int _poll_interval,
                                      gdt::GDTSession *_host_gdts,
                                      int _stats_port) : poll_interval(_poll_interval),
                                                         active(false),
                                                         thread_count(0),
                                                         stats_port(_stats_port),
                                                         gdts(nullptr),
                                                         host_gdts(_host_gdts) {
    pthread_mutex_init(&mtx_stats, nullptr);
    client_created.gdt_stats = this;
    client_destroyed.gdt_stats = this;
}

gdt::GDTStatsSession::~GDTStatsSession() {
    set_activity(false);
    timespec st = {0, 100000000};
    while (get_thread_count() > 0) {
        nanosleep(&st, nullptr);
    }
    gdts->stop_server();
    gdt::destroy_session(gdts);
}

void gdt::GDTStatsSession::init_gdt_session_stats(GDTSession *_gdts) {
    if (_gdts == nullptr)
        return;

    // set events
    _gdts->set_callback(GDT_ET_CLIENT_CREATED, &client_created);
    _gdts->set_callback(GDT_ET_CLIENT_DESTROYED, &client_destroyed);

}

unsigned int gdt::GDTStatsSession::inc_thread_count() {
    pthread_mutex_lock(&mtx_stats);
    unsigned int tmp = ++thread_count;
    pthread_mutex_unlock(&mtx_stats);
    return tmp;
}

unsigned int gdt::GDTStatsSession::dec_thread_count() {
    pthread_mutex_lock(&mtx_stats);
    unsigned int tmp = --thread_count;
    pthread_mutex_unlock(&mtx_stats);
    return tmp;
}

unsigned int gdt::GDTStatsSession::get_thread_count() {
    pthread_mutex_lock(&mtx_stats);
    unsigned int tmp = thread_count;
    pthread_mutex_unlock(&mtx_stats);
    return tmp;
}

void gdt::GDTStatsSession::set_activity(bool _is_active) {
    pthread_mutex_lock(&mtx_stats);
    active = _is_active;
    pthread_mutex_unlock(&mtx_stats);
}

bool gdt::GDTStatsSession::is_active() {
    pthread_mutex_lock(&mtx_stats);
    bool tmp = active;
    pthread_mutex_unlock(&mtx_stats);
    return tmp;
}

int gdt::GDTStatsSession::add_trap(const TrapId *trap_id,
                                   GDTTrapHandler *handler) {
    pthread_mutex_lock(&mtx_stats);
    int res = 0;
    auto it = trap_map.find(*trap_id);
    if (it != trap_map.end())
        res = 1;
    else {
        if (trap_id->label != "0")
            trap_map[*trap_id] = handler;
        else
            res = 1;
    }
    pthread_mutex_unlock(&mtx_stats);
    return res;
}

int gdt::GDTStatsSession::add_trap(const TrapId &trap_id,
                                   GDTTrapHandler *handler) {
    pthread_mutex_lock(&mtx_stats);
    int res = 0;
    auto it = trap_map.find(trap_id);
    if (it != trap_map.end())
        res = 1;
    else {
        if (trap_id.label != "0")
            trap_map[trap_id] = handler;
        else
            res = 1;
    }
    pthread_mutex_unlock(&mtx_stats);
    return res;
}

gdt::GDTTrapHandler *gdt::GDTStatsSession::remove_trap(const TrapId &trap_id) {
    pthread_mutex_lock(&mtx_stats);
    std::map<TrapId, GDTTrapHandler *, TrapIdCompare>::iterator it =
        trap_map.find(trap_id);
    if (it == trap_map.end()) {
        pthread_mutex_unlock(&mtx_stats);
        return nullptr;
    }
    GDTTrapHandler *res = it->second;
    trap_map.erase(it);
    pthread_mutex_unlock(&mtx_stats);
    return res;
}

uint64_t gdt::GDTStatsSession::get_trap_value(const TrapId *trap_id) {
    uint64_t res = 0;
    pthread_mutex_lock(&mtx_stats);
    auto it = trap_map.find(*trap_id);
    if (it != trap_map.end()) {
        res = it->second->value;
    }
    pthread_mutex_unlock(&mtx_stats);
    return res;
}

void gdt::GDTStatsSession::lock() { pthread_mutex_lock(&mtx_stats); }

void gdt::GDTStatsSession::unlock() { pthread_mutex_unlock(&mtx_stats); }

gdt::GDTTrapHandler *gdt::GDTStatsSession::get_trap(const TrapId *trap_id,
                                                    bool unsafe) {
    GDTTrapHandler *tmp_handler = nullptr;
    if (!unsafe)
        pthread_mutex_lock(&mtx_stats);
    auto it = trap_map.find(*trap_id);
    if (it != trap_map.end()) {
        tmp_handler = it->second;
    }
    if (!unsafe)
        pthread_mutex_unlock(&mtx_stats);
    return tmp_handler;
}

std::map<gdt::TrapId, gdt::GDTTrapHandler *, gdt::TrapIdCompare> *
gdt::GDTStatsSession::get_trap_map() {
    return &trap_map;
}

void gdt::GDTStatsSession::setup_client(gdt::GDTClient *_client) {
    _client->set_callback(gdt::GDT_ET_STREAM_NEW, &new_client.snew);
}

void gdt::GDTStatsSession::start() {
    std::string tmp_dtype;
    std::string tmp_did;

    // set activity flag
    active = true;

    // set daemon type and id
    tmp_dtype.append("%");
    tmp_dtype.append(host_gdts->get_daemon_type());
    tmp_did.append("%");
    tmp_did.append(host_gdts->get_daemon_id());

    // start GDT session
    gdts =
        gdt::init_session(tmp_dtype.c_str(), tmp_did.c_str(), 100, 5, false, 5);
    // accept connections (server mode)
    if (stats_port > 0)
        gdts->start_server(nullptr, stats_port);
    // events
    new_client.ss = this;
    new_client.snew.ss = this;
    gdts->set_callback(gdt::GDT_ET_CLIENT_NEW, &new_client);
    gdts->set_callback(gdt::GDT_ET_CLIENT_TERMINATED, &client_done);

    // init trap thread
    pthread_t tmp_thread;
    if (pthread_create(&tmp_thread, nullptr, &trap_loop, this) == 0) {
        inc_thread_count();
        pthread_setname_np(tmp_thread, "gdt_stats");
    }
}

void gdt::GDTStatsSession::stop() { set_activity(false); }

gdt::GDTSession *gdt::GDTStatsSession::get_gdt_session() { return gdts; }

void *gdt::GDTStatsSession::trap_loop(void *args) {
    if (args != nullptr) {
        auto ss = (GDTStatsSession *)args;
        const std::map<TrapId, GDTTrapHandler *, TrapIdCompare> *tmp_map =
            ss->get_trap_map();
        int total_sleep = 0;
        using val_t =  std::map<TrapId, GDTTrapHandler *, TrapIdCompare>::value_type;

        // loop
        while (ss->is_active()) {
            // sleep 1 sec
            sleep(1);
            ++total_sleep;
            // check if user timeout has been reached
            if (total_sleep < ss->poll_interval)
                continue;
            // reset current timeout
            total_sleep = 0;

            // lock
            pthread_mutex_lock(&ss->mtx_stats);

            // loop
            std::all_of(tmp_map->cbegin(), tmp_map->cend(), [](const val_t &p) {
                p.second->run();
                return true;
            });
            // unlock
            pthread_mutex_unlock(&ss->mtx_stats);
        }
        // detach thread
        pthread_detach(pthread_self());
        ss->dec_thread_count();
    }

    return nullptr;
}

