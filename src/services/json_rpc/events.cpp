/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "ws_server.h"
#include <json_rpc.h>
#include <daemon.h>
#include <atomic.h>
#include <gdt.pb.enums_only.h>
#include <zlib.h>

using data_vec_t = std::vector<uint8_t>;

#ifdef MINK_ENABLE_CONFIGD
EVHbeatMissed::EVHbeatMissed(mink::Atomic<uint8_t> *_activity_flag): activity_flag(_activity_flag) {}

void EVHbeatMissed::run(gdt::GDTCallbackArgs *args) {
    gdt::HeartbeatInfo *hi = args->get<gdt::HeartbeatInfo>(gdt::GDT_CB_INPUT_ARGS, 
                                                           gdt::GDT_CB_ARG_HBEAT_INFO);
    // set activity flag to false
    activity_flag->comp_swap(true, false);
    // stop heartbeat
    gdt::stop_heartbeat(hi);
    // display warning
    mink::CURRENT_DAEMON->log(
        mink::LLT_DEBUG,
        "GDT HBEAT not received, closing connection to [%s]...",
        hi->target_daemon_id);
}

void EVHbeatRecv::run(gdt::GDTCallbackArgs *args) {
    // do nothing
}

EVHbeatCleanup::EVHbeatCleanup(EVHbeatRecv *_recv, EVHbeatMissed *_missed) : missed(_missed),
                                                                             recv(_recv) {}

void EVHbeatCleanup::run(gdt::GDTCallbackArgs *args) {
    delete recv;
    delete missed;
    delete this;

    // get daemon pointer
    auto dd = static_cast<JsonRpcdDescriptor *>(mink::CURRENT_DAEMON);
    // init config until connected
    while (!mink::DaemonDescriptor::DAEMON_TERMINATED &&
           dd->init_cfg(false) != 0) {
        sleep(5);
    }
}
#endif

static void handle_error(const mink_utils::VariantParam *vp_err,
                         int id,
                         std::shared_ptr<WebSocketBase> &ws){
    int ec = mink::error::EC_UNKNOWN;
    try {
        if (vp_err)
            ec = std::stoi(static_cast<char *>(*vp_err));
    } catch (std::exception &e) {
        // nothing for now
    }
    // create json rpc reply
    std::string ws_rpl = json_rpc::JsonRpc::gen_err(ec, id).dump();
    //beast::flat_buffer &b = ws->get_buffer();
    //std::size_t sz = net::buffer_copy(b.prepare(ws_rpl.size()),
    //                                            net::buffer(ws_rpl));

    // send json rpc reply
    //b.commit(sz);
    ws->async_buffer_send(ws_rpl);
    //ws->get_stream().async_write(b.data(),
    //                             beast::bind_front_handler(&WebSocketBase::on_write,
    //                                                       ws));

}

static std::string sparam_zlib_decmpress(const uint8_t *data, 
                                         const std::size_t sz,
                                         char *out_buff, 
                                         const std::size_t out_buf_sz){
    // output string
    std::string s;
    // decompress
    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    // input size
    zs.avail_in = sz;
    // input data
    zs.next_in = (Bytef *)data;
    zs.avail_out = out_buf_sz;
    zs.next_out = (Bytef *)out_buff;
    // init decompress struct
    int z_res = inflateInit(&zs);
    if(z_res != Z_OK){
        // cleanup
        delete data;
    }
    // decompress
    do {
        // inflate and flush to buffer
        z_res = inflate(&zs, Z_SYNC_FLUSH);
        // error
        if (z_res < 0 && z_res != Z_BUF_ERROR)
            break;

        //  append uncompressed data
        s.append(out_buff, out_buf_sz - zs.avail_out);
        // update zlib struct
        if (zs.avail_out == 0) {
            zs.avail_out = out_buf_sz;
            zs.next_out = (Bytef *)out_buff;
        }
    } while (z_res != Z_STREAM_END);

    // zlib cleanup
    inflateEnd(&zs);
    // res
    return s;
}

void EVSrvcMsgRecv::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage* smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS, 
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    auto dd = static_cast<JsonRpcdDescriptor*>(mink::CURRENT_DAEMON);

    // check for missing params
    if (smsg->missing_params) {
        // TODO stats
        return;
    }

    // check for incomplete msg
    if (!smsg->is_complete()) {
        // TODO stats
        return;
    }

    // check service id
    switch (smsg->get_service_id()) {
        case asn1::ServiceId::_sid_sysagent:
            break;

        default:
            // unsupported
            return;
    }

    // check for source type
    const mink_utils::VariantParam *vp_src_type = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_type);
    if (vp_src_type == nullptr) return;

    // check for source id
    const mink_utils::VariantParam *vp_src_id = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_id);
    if (vp_src_id == nullptr) return;

    // check for guid
    const mink_utils::VariantParam *vp_guid = smsg->vpget(asn1::ParameterType::_pt_mink_guid);
    if(!vp_guid) return;

    // persistent guid
    const mink_utils::VariantParam *vp_p_guid = smsg->vpget(asn1::ParameterType::_pt_mink_persistent_correlation);

    // error check
    const mink_utils::VariantParam *vp_err = smsg->vpget(asn1::ParameterType::_pt_mink_error);

    // correlate guid
    dd->cmap.lock();
    mink_utils::Guid guid;
    guid.set(static_cast<uint8_t *>((unsigned char *)*vp_guid));
    JrpcPayload *pld = dd->cmap.get(guid);
    if(!pld){
        dd->cmap.unlock();
        return;
    }
    // set as persistent (if requested)
    if (vp_p_guid)
        pld->persistent = true;
    else
        pld->persistent = false;

    // id
    int id = pld->id;
    auto ts_req = pld->ts;
    auto ts_now = std::chrono::system_clock::now();
    // session pointer
    std::shared_ptr<WebSocketBase> ws = pld->cdata.lock();
    // check is session has expired
    if(ws.get() == nullptr){
        dd->cmap.remove(guid);
        dd->cmap.unlock();
        return;
    }

    // generate empty json rpc reply
    auto j = json_rpc::JsonRpc::gen_response(id);
    // update ts
    dd->cmap.update_ts(guid);
    if(!pld->persistent) dd->cmap.remove(guid);
    // unlock
    dd->cmap.unlock();


    // if error found
    if(vp_err){
        handle_error(vp_err, id, ws);
        return;
    }

    // create result object
    j[json_rpc::JsonRpc::RESULT_] = json::array();
    auto &j_params = j.at(json_rpc::JsonRpc::RESULT_);
    // tmp val string
    std::string val;

    // remove auth params and guid
    smsg->vpmap.erase_param(asn1::ParameterType::_pt_mink_auth_id);
    smsg->vpmap.erase_param(asn1::ParameterType::_pt_mink_auth_password);
    smsg->vpmap.erase_param(asn1::ParameterType::_pt_mink_guid);

    // loop GDT params
    mink_utils::PooledVPMap<uint32_t>::it_t it = smsg->vpmap.get_begin();

    // zlib out buffer
    char z_out_buff[65535];

    // loop param map
    for(; it != smsg->vpmap.get_end(); it++){
        // param name from ID
        auto itt = gdt_grpc::SysagentParamMap.find(it->first.key);
        const std::string pname = (itt != gdt_grpc::SysagentParamMap.cend() ? itt->second : "n/a");
        // get param type
        const int pt = it->second.get_type();

        // pointer type is used for long params (fragmented)
        if(pt == mink_utils::DPT_POINTER){
            auto data = static_cast<data_vec_t *>((void *)it->second);
            try {
                // output string
                std::string s = sparam_zlib_decmpress(data->data(),
                                                      data->size(),
                                                      z_out_buff,
                                                      sizeof(z_out_buff));
                // compressed/uncompressed
                if (s.empty()) {
                    s.assign(reinterpret_cast<char *>(data->data()), data->size());
                }
                // new json object
                auto o = json::object();
                o[pname] = s;
                o["idx"] = it->first.index;
                // new json rpc param object
                j_params.push_back(o);

            } catch (std::exception &e) {
                mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                         "cannot reassemble fragmented GDT data: [%s]",
                                          e.what());

            }
            // cleanup
            delete data;
            continue;
        }


        // short STRING
        if (pt == mink_utils::DPT_STRING) {
            val = static_cast<char *>(it->second);

        // STRING as OCTETES (check if printable)
        } else if (pt == mink_utils::DPT_OCTETS) {
            // sparam data
            unsigned char *od = static_cast<unsigned char *>(it->second);
            // output string
            val = sparam_zlib_decmpress(od,
                                        it->second.get_size(),
                                        z_out_buff,
                                        sizeof(z_out_buff));
            
            // compressed/uncompressed
            if (val.empty()) {
                val.assign(reinterpret_cast<char *>(od), it->second.get_size());
            }

        // ignore other types
        } else continue;

        // setup json object
        auto o = json::object();
        o["idx"] = it->first.index;
        o[pname] = val;
        // new json rpc param object
        j_params.push_back(o);
    }

    // verfify json
    try {
        std::string ws_rpl = j.dump();
        //std::unique_lock<std::mutex> l(ws->get_mtx());
        //beast::flat_buffer &b = ws->get_buffer();
        //std::size_t sz = net::buffer_copy(b.prepare(ws_rpl.size()),
        //                                  net::buffer(ws_rpl));

        // send json rpc reply (success)
        //b.commit(sz);
        //l.unlock();
        ws->async_buffer_send(ws_rpl);
        mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                  "JSON RPC received for id = [%d], latency = [%d msec]",
                                  id,
                                  std::chrono::duration_cast<std::chrono::milliseconds>(ts_now - ts_req));

        //ws->get_stream().async_write(b.data(),
        //                             beast::bind_front_handler(&WebSocketBase::on_write,
        //                                                       ws));
    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                  "JSON RPC error: [%s]",
                                  e.what());

        // send error
        handle_error(nullptr, id, ws);
    }
}

void EVParamStreamLast::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage *smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    gdt::ServiceParam *sparam = args->get<gdt::ServiceParam>(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARGS_SRVC_PARAM);

    // save data
    auto data = static_cast<data_vec_t *>(smsg->params.get_param(2));
    data->insert(data->end(),
                 sparam->get_data(),
                 sparam->get_data() + sparam->get_data_size());
    smsg->vpmap.set_pointer(sparam->get_id(), data, sparam->get_index());
    smsg->params.remove_param(2);

}

void EVParamStreamNext::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage *smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    gdt::ServiceParam *sparam = args->get<gdt::ServiceParam>(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARGS_SRVC_PARAM);

    // save data
    auto data = static_cast<data_vec_t *>(smsg->params.get_param(2));
    data->insert(data->end(),
                 sparam->get_data(),
                 sparam->get_data() + sparam->get_data_size());

}

void EVParamStreamNew::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage *smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    gdt::ServiceParam *sparam = args->get<gdt::ServiceParam>(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARGS_SRVC_PARAM);

    // set handlers
    sparam->set_callback(gdt::GDT_ET_SRVC_PARAM_STREAM_NEXT, &prm_strm_next);
    sparam->set_callback(gdt::GDT_ET_SRVC_PARAM_STREAM_END, &prm_strm_last);

    // save data
    auto data = new data_vec_t();
    data->insert(data->end(),
                 sparam->get_data(),
                 sparam->get_data() + sparam->get_data_size());
    smsg->params.set_param(2, data);
}

void EVParamShortNew::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage *smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    gdt::ServiceParam *sparam = args->get<gdt::ServiceParam>(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARGS_SRVC_PARAM);
    // save data
    smsg->vpmap.set_octets(sparam->get_id(),
                           sparam->get_data(),
                           sparam->get_data_size(),
                           sparam->get_index());
}

void EVSrvcMsgRX::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage *smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    // set handlers
    smsg->set_callback(gdt::GDT_ET_SRVC_MSG_COMPLETE, &msg_recv);
    smsg->set_callback(gdt::GDT_ET_SRVC_PARAM_STREAM_NEW, &prm_strm_new);
    smsg->set_callback(gdt::GDT_ET_SRVC_SHORT_PARAM_NEW, &prm_short_new);
}

void EVSrvcMsgSent::run(gdt::GDTCallbackArgs *args){
    // get service message
    gdt::ServiceMessage *smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    // get extra user callback and free it
    auto usr_cb = static_cast<GDTCallbackMethod *>(smsg->params.get_param(3));
    delete usr_cb;

    // return service message to pool
    smsg->get_smsg_manager()->free_smsg(smsg);
}

void EVSrvcMsgErr::run(gdt::GDTCallbackArgs *args){
    // reserved
}


