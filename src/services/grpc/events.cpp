/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "events.h"
#include "grpc.h"
#include <daemon.h>
#include <atomic.h>

using data_vec_t = std::vector<uint8_t>;

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
    auto dd = static_cast<GrpcdDescriptor *>(mink::CURRENT_DAEMON);
    // init config until connected
    while (!mink::DaemonDescriptor::DAEMON_TERMINATED &&
           dd->init_cfg(false) != 0) {
        sleep(5);
    }
}

void EVSrvcMsgRecv::run(gdt::GDTCallbackArgs *args){
    std::cout << "EVSrvcMsgRecv::run" << std::endl;
    gdt::ServiceMessage* smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS, 
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    auto dd = static_cast<GrpcdDescriptor*>(mink::CURRENT_DAEMON);
    auto gdt_stream = args->get<gdt::GDTStream>(gdt::GDT_CB_INPUT_ARGS, 
                                                gdt::GDT_CB_ARG_STREAM);
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

    std::cout << "Service ID found!!!" << std::endl;

    // check for source type
    const mink_utils::VariantParam *vp_src_type = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_type);
    if (vp_src_type == nullptr) return;

    // check for source id
    const mink_utils::VariantParam *vp_src_id = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_id);
    if (vp_src_id == nullptr) return;

    std::cout << "Source daemon found!!!" << (char *)*vp_src_type << ":" << (char *)*vp_src_id <<std::endl;
    // check for guid
    const mink_utils::VariantParam *vp_guid = smsg->vpget(asn1::ParameterType::_pt_mink_guid);
    if(!vp_guid) return;
    
    std::cout << "GUIDD found!!!" << std::endl;

    // correlate guid
    dd->cmap.lock();
    mink_utils::Guid guid;
    guid.set(static_cast<uint8_t *>((unsigned char *)*vp_guid));
    GrpcPayload **pld = dd->cmap.get(guid);
    if(!pld){
        dd->cmap.unlock();
        return;
    }
    // update ts
    dd->cmap.update_ts(guid);
    dd->cmap.remove(guid);
    // unlock
    dd->cmap.unlock();


    std::cout << "GUIDD correlated!!!" << std::endl;

    // call data pointer
    RPCBase *c = (*pld)->cdata;
    // header
    gdt_grpc::Header *hdr = c->reply_.mutable_header();
    gdt_grpc::Body *bdy = c->reply_.mutable_body();
    // set header
    hdr->mutable_source()->set_id(static_cast<char*>(*vp_src_id));
    hdr->mutable_source()->set_type(static_cast<char*>(*vp_src_type));
    
    // set params
    mink_utils::PooledVPMap<uint32_t>::it_t it = smsg->vpmap.get_begin();
    // loop param map
    for(; it != smsg->vpmap.get_end(); it++){
        // pointer type is used for long params
        if(it->second.get_type() == mink_utils::DPT_POINTER){
            auto data = static_cast<data_vec_t *>((void *)it->second);
            std::string s(reinterpret_cast<char *>(data->data()), data->size());
            // new grpc param
            gdt_grpc::Body::Param *p = bdy->add_params();
            p->set_id(it->first.key);
            p->set_index(it->first.index);
            p->set_value(s);
            delete data;
            continue;
        }
        // skip non-string params
        if(it->second.get_type() != mink_utils::DPT_STRING) continue;
        // new grpc param
        gdt_grpc::Body::Param *p = bdy->add_params();
        p->set_id(it->first.key);
        p->set_index(it->first.index);
        p->set_value(static_cast<char*>(it->second));

        std::cout << it->first.key << " - " << (char*)it->second << std::endl;

    }
    
    // send grpc reply
    c->status_ = RPCBase::FINISH;
    c->responder_.Finish(c->reply_, grpc::Status::OK, c);

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

void EVSrvcMsgRX::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage *smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS, 
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    // set handlers
    smsg->set_callback(gdt::GDT_ET_SRVC_MSG_COMPLETE, &msg_recv);
    smsg->set_callback(gdt::GDT_ET_SRVC_PARAM_STREAM_NEW, &prm_strm_new);
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
    std::cout << "<<<< FREE!!!!<< " << std::endl;
}

void EVSrvcMsgErr::run(gdt::GDTCallbackArgs *args){
    // reserved
}
