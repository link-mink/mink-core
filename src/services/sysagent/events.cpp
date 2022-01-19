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
#include "sysagent.h"
#include <daemon.h>
#include <thread>
#include <atomic.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <proc/readproc.h>
#include <config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif

using data_vec_t = std::vector<uint8_t>;

#ifdef ENABLE_CONFIGD
EVHbeatMissed::EVHbeatMissed(mink::Atomic<uint8_t> *_activity_flag) : activity_flag(_activity_flag) {}

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
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // init config until connected
    while (!mink::DaemonDescriptor::DAEMON_TERMINATED &&
           dd->init_cfg(false) != 0) {
        sleep(5);
    }
}
#endif

void EVSrvcMsgRecv::run(gdt::GDTCallbackArgs *args){
    gdt::ServiceMessage* smsg = args->get<gdt::ServiceMessage>(gdt::GDT_CB_INPUT_ARGS, 
                                                               gdt::GDT_CB_ARGS_SRVC_MSG);
    gdt::ServiceMsgManager* gdtsmm = smsg->get_smsg_manager();
    auto dd = static_cast<SysagentdDescriptor*>(mink::CURRENT_DAEMON);
    gdt::GDTStream* gdt_stream = args->get<gdt::GDTStream>(gdt::GDT_CB_INPUT_ARGS, 
                                                           gdt::GDT_CB_ARG_STREAM);
    // look for missing params
    if (smsg->missing_params) {
        // TODO stats
        std::cout << "MISSING" << std::endl;
        return;
    }

    // look for incomplete msg
    if (!smsg->is_complete()) {
        // TODO stats
        std::cout << "INCOMPLETE" << std::endl;
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

    // look for source type
    const mink_utils::VariantParam *vp_src_type = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_type);
    if (vp_src_type == nullptr) return;

    // look for source id
    const mink_utils::VariantParam *vp_src_id = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_id);
    if (vp_src_id == nullptr) return;

    // look for guid
    const mink_utils::VariantParam *vp_guid = smsg->vpget(asn1::ParameterType::_pt_mink_guid);
    if(!vp_guid) return;

    // look for cmd id
    const mink_utils::VariantParam *vp_cmd_id = smsg->vpget(asn1::ParameterType::_pt_mink_command_id);
    if(!vp_cmd_id) return;

    // look for username
    const mink_utils::VariantParam *vp_usr = smsg->vpget(asn1::ParameterType::_pt_mink_auth_id);
    if(!vp_usr) return;

    // look for password hash
    const mink_utils::VariantParam *vp_pwd = smsg->vpget(asn1::ParameterType::_pt_mink_auth_password);
    if(!vp_pwd) return;

    // authenticate user
    std::string usr(static_cast<char *>(*vp_usr));
    std::string pwd(static_cast<char *>(*vp_pwd));
    // user credentials
    std::tuple<bool, int, int> c{false, -1, 0};
    try {
        c = dd->dbm.user_auth(usr, pwd);
        if (!std::get<0>(c)) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                     "invalid credentials = [%s]",
                                      usr.c_str());
            return;
        }

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                 "cannot authenticate user: [%s]",
                                  e.what());
        return;
    }
    // skip other validations for "special" users (flags > 0)
    if (std::get<2>(c) == 0) {
        // check if cmd id is valid for this user
        if (!dd->dbm.cmd_auth(static_cast<int>(*vp_cmd_id), usr)) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                     "invalid command id credentials");
            return;
        }

        // validate command specific methods
        if (!dd->dbm.cmd_specific_auth(smsg->vpmap, usr)) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                     "invalid command specific credentials");
            return;
        }
    }

    // save source daemon address 
    std::string src_type(static_cast<char *>(*vp_src_type));
    std::string src_id(static_cast<char *>(*vp_src_id));

    // set client if needed
    if (!dd->rtrd_gdtc || !dd->rtrd_gdtc->is_registered())
        dd->rtrd_gdtc = dd->gdts->get_registered_client("routingd");

    // - do not free current smsg (will be freed when sent in async_done
    // handler)
    // - pass flag skips checking for auto_free flag in
    // ServiceStreamHandlerDone,
    //   mandatory in this case
    gdt_stream->set_param(gdt::SMSG_PT_PASS, smsg);

    // run in separate thread
    std::thread exec_th([this,
                         dd,
                         gdtsmm,
                         smsg,
                         vp_cmd_id,
                         src_type,
                         src_id,
                         gdt_stream] {


        // run plugin
        if (dd->plg_mngr.run(static_cast<int>(*vp_cmd_id), smsg)){
            // return service message to pool
            smsg->get_smsg_manager()->free_smsg(smsg);
            return;
        }

        // set source daemon
        smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_type, dd->get_daemon_type());
        smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_id, dd->get_daemon_id());
     
        // extra params
        using spmap_t = std::vector<gdt::ServiceParam*>;
        gdt::GDTCallbackMethod *ev_usr_cb = nullptr;
        spmap_t *pmap = nullptr;
        // get callback and smsg map
        const mink_utils::VariantParam *vp_cb = smsg->vpmap.get_param(0);
        const mink_utils::VariantParam *vp_pmap = smsg->vpmap.get_param(1);
        // check pointers
        if (vp_cb) ev_usr_cb = static_cast<gdt::GDTCallbackMethod *>((void *)*vp_cb);
        if (vp_pmap) pmap = static_cast<spmap_t *>((void *)*vp_pmap);

        // sync vpmap
        if (gdtsmm->vpmap_sparam_sync(smsg, pmap) == 0) {
            // set extra params
            smsg->params.set_param(3, ev_usr_cb);
            // send
            int res = gdtsmm->send(smsg,
                                   dd->rtrd_gdtc,
                                   src_type.c_str(),
                                   src_id.c_str(),
                                   true,
                                   &srvc_msg_sent);
            if(res){
                // error
                // TODO stats
                // return service message to pool
                smsg->get_smsg_manager()->free_smsg(smsg);
                // free user cb
                delete ev_usr_cb;
            }

        } else {
            // error
            // TODO STATS
            // return service message to pool
            smsg->get_smsg_manager()->free_smsg(smsg);
            // free user cb
            delete ev_usr_cb;
        }
    });
    // detach thread
    exec_th.detach();
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
    using namespace gdt;
    // get service message
    ServiceMessage *smsg = args->get<ServiceMessage>(GDT_CB_INPUT_ARGS, 
                                                     GDT_CB_ARGS_SRVC_MSG);
    // get extra user callback and free it
    auto usr_cb = static_cast<GDTCallbackMethod *>(smsg->params.get_param(3));
    delete usr_cb;

    // return service message to pool
    smsg->get_smsg_manager()->free_smsg(smsg);
}

void EVSrvcMsgErr::run(gdt::GDTCallbackArgs *args){
    // reserved
}
