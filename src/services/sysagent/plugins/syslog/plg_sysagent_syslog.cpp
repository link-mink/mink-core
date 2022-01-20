/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "gdt_def.h"
#include "mink_err_codes.h"
#include "mink_utils.h"
#include <config.h>
#include <exception>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <string>
#include <thread>
#include <atomic>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <boost/asio.hpp>
#include <zlib.h>
#include <sysagent.h>

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_SYSLOG_START,
    gdt_grpc::CMD_SYSLOG_STOP,

    // end of list marker
    -1
};

/***********************/
/* GDT message sent cb */
/***********************/
class GdtLogSentCb: public gdt::GDTCallbackMethod {
public:
    void run(gdt::GDTCallbackArgs* args) override {
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
};


/**************************/
/* GDT push user callback */
/**************************/
class EVUserCB: public gdt::GDTCallbackMethod {
public:
    EVUserCB() = default;
    ~EVUserCB() = default;
    EVUserCB(const EVUserCB &o) = delete;
    EVUserCB &operator=(const EVUserCB &o) = delete;
    // buffer
    std::vector<char> buff;
    // param map for non-variant params
    std::vector<gdt::ServiceParam *> pmap;
};


// syslog thread "running"" flag
std::atomic_bool running;
// gdt log sent cb
GdtLogSentCb gdt_log_sent_cb;
// permanent stream guid
mink_utils::Guid guid;
int udp_port = -1;


/**********************/
/* zLib error handler */
/**********************/
static void handle_zlib_error(gdt::ServiceMsgManager *smsgm, 
                              gdt::ServiceMessage *smsg, 
                              EVUserCB *ev_usr_cb){

    smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR,
                         std::to_string(mink::error::EC_UNKNOWN).c_str());

    
}

/****************/
/* Push via GDT */
/****************/
static void gdt_push(const std::string data, 
                     gdt::ServiceMsgManager *smsgm, 
                     const std::string &d_type, 
                     const std::string &d_id,
                     const mink_utils::Guid &guid,
                     const bool last){

    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // local routing daemon pointer
    gdt::GDTClient *gdtc = nullptr;
    // get new router if connection broken
    if (!(dd->rtrd_gdtc && dd->rtrd_gdtc->is_registered()))
        dd->rtrd_gdtc = dd->gdts->get_registered_client("routingd");
    // local routing daemon pointer
    gdtc = dd->rtrd_gdtc;
    // null check
    if (!gdtc) return;

    // allocate new service message
    gdt::ServiceMessage *smsg = smsgm->new_smsg();
    // msg sanity check
    if (!smsg) return;

    // service id
    smsg->set_service_id(asn1::ServiceId::_sid_sysagent);

    // get sparam
    gdt::ServiceParam *sp = smsgm->get_param_factory()
                                 ->new_param(gdt::SPT_OCTETS);
    // null check 
    if(!sp){
        smsgm->free_smsg(smsg);
        return;
    }

    /************/
    /* compress */
    /************/
    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    size_t buff_sz = data.size();
    // input size
    zs.avail_in = buff_sz;
    // input data
    zs.next_in = (Bytef *)data.data();
    // async data buffer
    EVUserCB *ev_usr_cb = new EVUserCB();
    // attach to smsg
    smsg->params.set_param(3, ev_usr_cb);
    //output buffer size
    ev_usr_cb->buff.resize(zs.avail_in * 2);
    zs.avail_out = ev_usr_cb->buff.size();
    zs.next_out = (Bytef *)ev_usr_cb->buff.data();
    // init struct
    if(deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK){
        handle_zlib_error(smsgm, smsg, ev_usr_cb);
        return;
    }
    // compress data
    int zres = deflate(&zs, Z_FINISH);
    if(zres != Z_STREAM_END){
        handle_zlib_error(smsgm, smsg, ev_usr_cb);
        return;
    }

    // finish
    if(deflateEnd(&zs) != Z_OK){
        handle_zlib_error(smsgm, smsg, ev_usr_cb);
        return;
    }
    
    // set guid
    smsg->vpmap.set_octets(asn1::ParameterType::_pt_mink_guid, guid.data(), 16);
    // persistent guid
    if (!last) smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_persistent_correlation,
                                    std::to_string(1).c_str());

    // set source daemon type
    smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_type,
                         dd->get_daemon_type());
    // set source daemon id
    smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_id,
                         dd->get_daemon_id());

    // resize buffer
    ev_usr_cb->buff.resize(zs.total_out);
    // set sparam
    sp->set_data(ev_usr_cb->buff.data(), zs.total_out);
    sp->set_id(gdt_grpc::PT_SL_LOGLINE);
    sp->set_extra_type(0);
    ev_usr_cb->pmap.push_back(sp);

    // sync vpmap
    if (smsgm->vpmap_sparam_sync(smsg, &ev_usr_cb->pmap) != 0) {
        smsgm->free_smsg(smsg);
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "Cannot dispatch LOGLINE via GDT");
        delete ev_usr_cb;
        return;
    }


    // send service message
    int r = smsgm->send(smsg,
                        gdtc,
                        d_type.c_str(),
                        (!d_id.empty() ? d_id.c_str() : nullptr),
                        true,
                        &gdt_log_sent_cb);
    if (r) {
        smsgm->free_smsg(smsg);
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "Cannot dispatch LOGLINE via GDT");


        delete ev_usr_cb;
        return;
    }

}

/*****************/
/* Syslog thread */
/*****************/
static void thread_syslog(gdt::ServiceMsgManager *smsgm, 
                          const std::string src_dtype, 
                          const std::string src_did,
                          const mink_utils::VariantParam *vp_guid,
                          const int port){

    using boost::asio::ip::udp;

    // UDP socket and buffer
    char data[2048];
    mink_utils::Guid guid;
    guid.set(static_cast<uint8_t *>(*vp_guid));
    udp::endpoint endp;
    std::size_t l;
    boost::asio::io_context io_ctx;
    udp::socket s(io_ctx, udp::endpoint(udp::v4(), port));
   
    // start receiving syslog packets 
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED && running.load()) {
        try{
            l = s.receive_from(boost::asio::buffer(data, sizeof(data)), endp);
            data[l] = '\0';
            // push
            gdt_push(data, smsgm, src_dtype, src_did, guid, !running.load());

        }catch(std::exception &e){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                      "plg_syslog: [%s]",
                                      e.what());
        }
    }
    udp_port = -1;
}


/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    running.store(false);
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

static int vp_str_to_port(const mink_utils::VariantParam *vp){
    if (!vp) return -1;
    // port
    int port = -1;
    try {
        port = std::stoi(static_cast<char *>(*vp));

    } catch (std::exception &e) {
        return -1;
    }

    return port;
}


/*************************************/
/* Implementation of "start" command */
/*************************************/
static void impl_syslog_start(gdt::ServiceMessage *smsg){
    using boost::asio::ip::udp;
    using Vp = mink_utils::VariantParam;

    // look for source type
    const Vp *vp_src_type = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_type);
    if (vp_src_type == nullptr) return;

    // look for source id
    const Vp *vp_src_id = smsg->vpget(asn1::ParameterType::_pt_mink_daemon_id);
    if (vp_src_id == nullptr) return;

    // check for guid
    const Vp *vp_guid = smsg->vpget(asn1::ParameterType::_pt_mink_guid);
    if (vp_guid == nullptr) return;

    // port
    const Vp *vp_port = smsg->vpget(gdt_grpc::PT_SL_PORT);
    if (vp_port == nullptr) return;

    // save source daemon address
    std::string src_type(static_cast<char *>(*vp_src_type));
    std::string src_id(static_cast<char *>(*vp_src_id));

    // already running
    if (udp_port != -1) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_syslog: already running");
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR,
                             std::to_string(mink::error::EC_UNKNOWN).c_str());
        return;
    }

    // port
    int port = vp_str_to_port(vp_port);
    if (port == -1){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_syslog: invalid UDP port value");
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR,
                             std::to_string(mink::error::EC_UNKNOWN).c_str());
        return;

    }

    // check if already running
    if (running.load()) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_syslog: already running");
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR, 
                             std::to_string(mink::error::EC_UNKNOWN).c_str());
        return;
    }

    // setup listener thread
    try{
        udp_port = port;
        running.store(true);
        std::thread th(&thread_syslog, 
                       smsg->get_smsg_manager(), 
                       src_type, 
                       src_id, 
                       vp_guid,
                       port);
        th.detach();
        smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_persistent_correlation,
                             std::to_string(1).c_str());
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_STATUS, 
                             std::to_string(mink::error::EC_OK).c_str());

    }catch(std::exception &e){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                  "plg_syslog: [%s]",
                                  e.what());
    }
   
}

/************************************/
/* Implementation of "stop" command */
/************************************/
static void impl_syslog_stop(gdt::ServiceMessage *smsg){
    using boost::asio::ip::udp;
    using Vp = mink_utils::VariantParam;

    // port
    const Vp *vp_port = smsg->vpget(gdt_grpc::PT_SL_PORT);
    if (vp_port == nullptr) return;

    // port
    int port = vp_str_to_port(vp_port);
    if (port == -1 || port != udp_port){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_syslog: invalid UDP port value");
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR,
                             std::to_string(mink::error::EC_UNKNOWN).c_str());
        return;

    }

    running.store(false);
    boost::asio::io_context io_ctx;
    udp::socket s(io_ctx, udp::endpoint(udp::v4(), 0));
    std::string dummy_str("SYSLOG_END");
    auto endp = udp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 
                              udp_port);
    s.send_to(boost::asio::buffer(dummy_str), endp);

    smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_STATUS,
                         std::to_string(mink::error::EC_OK).c_str());
    smsg->vpmap.erase_param(asn1::ParameterType::_pt_mink_persistent_correlation);
}


/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm, 
                   mink_utils::PluginDescriptor *pd, 
                   int cmd_id,
                   void *data){

    if(!data) return 1;
    gdt::ServiceMessage *smsg = static_cast<gdt::ServiceMessage*>(data);

    // check command id
    switch (cmd_id) {
        case gdt_grpc::CMD_SYSLOG_START:
            impl_syslog_start(smsg);
            break;
        case gdt_grpc::CMD_SYSLOG_STOP:
            impl_syslog_stop(smsg);
            break;

        default:
            break;
    }
    return 0;
}


