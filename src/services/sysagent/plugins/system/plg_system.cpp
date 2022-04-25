/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <atomic>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/process.hpp>
#include <boost/asio/io_service.hpp>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <json_rpc.h>
#include <mutex>
#include <proc/readproc.h>
#include <mink_pkg_config.h>
#include <utility>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include "mink_err_codes.h"
#include <boost/asio.hpp>
#include <zlib.h>
#include <sysagent.h>

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_GET_PROCESS_LST,
    gdt_grpc::CMD_SHELL_EXEC,
    gdt_grpc::CMD_SOCKET_PROXY,
    gdt_grpc::CMD_REMOTE_EXEC_START,
    gdt_grpc::CMD_REMOTE_EXEC_STOP,
    gdt_grpc::CMD_NET_TCP_SEND,
    // end of list marker
    -1
};

/***********/
/* Aliases */
/***********/
using NetSendData = std::vector<std::string>;
using ProcLst = std::vector<std::tuple<std::string, std::string, int, int>>;

/***********************/
/* extra user callback */
/***********************/
class EVUserCB: public gdt::GDTCallbackMethod {
public:
    EVUserCB() = default;
    EVUserCB(const EVUserCB &o) = delete;
    EVUserCB &operator=(const EVUserCB &o) = delete;

    // param map for non-variant params
    std::vector<gdt::ServiceParam*> pmap;
    std::string buff;
};

/*************************************/
/* GDT push user callbacki (cmd res) */
/*************************************/
class CmdResEVUserCB: public gdt::GDTCallbackMethod {
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

/***************************/
/* Remote CMD related vars */
/***************************/
// port list
std::map<int, std::atomic_bool> ports;
// lock
std::mutex mtx_ports;
// gdt log sent cb
CmdResEVUserCB cmd_res_sent_cb;

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

static void impl_processlst(gdt::ServiceMessage *smsg){
    PROCTAB *proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);

    proc_t proc_info;
    memset(&proc_info, 0, sizeof(proc_info));
    int i = 0;
    using namespace gdt_grpc;
    while (readproc(proc, &proc_info) != nullptr) {
        smsg->vpset(PT_PL_CMD, proc_info.cmd, i);
        smsg->vpset(PT_PL_TID, std::to_string(proc_info.tid), i);
        smsg->vpset(PT_PL_PPID, std::to_string(proc_info.ppid), i);
        smsg->vpset(PT_PL_RESIDENT, std::to_string(proc_info.resident), i);
        smsg->vpset(PT_PL_UTIME, std::to_string(proc_info.utime), i);
        smsg->vpset(PT_PL_STIME, std::to_string(proc_info.stime), i);
        ++i;
    }

    closeproc(proc);

}

static void impl_processlst_lcl(ProcLst *d_out){
    PROCTAB *proc = openproc(PROC_FILLSTAT | PROC_FILLCOM);
    while (proc_t *pi = readproc(proc, nullptr)) {
        std::string cmdl("");
        char **cmdline = pi->cmdline;
        while (cmdline && *cmdline) {
            cmdl.append(*cmdline);
            cmdl += " ";
            ++cmdline;
        }
        d_out->push_back(std::make_tuple(pi->cmd,
                                         cmdl,
                                         pi->ppid,
                                         pi->tid));
        freeproc(pi);
    }

    closeproc(proc);

}


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
    // output buffer size
    ev_usr_cb->buff.resize(zs.avail_in * 2 + 8);
    zs.avail_out = ev_usr_cb->buff.size();
    zs.next_out = (Bytef *)ev_usr_cb->buff.data();
    // init struct
    if(deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK){
        handle_zlib_error(smsgm, smsg, ev_usr_cb);
        deflateEnd(&zs);
        delete ev_usr_cb;
        smsgm->free_smsg(smsg);
        return;
    }
    // compress data
    int zres = deflate(&zs, Z_FINISH);
    if(zres != Z_STREAM_END){
        handle_zlib_error(smsgm, smsg, ev_usr_cb);
        deflateEnd(&zs);
        delete ev_usr_cb;
        smsgm->free_smsg(smsg);
        return;
    }

    // finish
    if(deflateEnd(&zs) != Z_OK){
        handle_zlib_error(smsgm, smsg, ev_usr_cb);
        delete ev_usr_cb;
        smsgm->free_smsg(smsg);
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
                                  "Cannot dispatch CMDLINE via GDT");
        delete ev_usr_cb;
        return;
    }


    // send service message
    int r = smsgm->send(smsg,
                        gdtc,
                        d_type.c_str(),
                        (!d_id.empty() ? d_id.c_str() : nullptr),
                        true,
                        &cmd_res_sent_cb);
    if (r) {
        smsgm->free_smsg(smsg);
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "Cannot dispatch CMDLINE via GDT");


        delete ev_usr_cb;
        return;
    }

}


/*****************/
/* Syslog thread */
/*****************/
static void thread_cmd_rx(gdt::ServiceMsgManager *smsgm,
                          const std::string src_dtype,
                          const std::string src_did,
                          const mink_utils::VariantParam *vp_guid,
                          const int port,
                          std::atomic_bool *is_running){

    using boost::asio::ip::udp;

    // UDP socket and buffer
    char data[65536];
    mink_utils::Guid guid;
    guid.set(static_cast<uint8_t *>(*vp_guid));
    udp::endpoint endp;
    std::size_t l;
    boost::asio::io_context io_ctx;
    udp::socket s(io_ctx, udp::endpoint(udp::v4(), port));

    // start receiving cmd result
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED && is_running->load()) {
        try{
            l = s.receive_from(boost::asio::buffer(data, sizeof(data) - 1), endp);
            data[l] = '\0';
            // push
            gdt_push(data, smsgm, src_dtype, src_did, guid, !is_running->load());

        }catch(std::exception &e){
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_system: [%s]",
                                      e.what());
        }
    }

    std::unique_lock<std::mutex> lock(mtx_ports);
    ports.erase(port);
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



/*****************************/
/* Remote exec START handler */
/*****************************/
static void impl_remote_exec_start(gdt::ServiceMessage *smsg){
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
    const Vp *vp_port = smsg->vpget(gdt_grpc::PT_RE_PORT);
    if (vp_port == nullptr) return;

    // save source daemon address
    std::string src_type(static_cast<char *>(*vp_src_type));
    std::string src_id(static_cast<char *>(*vp_src_id));

    // port
    int port = vp_str_to_port(vp_port);
    if (port == -1){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_system: invalid UDP port value");
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR,
                             std::to_string(mink::error::EC_UNKNOWN).c_str());
        return;
    }

    // check if already running
    std::unique_lock<std::mutex> lock(mtx_ports);
    const auto it = ports.find(port);
    if(it != ports.cend()){
        lock.unlock();
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_system: port [%d] already used",
                                   port);
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR,
                             std::to_string(mink::error::EC_UNKNOWN).c_str());

        return;
    }

    // add to list of ports
    ports[port] = false;
    // get atomic bool ref
    std::atomic_bool *rf = &ports.at(port);
    // unlock
    lock.unlock();

    // setup listener thread
    try{
        rf->store(true);
        std::thread th(&thread_cmd_rx,
                       smsg->get_smsg_manager(),
                       src_type,
                       src_id,
                       vp_guid,
                       port,
                       rf);
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

/****************************/
/* Remote exec STOP handler */
/****************************/
static void impl_remote_exec_stop(gdt::ServiceMessage *smsg){
    using boost::asio::ip::udp;
    using Vp = mink_utils::VariantParam;

    // port
    const Vp *vp_port = smsg->vpget(gdt_grpc::PT_RE_PORT);
    if (vp_port == nullptr) return;

    // port
    int port = vp_str_to_port(vp_port);
    // find port
    std::unique_lock<std::mutex> lock(mtx_ports);
    auto it = ports.find(port);
    if (port == -1 || it == ports.end()){
        lock.unlock();
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_syslog: invalid UDP port value");
        smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_ERROR,
                             std::to_string(mink::error::EC_UNKNOWN).c_str());
        return;
    }
    lock.unlock();

    // stop thread (send dummy data)
    it->second.store(false);
    boost::asio::io_context io_ctx;
    udp::socket s(io_ctx, udp::endpoint(udp::v4(), 0));
    std::string dummy_str("CMD_END");
    auto endp = udp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"),
                              port);
    s.send_to(boost::asio::buffer(dummy_str), endp);
    smsg->vpmap.set_cstr(gdt_grpc::PT_MINK_STATUS,
                         std::to_string(mink::error::EC_OK).c_str());
    smsg->vpmap.erase_param(asn1::ParameterType::_pt_mink_persistent_correlation);


}

// shell exec using Boost.Process
static void impl_shell_exec(gdt::ServiceMessage *smsg){
    namespace bp = boost::process;
    using namespace gdt_grpc;

    // shell command
    const mink_utils::VariantParam *vp_cmd = smsg->vpget(PT_SHELL_CMD);
    if(!vp_cmd) return;

    // cmd
    std::string cmd(static_cast<char*>(*vp_cmd));
    // create future
    std::future<std::vector<char>> cmd_out;
    try{
        // SIGPIPE ignore
        struct sigaction sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, nullptr);

        boost::asio::io_service ios;
        // start child process
        bp::child c(cmd,
                    bp::std_in.close(),
                    bp::std_out > cmd_out,
                    ios);
        // run
        ios.run_for(std::chrono::seconds(2));
        c.terminate();
        c.wait();

        // get output
        auto st = cmd_out.wait_for(std::chrono::milliseconds(1));
        if (st != std::future_status::ready) {
            return;
        }
        // assign data
        auto cb = new EVUserCB();
        auto o = cmd_out.get();
        cb->buff.assign(o.data(), o.size());

        // push via GDT
        gdt::ServiceParam *sp = smsg->get_smsg_manager()
                                    ->get_param_factory()
                                    ->new_param(gdt::SPT_OCTETS);
        if(sp){
            sp->set_data(cb->buff.data(), cb->buff.size() - 1);
            sp->set_id(PT_SHELL_STDOUT);
            sp->set_extra_type(0);
            cb->pmap.push_back(sp);
        }
        smsg->vpmap.set_pointer(0, cb);
        smsg->vpmap.set_pointer(1, &cb->pmap);
        smsg->vpmap.erase_param(PT_SHELL_CMD);

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_syslog: [%s]",
                                  e.what());
    }
}

static void impl_socket_proxy(gdt::ServiceMessage *smsg){
#if defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
    using namespace gdt_grpc;
    using json = nlohmann::basic_json<nlohmann::ordered_map>;
    namespace asio = boost::asio;
    // socket type
    const mink_utils::VariantParam *vp_spt = smsg->vpget(PT_SP_TYPE);
    if(!vp_spt) return;

    // socket path (domain socket)
    const mink_utils::VariantParam *vp_spp = smsg->vpget(PT_SP_PATH);
    if(!vp_spp) return;

    // socket payload
    const mink_utils::VariantParam *vp_sp_pld = smsg->vpget(PT_SP_PAYLOAD);
    if(!vp_sp_pld) return;

    boost::system::error_code ec;
    try{
        // asio context and socket
        asio::io_context ioc;
        asio::local::stream_protocol::socket s(ioc);
        // connect and set to non blocking
        asio::local::stream_protocol::endpoint ep(static_cast<char *>(*vp_spp));
        s.connect(ep);
        s.non_blocking(true);
        // get embedded data and size
        const char *data = static_cast<const char *>(*vp_sp_pld);
        std::string dt(data, vp_sp_pld->get_size());
        // parse data (verify)
        json jdata = json::parse(dt, nullptr, false);
        if (jdata.is_discarded())
            throw std::invalid_argument("malformed PT_SP_PAYLOAD JSON data");

        // write to socket
        std::size_t bc = 0;
        while(bc == 0) {
            try {
                bc = asio::write(s, asio::buffer(jdata.dump()));
            } catch (boost::system::system_error &e) {
                if (e.code() != asio::error::try_again)
                    throw std::invalid_argument("unknown error");
            }
        }

        // create 8Kb reply buffer
        std::array<char, 8192> buff;
        // json data
        std::string recv_json;
        asio::mutable_buffer mb = asio::buffer(buff.data(), buff.size());
        // read data
        bc = 0;
        while (bc == 0) {
            try {
                bc = s.receive(mb);
                recv_json.append(asio::buffer_cast<char *>(mb));
            } catch (boost::system::system_error &e) {
                if (e.code() != asio::error::try_again)
                    throw std::invalid_argument("unknown error");
            }
        }

        auto cb = new EVUserCB();
        cb->buff.assign(recv_json);

        // push via GDT
        gdt::ServiceParam *sp = smsg->get_smsg_manager()
                                    ->get_param_factory()
                                    ->new_param(gdt::SPT_OCTETS);
        if(sp){
            sp->set_data(cb->buff.data(), cb->buff.size());
            sp->set_id(PT_SP_PAYLOAD);
            sp->set_extra_type(0);
            cb->pmap.push_back(sp);
        }
        smsg->vpmap.set_pointer(0, cb);
        smsg->vpmap.set_pointer(1, &cb->pmap);
        smsg->vpmap.erase_param(PT_SP_TYPE);
        smsg->vpmap.erase_param(PT_SP_PATH);
        smsg->vpmap.erase_param(PT_SP_PAYLOAD);

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_syslog: [%s]",
                                  e.what());
    }

#else // defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
// unsupported
#endif // defined(BOOST_ASIO_HAS_LOCAL_SOCKETS
}

static void impl_tcp_send(NetSendData *data) {
    using boost::asio::ip::tcp;
    namespace asio = boost::asio;
    // sanity check
    if(!data || data->size() != 3){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                 "plg_syslog: [CMD_NET_TCP_SEND invalid data]");
        return;
    }

    try {
        asio::io_context io_ctx;
        tcp::socket s(io_ctx);
        tcp::resolver r(io_ctx);
        asio::connect(s, r.resolve(data->at(0), data->at(1)));

        // write
        boost::asio::write(s, boost::asio::buffer(data->at(2)));

        // close
        s.close();

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_syslog: [%s]",
                                  e.what());
    }
}
static void impl_tcp_send(mink_utils::Plugin_data_std *data) {
    using boost::asio::ip::tcp;
    namespace asio = boost::asio;
    // sanity check
    if(!data || data->size() != 3){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                 "plg_syslog: [CMD_NET_TCP_SEND invalid data]");
        return;
    }

    try {
        asio::io_context io_ctx;
        tcp::socket s(io_ctx);
        tcp::resolver r(io_ctx);
        asio::connect(s, r.resolve(data->at(0).cbegin()->second,
                                   data->at(1).cbegin()->second));

        // write
        boost::asio::write(s,
                           boost::asio::buffer(data->at(2).cbegin()->second));

        // close
        s.close();

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_syslog: [%s]",
                                  e.what());
    }

}

/*************************/
/* local command handler */
/*************************/
extern "C" int run_local(mink_utils::PluginManager *pm,
                         mink_utils::PluginDescriptor *pd,
                         int cmd_id,
                         mink_utils::PluginInputData &p_id){
    // sanity/type check
    if (!p_id.data())
        return -1;

    // UNIX socket local interface
    if(p_id.type() == mink_utils::PLG_DT_JSON_RPC){
        // TODO
        return 0;
    }

    // plugin2plugin local interface (custom)
    if(p_id.type() == mink_utils::PLG_DT_SPECIFIC){
        // check command id
        switch(cmd_id){
            case gdt_grpc::CMD_NET_TCP_SEND:
                impl_tcp_send(static_cast<NetSendData *>(p_id.data()));
                break;

            case gdt_grpc::CMD_GET_PROCESS_LST:
                impl_processlst_lcl(static_cast<ProcLst*>(p_id.data()));
                break;


            default:
                break;
        }
        return 0;
    }

    // plugin2plugin local interface (standard)
    if (p_id.type() == mink_utils::PLG_DT_STANDARD) {
        // plugin in/out data
        auto *plg_d = static_cast<mink_utils::Plugin_data_std *>(p_id.data());
        // check command id
        switch(cmd_id){
            case gdt_grpc::CMD_NET_TCP_SEND:
                impl_tcp_send(plg_d);
                break;

            default:
                break;
        }
        return 0;
    }

    // unknown interface
    return -1;

}


/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm,
                   mink_utils::PluginDescriptor *pd,
                   int cmd_id,
                   mink_utils::PluginInputData &p_id){

    // sanity/type check
    if (!(p_id.data() && p_id.type() == mink_utils::PLG_DT_GDT))
        return 1;

    // get GDT smsg
    auto smsg = static_cast<gdt::ServiceMessage*>(p_id.data());

    // check command id
    switch (cmd_id) {
        case gdt_grpc::CMD_GET_PROCESS_LST:
            impl_processlst(smsg);
            break;

        case gdt_grpc::CMD_SHELL_EXEC:
            impl_shell_exec(smsg);
            break;

        case gdt_grpc::CMD_SOCKET_PROXY:
            impl_socket_proxy(smsg);
            break;

        case gdt_grpc::CMD_REMOTE_EXEC_START:
            impl_remote_exec_start(smsg);
            break;

        case gdt_grpc::CMD_REMOTE_EXEC_STOP:
            impl_remote_exec_stop(smsg);
            break;

        default:
            break;
    }
    return 0;
}


