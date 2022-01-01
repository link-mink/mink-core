/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <boost/asio/local/stream_protocol.hpp>
#include <boost/process.hpp>
#include <boost/asio/io_service.hpp>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <json_rpc.h>
#include <proc/readproc.h>
#include <config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_GET_PROCESS_LST,
    gdt_grpc::CMD_SHELL_EXEC,
    gdt_grpc::CMD_SOCKET_PROXY,
    // end of list marker
    -1
};

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
        std::cout << e.what() << std::endl;
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
        std::cout << "ERROR: " << e.what() << std::endl;
    }

#else // defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
// unsupported
#endif // defined(BOOST_ASIO_HAS_LOCAL_SOCKETS
}

/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm, 
                   mink_utils::PluginDescriptor *pd, 
                   int cmd_id,
                   void *data){

    if(!data) return 1;
    auto smsg = static_cast<gdt::ServiceMessage*>(data);

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

        default:
            break;
    }
    return 0;
}


