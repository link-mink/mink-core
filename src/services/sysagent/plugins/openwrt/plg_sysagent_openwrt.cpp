/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "daemon.h"
#include <thread>
#include <future>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_err_codes.h>
#include <config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <json-c/json.h>
extern "C" {
    #include <libubus.h>
    #include <libubox/blobmsg.h>
    #include <libubox/blobmsg_json.h>
}
#include <boost/beast/core/detail/base64.hpp>
#include <zlib.h>

/*********/
/* types */
/*********/
using data_vec_t = std::vector<uint8_t>;
namespace base64 = boost::beast::detail::base64;

/********************/
/* fwd declarations */
/********************/
static std::string process_vparam_octets(const mink_utils::VariantParam *vp);
static void ubus_event_cb(ubus_request *req, int type, blob_attr *msg);

/***********************/
/* extra user callback */
/***********************/
class EVUserCB: public gdt::GDTCallbackMethod {
public:
    EVUserCB() = default;
    EVUserCB(const EVUserCB &o) = delete;
    EVUserCB &operator=(const EVUserCB &o) = delete;

    ~EVUserCB() override{
        free(buff);
    }

    // param map for non-variant params
    std::vector<gdt::ServiceParam*> pmap;
    // ubus reply buffer
    char *buff = nullptr;
};

/***********************/
/* ubus invoke context */
/***********************/
typedef struct ubus_invoke_ctx {
    blob_buf msg;
    gdt::ServiceMessage *smsg;
    EVUserCB *ev_usr_cb;
} ubus_invoke_ctx_t;

/****************************/
/* ubus request correlation */
/****************************/
class ubus_correlation {
public:
    ubus_correlation() = default;
    ubus_correlation(gdt::ServiceMessage *_smsg) : smsg(_smsg) {}
    ubus_correlation(const ubus_correlation &o) = delete;
    ubus_correlation(ubus_correlation &&o)
        : ready(std::move(o.ready))
        , smsg(o.smsg) {}

    std::promise<gdt::ServiceMessage *> ready;
    gdt::ServiceMessage *smsg;
};


/************************/
/* ubus thread (queued) */
/************************/
class UbusHandler {
public:
    UbusHandler(){
        connect();
    }
    void run() {
        while (!mink::DaemonDescriptor::DAEMON_TERMINATED) {
            std::unique_lock<std::mutex> l(mtx_);
            if (!q_.empty()) {
                auto &d = q_.front();
                process(d);
                // unlock to allow queuing while processing
                d.ready.set_value(d.smsg);
                l.unlock();
                // pop
                l.lock();
                q_.pop_front();
                l.unlock();
                // next
                continue;
            }
            l.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    std::future<gdt::ServiceMessage *> add(ubus_correlation &d){
        std::unique_lock<std::mutex> l(mtx_);
        q_.push_back(std::move(d));
        return q_.back().ready.get_future();
    }

    void set_error(gdt::ServiceMessage *smsg, int ec) {
        using namespace gdt_grpc;
        smsg->vpmap.erase_param(PT_OWRT_UBUS_METHOD);
        smsg->vpmap.erase_param(PT_OWRT_UBUS_ARG);
        smsg->vpmap.erase_param(PT_OWRT_UBUS_PATH);
        smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_error,
                             std::to_string(ec).c_str());
    }

    void process(ubus_correlation &d){
        using namespace gdt_grpc;
        using Vp = mink_utils::VariantParam;

        // smsg pointer
        auto smsg = d.smsg;

        // ubus path (mandatory)
        const Vp *vp_path = smsg->vpget(PT_OWRT_UBUS_PATH);
        if (!vp_path)
            return;

        // reconnect if needed
        if(!ctx) connect();
        if(!ctx){
            set_error(smsg, mink::error::EC_UNKNOWN);
            return;
        }

        // verify path
        uint32_t id = 0;
        if (ubus_lookup_id(ctx, static_cast<char *>(*vp_path), &id)) {
            set_error(smsg, mink::error::EC_UNKNOWN);
            return;
        }
        // ubus method (mandatory)
        const Vp *vp_method = smsg->vpget(PT_OWRT_UBUS_METHOD);
        if (!vp_method) {
            set_error(smsg, mink::error::EC_UNKNOWN);
            return;
        }

        // method arg (optional)
        const Vp *vp_arg = smsg->vpget(PT_OWRT_UBUS_ARG);
        json_object *jo = nullptr;
        json_tokener* j_tknr = nullptr;
        if(vp_arg){
            // extract data
            std::string data;
            try {
                data = process_vparam_octets(vp_arg);

            } catch (std::exception &e) {
                set_error(smsg, mink::error::EC_UNKNOWN);
                return;
            }
            // verify json
            j_tknr = json_tokener_new();
            jo = json_tokener_parse_ex(j_tknr, data.c_str(), data.size());
            if (!(jo && json_object_get_type(jo) == json_type_object)) {
                json_tokener_free(j_tknr);
                set_error(smsg, mink::error::EC_UNKNOWN);
                return;
            }
        }else{
            jo = json_object_new_object();
        }

        int uc_tmt = 2000;
        // timeout (optional)
        const Vp *vp_tmt = smsg->vpget(asn1::ParameterType::_pt_mink_timeout);
        if (vp_tmt) uc_tmt = static_cast<int>(*vp_tmt);

        // create ubus invoke context
        auto ic = new ubus_invoke_ctx_t();
        ic->smsg = smsg;
        ic->ev_usr_cb = new EVUserCB();
        blob_buf_init(&ic->msg, 0);
        blobmsg_add_object(&ic->msg, jo);
        // invoke ubus command
        int r = ubus_invoke(ctx,
                            id,
                            static_cast<char*>(*vp_method),
                            ic->msg.head,
                            &ubus_event_cb,
                            ic,
                            uc_tmt);
        // invoke failed
        if(r){
            set_error(ic->smsg, mink::error::EC_UNKNOWN);
            // cleanup
            blob_buf_free(&ic->msg);
            delete ic->ev_usr_cb;
            delete ic;
        }

        // free
        json_object_put(jo);
        if (j_tknr) json_tokener_free(j_tknr);
    }

    void free_ctx() {
        if (ctx) ubus_free(ctx);
        ctx = nullptr;
    }

    ubus_context *connect(){
        ctx = ubus_connect(nullptr);
        return ctx;
    }

private:
    std::mutex mtx_;
    std::deque<ubus_correlation> q_;
    ubus_context *ctx = nullptr;
};

/****************/
/* ubus handler */
/****************/
UbusHandler uh;

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_UBUS_CALL,
    gdt_grpc::CMD_FIRMWARE_UPDATE,

    // end of list marker
    -1
};

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    std::thread th_ubus(&UbusHandler::run, &uh);
    th_ubus.detach();
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    //if(ctx) ubus_free(ctx);
    return 0;
}

static void set_ubus_error(gdt::ServiceMessage *smsg, int ec){
    using namespace gdt_grpc;
    smsg->vpmap.erase_param(PT_OWRT_UBUS_METHOD);
    smsg->vpmap.erase_param(PT_OWRT_UBUS_ARG);
    smsg->vpmap.erase_param(PT_OWRT_UBUS_PATH);
    smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_error,
                         std::to_string(ec).c_str());

}

static std::string process_vparam_octets(const mink_utils::VariantParam *vp){
    // sanity check (nullptr)
    if (!vp)
        throw std::invalid_argument("VariantParam = nullptr");

    // output string
    std::string res;

    // DPT_POINTER type (DPT_OCTETS)
    if (vp->get_type() == mink_utils::DPT_POINTER) {
        try {
            auto data = static_cast<data_vec_t *>((void *)*vp);
            res.assign(reinterpret_cast<char *>(data->data()), data->size());
            // free vector buffer used for fragmentation
            delete data;

        } catch (std::exception &e) {
            throw std::invalid_argument(
                "error while processing VariantParam DPT_OCTETS data");
        }
    // DPT_STRING (small unfragmented)
    } else if (vp->get_type() == mink_utils::DPT_STRING) {
        try {
            res.assign(static_cast<char *>((char *)*vp));
        } catch (std::exception &e) {
            throw std::invalid_argument(
                "error while processing VariantParam DPT_STRING data");
        }

    } else
        throw std::invalid_argument("VariantParam type not supported");


    // return string
    return res;
}


// Implementation of "ubus_call" command
static void impl_ubus_call(gdt::ServiceMessage *smsg){
    ubus_correlation uc{smsg};
    auto f = uh.add(uc);
    gdt::ServiceMessage *s = f.get();
    // sanity check
    if(s != smsg){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "potential memory corruption (smsg != s)");
        exit(EXIT_FAILURE);
    }
}

static void ubus_event_cb(ubus_request *req, int type, blob_attr *msg){
    using namespace gdt_grpc;
    // get context
    auto ic = static_cast<ubus_invoke_ctx_t*>(req->priv);
    // erase request params
    ic->smsg->vpmap.erase_param(PT_OWRT_UBUS_METHOD);
    ic->smsg->vpmap.erase_param(PT_OWRT_UBUS_ARG);
    ic->smsg->vpmap.erase_param(PT_OWRT_UBUS_PATH);

    // nullptr check
    if (!msg) {
        set_ubus_error(ic->smsg, mink::error::EC_UNKNOWN);
        //cleanup
        blob_buf_free(&ic->msg);
        delete ic->ev_usr_cb;
        delete ic;
        return;
    }
    // extract json data
    ic->ev_usr_cb->buff = blobmsg_format_json(msg, true);
    // nullptr check
    if (!ic->ev_usr_cb->buff){
        set_ubus_error(ic->smsg, mink::error::EC_UNKNOWN);
        // cleanup
        blob_buf_free(&ic->msg);
        delete ic->ev_usr_cb;
        delete ic;
        return;
    }

    // prepare ubus result
    gdt::ServiceMessage *smsg = ic->smsg;
    std::vector<gdt::ServiceParam*> *pmap = &ic->ev_usr_cb->pmap;
    gdt::ServiceParam *sp = smsg->get_smsg_manager()
                                ->get_param_factory()
                                ->new_param(gdt::SPT_OCTETS);
    if(sp){
        // compress
        z_stream zs;
        zs.zalloc = Z_NULL;
        zs.zfree = Z_NULL;
        zs.opaque = Z_NULL;
        // input size
        zs.avail_in = strlen(ic->ev_usr_cb->buff);
        // input data
        zs.next_in = (Bytef *)ic->ev_usr_cb->buff;
        //output buffer size
        char z_out_buff[zs.avail_in * 2];
        zs.avail_out = sizeof(z_out_buff);
        zs.next_out = (Bytef *)z_out_buff;
        // init struct
        if(deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK){
            set_ubus_error(ic->smsg, mink::error::EC_UNKNOWN);
            // cleanup
            blob_buf_free(&ic->msg);
            delete ic->ev_usr_cb;
            delete ic;
            return;
        }
        // compress data
        int zres = deflate(&zs, Z_FINISH);
        if(zres != Z_STREAM_END){
            set_ubus_error(ic->smsg, mink::error::EC_UNKNOWN);
            // cleanup
            blob_buf_free(&ic->msg);
            delete ic->ev_usr_cb;
            delete ic;
            return;

        }
        // finish
        if(deflateEnd(&zs) != Z_OK){
            set_ubus_error(ic->smsg, mink::error::EC_UNKNOWN);
            // cleanup
            blob_buf_free(&ic->msg);
            delete ic->ev_usr_cb;
            delete ic;
            return;
        }
       
        // switch buffers 
        memcpy(ic->ev_usr_cb->buff, z_out_buff, zs.total_out);
        sp->set_data(ic->ev_usr_cb->buff, zs.total_out);
        sp->set_id(PT_OWRT_UBUS_RESULT);
        sp->set_extra_type(0);
        pmap->push_back(sp);
    }
    smsg->vpmap.set_pointer(0, ic->ev_usr_cb);
    smsg->vpmap.set_pointer(1, pmap);
    // cleanup
    blob_buf_free(&ic->msg);
    delete ic;
}

// Implementation of "firmware_update" command
static void impl_firmware_update(gdt::ServiceMessage *smsg){
    using namespace gdt_grpc;

    // firmware data (base64)
    const mink_utils::VariantParam *vp_fwd = smsg->vpget(PT_FU_DATA);
    if(!vp_fwd) return;

    // extract data
    std::string data;
    try {
        data = process_vparam_octets(vp_fwd);
        // create file for writing (fixed filename for security reasons)
        FILE *f = fopen("/tmp/firmware.img", "a+");
        if (!f)
            throw std::invalid_argument("error file creating file");

        // decode and write data
        const std::size_t sz = base64::decoded_size(data.size());
        std::vector<char> arr(sz);
        auto res = base64::decode(arr.data(), data.data(), data.size());
        if (fwrite(arr.data(), res.first, 1, f) != 1)
            throw std::invalid_argument("size mismatch while writing file");
        fclose(f);

    } catch (std::exception &e) {
        std::cout << e.what() << std::endl;
        set_ubus_error(smsg, mink::error::EC_UNKNOWN);
        return;
    }
    smsg->vpmap.erase_param(PT_FU_DATA);

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
        case gdt_grpc::CMD_UBUS_CALL:
            impl_ubus_call(smsg);
            break;

        case gdt_grpc::CMD_FIRMWARE_UPDATE:
            impl_firmware_update(smsg);
            break;

        default:
            break;
    }
    return 0;
}


