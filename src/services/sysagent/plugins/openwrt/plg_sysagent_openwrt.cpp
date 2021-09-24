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

#include <mink_plugin.h>
#include <gdt_utils.h>
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

/***********************/
/* extra user callback */
/***********************/
class EVUserCB: public gdt::GDTCallbackMethod {
public:
    EVUserCB(){
        buff = NULL;
    }

    ~EVUserCB(){
        free(buff);
    }

    // param map for non-variant params
    std::vector<gdt::ServiceParam*> pmap;
    // ubus reply buffer
    char *buff;
};

/***********************/
/* ubus invoke context */
/***********************/
typedef struct ubus_invoke_ctx {
    blob_buf msg;
    gdt::ServiceMessage *smsg;
    EVUserCB *ev_usr_cb;
} ubus_invoke_ctx_t;

// ubus handlers
static ubus_context *ctx = NULL;
static ubus_event_handler ubus_evh;
static void ubus_event_cb(ubus_request *req, int type, blob_attr *msg);

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
int COMMANDS[] = {
    gdt_grpc::CMD_UBUS_CALL,

    // end of list marker
    -1
};

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    ctx = ubus_connect(NULL);
    if (!ctx) return 1;
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    if(ctx) ubus_free(ctx);
    return 0;
}


// Implementation of "ubus_call" command
static void impl_ubus_call(gdt::ServiceMessage *smsg){
    using namespace gdt_grpc; 

    // look for context
    if (!ctx) return;

    // ubus path (mandatory)
    mink_utils::VariantParam *vp_path = smsg->vpget(PT_OWRT_UBUS_PATH);
    if(!vp_path) return;
    // verify path
    uint32_t id = 0;
    if(ubus_lookup_id(ctx, static_cast<char*>(*vp_path), &id)) return;

    // ubus method (mandatory)
    mink_utils::VariantParam *vp_method = smsg->vpget(PT_OWRT_UBUS_METHOD);
    if(!vp_method) return;

    // method arg (optional)
    mink_utils::VariantParam *vp_arg = smsg->vpget(PT_OWRT_UBUS_ARG);
    json_object *jo = NULL;
    json_tokener* j_tknr = NULL;
    if(vp_arg){
        // extract data
        std::string data(static_cast<char*>(*vp_arg));
        // verify json
        j_tknr = json_tokener_new();
        jo = json_tokener_parse_ex(j_tknr, data.c_str(), data.size());
        if (!(jo && json_object_get_type(jo) == json_type_object)) {
            json_tokener_free(j_tknr);
            return;
        }
    }else{
        jo = json_object_new_object();
    }
    
    // create ubus invoke context
    ubus_invoke_ctx_t *ic = new ubus_invoke_ctx_t();
    ic->smsg = smsg;
    ic->ev_usr_cb = new EVUserCB();
    blob_buf_init(&ic->msg, 0);
    blobmsg_add_object(&ic->msg, jo);

    // invoke ubus command
    ubus_invoke(ctx, 
                id, 
                static_cast<char*>(*vp_method), 
                ic->msg.head, 
                &ubus_event_cb, 
                ic, 
                2000);
   
    // free json parser
    json_object_put(jo);
    if (j_tknr) json_tokener_free(j_tknr);
}

static void ubus_event_cb(ubus_request *req, int type, blob_attr *msg){
    using namespace gdt_grpc;
    if (!msg) return;
    // get context
    ubus_invoke_ctx_t *ic = static_cast<ubus_invoke_ctx_t*>(req->priv);
    // extract json data
    ic->ev_usr_cb->buff = blobmsg_format_json(msg, true);
    gdt::ServiceMessage *smsg = ic->smsg;
    //ic->smsg->vpset(PT_OWRT_UBUS_RESULT, s);
    std::vector<gdt::ServiceParam*> *pmap = &ic->ev_usr_cb->pmap;
    gdt::ServiceParam *sp = smsg->get_smsg_manager()
                                ->get_param_factory()
                                ->new_param(gdt::SPT_OCTETS);
    if(sp){
        sp->set_data(ic->ev_usr_cb->buff, strlen(ic->ev_usr_cb->buff));
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
        case gdt_grpc::CMD_UBUS_CALL:
            impl_ubus_call(smsg);
            break;

        default:
            break;
    }
    return 0;
}


