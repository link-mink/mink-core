/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <gdt_reg_events.h>


void gdt::RegClientStreamDone::run(gdt::GDTCallbackArgs* args){
    asn1::GDTMessage* in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                gdt::GDT_CB_ARG_IN_MSG);
    gdt::GDTStream* stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                            gdt::GDT_CB_ARG_STREAM);
    gdt::GDTClient* client = stream->get_client();
    GDTSession* gdts = client->get_session();
    // timeout is in_msg is NULL
    if(in_msg == NULL) snew->status = -1;

    // set registration flag
    if(snew->status == 0) client->set_reg_flag(true);
    else client->disconnect();

    // run event if client registered
    if(client->is_registered()){
        // add client to routing method
        if(gdts->get_routing_handler() != NULL){
            gdts->lock_clients();
            gdts->get_routing_handler()->update_client(client,
                                                       client->get_end_point_daemon_type(),
                                                       client->get_end_point_daemon_id());
            gdts->unlock_clients();

        }

        // remove new stream event for current client
        client->remove_callback(gdt::GDT_ET_STREAM_NEW);

        // process callback
        GDTCallbackArgs cb_args;
        cb_args.clear_all_args();
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, client);
        gdts->process_callback(GDT_ET_CLIENT_CREATED, &cb_args);
        gdts->process_callback(GDT_ET_CLIENT_NEW, &cb_args);

    }
    snew->done_signal.set(true);

}



gdt::RegClientStreamNew::RegClientStreamNew(GDTClient* _client){
    client = _client;
    sdone = NULL;
    status = 1;

}

gdt::RegClientStreamNew::~RegClientStreamNew(){

}


void gdt::RegClientStreamNew::run(gdt::GDTCallbackArgs* args){
    gdt::GDTStream* stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                            gdt::GDT_CB_ARG_STREAM);
    gdt::GDTClient* client = stream->get_client();
    asn1::GDTMessage* gdtm = stream->get_gdt_message();
    bool* include_body = (bool*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                              gdt::GDT_CB_ARG_BODY);
    asn1::GDTMessage* in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                gdt::GDT_CB_ARG_IN_MSG);
    uint64_t* in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                 gdt::GDT_CB_ARG_IN_MSG_ID);
    char* tmp_val = NULL;
    int tmp_val_l = 0;
    std::string tmp_str;
    int c = 0;
    asn1::Parameters *p = NULL;
    asn1::RegistrationMessage *reg = NULL;

    // set end and timeout event handlers
    stream->set_callback(gdt::GDT_ET_STREAM_END, sdone);
    stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT, sdone);
    // remove new stream event, discard any new streams (unsafe flag is TRUE, mutex already locked)
    client->remove_callback(gdt::GDT_ET_STREAM_NEW, true);


    // check for body
    if(in_msg->_body == NULL) goto params_done;
    // check for config message
    if(!in_msg->_body->_reg->has_linked_data(*in_sess)) goto params_done;
    // reg msg pointer
    reg = in_msg->_body->_reg;
    // check for GET action
    if (reg->_reg_action->linked_node->tlv->value[0] !=
        asn1::RegistrationAction::_ra_reg_request)
        goto params_done;
    // check for params part
    if(reg->_params == NULL) goto params_done;
    // check params data
    if(!reg->_params->has_linked_data(*in_sess)) goto params_done;
    // params
    p = reg->_params;

    // process params
    for(unsigned int i = 0; i<p->children.size(); i++){
        // check for current session
        if(!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if(p->get_child(i)->_value == NULL) continue;
        // check if value exists in current session
        if(!p->get_child(i)->_value->has_linked_data(*in_sess)) continue;
        // check if child exists
        if(!p->get_child(i)->_value->get_child(0)) continue;
        // check if child exists in current sesion
        if(!p->get_child(i)->_value->get_child(0)->has_linked_data(*in_sess)) continue;
        // check param id, convert from big endian to host
        uint32_t* param_id = (uint32_t*)p->get_child(i)->_id->linked_node->tlv->value;
        // set tmp values
        tmp_val = (char*)p->get_child(i)->_value->get_child(0)->linked_node->tlv->value;
        tmp_val_l = p->get_child(i)->_value->get_child(0)->linked_node->tlv->value_length;
        // match param
        switch(be32toh(*param_id)){
            // daemon type
            case asn1::ParameterType::_pt_mink_daemon_type:
                tmp_str.clear();
                tmp_str.append(tmp_val, tmp_val_l);
                client->set_end_point_daemon_type(tmp_str.c_str());
                ++c;
                break;

                // daemon id
            case asn1::ParameterType::_pt_mink_daemon_id:
                tmp_str.clear();
                tmp_str.append(tmp_val, tmp_val_l);
                client->set_end_point_daemon_id(tmp_str.c_str());
                ++c;
                break;

                // router status
            case asn1::ParameterType::_pt_mink_router_status:
                client->set_router_flag(tmp_val[0] == 0 ? false : true);
                ++c;
                break;
        }
    }

params_done:
    // check if all mandatory params were received
    if(c >= 3) status = 0;//client->set_reg_flag(true);

    // prepare body
    if(gdtm->_body != NULL) {
        gdtm->_body->unlink(1);
        gdtm->_body->_conf->set_linked_data(1);

    }else{
        gdtm->set_body();
        gdtm->prepare();
    }
    // set bodu
    pm_dtype = htobe32(asn1::ParameterType::_pt_mink_daemon_type);
    pm_did = htobe32(asn1::ParameterType::_pt_mink_daemon_id);
    pm_router = htobe32(asn1::ParameterType::_pt_mink_router_status);
    reg_action = asn1::RegistrationAction::_ra_reg_result;
    router_flag = (client->get_session()->is_router() ? 1 : 0);
    // set params
    if(gdtm->_body->_reg->_params == NULL){
        gdtm->_body->_reg->set_params();
        // set children, allocate more
        for(int i = 0; i<3; i++){
            gdtm->_body->_reg->_params->set_child(i);
            gdtm->_body->_reg->_params->get_child(i)->set_value();
            gdtm->_body->_reg->_params->get_child(i)->_value->set_child(0);

        }
        // prepare
        gdtm->prepare();

        // unlink params before setting new ones
    }else{
        int cc = gdtm->_body->_reg->_params->children.size();
        if(cc < 3){
            // set children, allocate more
            for(int i = cc; i<3; i++){
                gdtm->_body->_reg->_params->set_child(i);
                gdtm->_body->_reg->_params->get_child(i)->set_value();
                gdtm->_body->_reg->_params->get_child(i)->_value->set_child(0);

            }
            // prepare
            gdtm->prepare();

        }else if(cc > 3){
            // remove extra children if used in some other session, only 2 needed
            for(int i = 3; i<cc; i++) gdtm->_body->_reg->_params->get_child(i)->unlink(1);
        }
    }

    // set reg action
    gdtm->_body->_reg->_reg_action->set_linked_data(1, (unsigned char*)&reg_action, 1);

    // set daemon type
    gdtm->_body
        ->_reg
        ->_params
        ->get_child(0)
        ->_id
        ->set_linked_data(1, (unsigned char*)&pm_dtype, sizeof(uint32_t));

    gdtm->_body
        ->_reg
        ->_params
        ->get_child(0)
        ->_value
        ->get_child(0)
        ->set_linked_data(1, 
                          (unsigned char*)client->get_session()->get_daemon_type(), 
                          strnlen(client->get_session()->get_daemon_type(), 49));

    // set daemon id
    gdtm->_body
        ->_reg
        ->_params
        ->get_child(1)
        ->_id
        ->set_linked_data(1, (unsigned char*)&pm_did, sizeof(uint32_t));

    gdtm->_body
        ->_reg
        ->_params
        ->get_child(1)
        ->_value
        ->get_child(0)
        ->set_linked_data(1, 
                          (unsigned char*)client->get_session()->get_daemon_id(), 
                          strnlen(client->get_session()->get_daemon_id(), 49));

    // set router flag
    gdtm->_body
        ->_reg
        ->_params
        ->get_child(2)
        ->_id
        ->set_linked_data(1, (unsigned char*)&pm_router, sizeof(uint32_t));

    gdtm->_body
        ->_reg
        ->_params
        ->get_child(2)
        ->_value
        ->get_child(0)
        ->set_linked_data(1, (unsigned char*)&router_flag, 1);

    // include
    *include_body = true;

    // end stream
    stream->end_sequence();


}
