/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <config_gdt.h>

void config::CfgUpdateClientTerm::run(gdt::GDTCallbackArgs* args){
    auto client = (gdt::GDTClient*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                 gdt::GDT_CB_ARG_CLIENT);
    gdt::GDTCallbackMethod* snew = client->get_callback(gdt::GDT_ET_STREAM_NEW, true);
    // delete stream new event
    if(snew != nullptr) delete snew;
    // deallocate current event
    delete this;
}

void config::CfgUpdateStreamNew::run(gdt::GDTCallbackArgs* args){
    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                 gdt::GDT_CB_ARG_STREAM);
    auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                   gdt::GDT_CB_ARG_IN_MSG);
    auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                            gdt::GDT_CB_ARG_IN_MSG_ID);
    char* tmp_val = nullptr;
    uint32_t* tmp_ivp;

    asn1::Parameters *p = nullptr;
    asn1::ConfigMessage *cfg = nullptr;

    // new stream next event
    auto snext = new CfgUpdateStreamNext();
    snext->sdone.snew = this;
    snext->sdone.snext = snext;
    // set events
    stream->set_callback(gdt::GDT_ET_STREAM_NEXT, snext);
    stream->set_callback(gdt::GDT_ET_STREAM_END, &snext->sdone);

    // check for body
    if(in_msg->_body == nullptr) return;
    // check for config message
    if(!in_msg->_body->_conf->has_linked_data(*in_sess)) {
        run_continue(args);
        return;
    }
    // reg msg pointer
    cfg = in_msg->_body->_conf;
    // check for GET action
    if (cfg->_action->linked_node->tlv->value[0] !=
        asn1::ConfigAction::_ca_cfg_set) {
        stream->end_sequence();
        return;
    }
    // check for params part
    if(!cfg->_params) return;
    // check params data
    if(!cfg->_params->has_linked_data(*in_sess)) return;
    // params
    p = cfg->_params;
    // check for params part
    if(!p->has_linked_data(*in_sess)) goto stream_continue;
    // process params
    for(unsigned int i = 0; i<p->children.size(); i++){
        // check for current session
        if(!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if(!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if(!p->get_child(i)->_value->has_linked_data(*in_sess)) continue;
        // check if child exists
        if(!p->get_child(i)->_value->get_child(0)) continue;
        // check if child exists in current sesion
        if(!p->get_child(i)->_value->get_child(0)->has_linked_data(*in_sess))
            continue;
        // check param id, convert from big endian to host
        auto param_id = (uint32_t*)p->get_child(i)->_id->linked_node->tlv->value;
        // set tmp values
        tmp_val = (char*)p->get_child(i)->_value->get_child(0)->linked_node->tlv->value;
        // match param
        switch(be32toh(*param_id)){
            // config item count
            case asn1::ParameterType::_pt_mink_config_cfg_item_count:
                tmp_ivp = (uint32_t*)tmp_val;
                snext->update_count = be32toh(*tmp_ivp);
                break;

            default:
                break;
        }
    }

stream_continue:
    stream->continue_sequence();

}

void config::CfgUpdateStreamDone::process_cfg_events(){
    // get node
    config::ConfigItem* root = snew->config->get_definition_root();
    // sanity check
    if(root == nullptr) return;

    // group by ON CHANGE handler
    std::map<CfgNtfCallback*, config::ConfigItem> hndlr_map;
    std::map<CfgNtfCallback*, config::ConfigItem>::iterator it;
    config::ConfigItem* tmp_node = nullptr;
    config::ConfigItem tmp_group;
    // check flat cfg nodes
    for(unsigned int i = 0; i<snext->cfg_res.children.size(); i++){
        // find node in tree structure
        tmp_node = (*root)(snext->cfg_res.children[i]->name.c_str());
        // skip if not found
        if(tmp_node == nullptr) continue;
        // skip if no ON CHAGNE andler
        if(tmp_node->on_change == nullptr) continue;
        // update node value (important for MOD/DEL actions since values are
        // modified after this event)
        // no need to reset it after, it will be done if CfgUpdateStreamDone method
        tmp_node->value = snext->cfg_res.children[i]->value;
        // update node state
        tmp_node->node_state = snext->cfg_res.children[i]->node_state;
        // if ITEM node and DELETED, set value to empty string
        // (important since values are modified after this event)
        if(tmp_node->node_state == config::CONFIG_NS_DELETED &&
           tmp_node->node_type == config::CONFIG_NT_ITEM) tmp_node->value = "";
        // check if handler already in map
        it = hndlr_map.find(tmp_node->on_change);
        // new handler found
        if(it == hndlr_map.end()){
            hndlr_map[tmp_node->on_change] = tmp_group;
            // add if not executed in previous pass
            if (!tmp_node->onc_hndlr_exec)
                hndlr_map[tmp_node->on_change].children.push_back(tmp_node);

            // add node to handler
        }else{
            // add if not executed in previous pass
            if (!tmp_node->onc_hndlr_exec)
                it->second.children.push_back(tmp_node);
        }
    }

    // run handlers
    for(it = hndlr_map.begin(); it != hndlr_map.end(); ++it){
        // check if modification list is empty
        if(!it->second.children.empty()){
            // run event handler
            it->first->run(&it->second);
            // mark as executed
            std::all_of(it->second.children.cbegin(),
                        it->second.children.cend(),
                        [](config::ConfigItem *n) {
                            n->onc_hndlr_exec = !n->onc_hndlr_exec;
                            return true;
                        });
        }
    }

    // remove grouped children to avoid deallocation
    for (it = hndlr_map.begin(); it != hndlr_map.end(); ++it)
        it->second.children.clear();
    // clear map
    hndlr_map.clear();


}


void config::CfgUpdateStreamDone::run(gdt::GDTCallbackArgs* args){
    // update configuration, changes in snew->snext->cfg_res
    if(!snew) return;
    ConfigItem* tmp_item = nullptr;
    ConfigItem* ch_item = nullptr;
    // lock config
    snew->config->lock();
    // run cfg events (first pass handles MODIFICATION and DELETION)
    process_cfg_events();
    // loop config changes (create NEW nodes als)
    for(unsigned int i = 0; i<snext->cfg_res.children.size(); i++){
        // set pointer
        tmp_item = snext->cfg_res.children[i];
        // check if config path exists (ConfigItem operator "()")
        ch_item = (*snew->config->get_definition_root())(tmp_item->name.c_str(),
                                                         true,
                                                         tmp_item->node_type,
                                                         true);
        // config path exists
        if(ch_item == nullptr) continue;

        // BLOCK node
        if(ch_item->node_type == CONFIG_NT_BLOCK){
            // deletion (validate parent)
            if((tmp_item->node_state == CONFIG_NS_DELETED) &&
               (ch_item->parent != nullptr)){

                // get item index
                int index = ch_item->parent->find(ch_item);
                // check if found
                if(index > -1){
                    // delete from list
                    ch_item->parent->children.erase(
                        ch_item->parent->children.begin() + index);
                    // free
                    delete ch_item;
                }
            }
            // ITEM node
        }else if(ch_item->node_type == CONFIG_NT_ITEM){
            if(tmp_item->node_state == CONFIG_NS_DELETED){
                ch_item->value = "";
                tmp_item->value = "";
            }else ch_item->value = tmp_item->value;

        }
    }

    // run cfg events (second pass handles ADDITION)
    process_cfg_events();

    // clear ON CHANGE executed flags, set node states to READY
    for(unsigned int i = 0; i<snext->cfg_res.children.size(); i++) {
        // set pointer
        tmp_item = snext->cfg_res.children[i];
        // check if config path exists (ConfigItem operator "()")
        ch_item = (*snew->config->get_definition_root())(tmp_item->name.c_str());
        // skip if not found
        if(ch_item == nullptr) continue;
        // reset flags
        ch_item->onc_hndlr_exec = false;
        ch_item->is_new = false;
        // set node state to ready
        ch_item->node_state = CONFIG_NS_READY;
    }

    // run user defined event handler
    if(snew->update_done != nullptr) snew->update_done->run(&snext->cfg_res);

    // unlock config
    snew->config->unlock();

    // free stream next memory
    delete snext;


}

void config::CfgUpdateStreamNext::run(gdt::GDTCallbackArgs* args){
    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                 gdt::GDT_CB_ARG_STREAM);
    auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                   gdt::GDT_CB_ARG_IN_MSG);
    auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                            gdt::GDT_CB_ARG_IN_MSG_ID);
    char* tmp_val = nullptr;
    int tmp_val_l = 0;
    config::ConfigItem* cfg_item = nullptr;
    asn1::Parameters *p = nullptr;
    asn1::ConfigMessage *cfg = nullptr;

    // check for body
    if(in_msg->_body == nullptr) return;
    // check for config message
    if(!in_msg->_body->_conf->has_linked_data(*in_sess))
        return;
    // reg msg pointer
    cfg = in_msg->_body->_conf;
    // check for GET action
    if (cfg->_action->linked_node->tlv->value[0] !=
        asn1::ConfigAction::_ca_cfg_set) {
        return;
    }
    // check for params part
    if(!cfg->_params) goto stream_continue;
    // check params data
    if(!cfg->_params->has_linked_data(*in_sess)) goto stream_continue;
    // params
    p = cfg->_params;

    // process params
    for(unsigned int i = 0; i<p->children.size(); i++){
        // check for current session
        if(!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if(!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if(!p->get_child(i)->_value->has_linked_data(*in_sess)) continue;
        // check if child exists
        if(!p->get_child(i)->_value->get_child(0)) continue;
        // check if child exists in current sesion
        if(!p->get_child(i)->_value->get_child(0)->has_linked_data(*in_sess))
            continue;
        // check param id, convert from big endian to host
        auto param_id = (uint32_t*)p->get_child(i)->_id->linked_node->tlv->value;
        // set tmp values
        tmp_val = (char*)p->get_child(i)->_value->get_child(0)->linked_node->tlv->value;
        tmp_val_l = p->get_child(i)->_value->get_child(0)->linked_node->tlv->value_length;
        // match param
        switch(be32toh(*param_id)){
            // config item path
            case asn1::ParameterType::_pt_mink_config_cfg_item_path:
                // start new config item
                cfg_item = new config::ConfigItem();
                cfg_item->name.append(tmp_val, tmp_val_l);
                cfg_res.children.push_back(cfg_item);
                break;

                // config item node value
            case asn1::ParameterType::_pt_mink_config_cfg_item_value:
                if (cfg_item) cfg_item->value.append(tmp_val, tmp_val_l);
                break;

                // config item node type
            case asn1::ParameterType::_pt_mink_config_cfg_item_nt:
                if (cfg_item) cfg_item->node_type = (config::ConfigNodeType)*tmp_val;
                break;

                // config item node state
            case asn1::ParameterType::_pt_mink_config_cfg_item_ns:
                if(cfg_item) cfg_item->node_state = (config::ConfigNodeState)*tmp_val;
                break;

            default:
                break;
        }
    }

stream_continue:
    stream->continue_sequence();
}

config::GDTCfgNtfUser::GDTCfgNtfUser(gdt::GDTClient* _gdtc) : gdtc(_gdtc){
    // reserved
}




config::GDTCfgNotification::GDTCfgNotification(const std::string* _cfg_path) : CfgNotification(_cfg_path),
                                                                               ready(false) {
    // reserved
}

config::GDTCfgNotification::~GDTCfgNotification() = default;

int config::GDTCfgNotification::notify(void* args){
    return 0;
}

void* config::GDTCfgNotification::reg_user(void* usr){
    auto uid = (GDTCfgNtfUser*)usr;
    if(!user_exists(uid)){
        users.push_back(*uid);
        return usr;
    }
    return nullptr;
}

int config::GDTCfgNotification::unreg_user(void* usr){
    auto uid = (config::UserId*)usr;
    for(unsigned int i = 0; i<users.size(); i++) if(users[i] == *uid){
        users.erase(users.begin() + i);
        return 0;
    }
    return 1;
}

bool config::GDTCfgNotification::user_exists(const config::GDTCfgNtfUser* usr){
    for(unsigned int i = 0; i<users.size(); i++) if(users[i] == *usr) return true;
    return false;
}

config::GDTCfgNtfUser* config::GDTCfgNotification::get_user(unsigned int usr_index){
    if(usr_index < users.size()) return &users[usr_index];
    return nullptr;
}

unsigned int config::GDTCfgNotification::get_user_count() const{
    return users.size();
}


config::RegUseStreamDone::RegUseStreamDone() : status(0),
                                               snext(nullptr) {
    sem_init(&signal, 0, 0);
}

config::RegUseStreamDone::~RegUseStreamDone(){
    sem_destroy(&signal);
}

void config::RegUseStreamDone::run(gdt::GDTCallbackArgs* args){
    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                 gdt::GDT_CB_ARG_STREAM);
    status = stream->get_timeout_status();
    sem_post(&signal);
}

void config::RegUsrStreamNext::run(gdt::GDTCallbackArgs* args){
    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                 gdt::GDT_CB_ARG_STREAM);
    auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                   gdt::GDT_CB_ARG_IN_MSG);
    auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                            gdt::GDT_CB_ARG_IN_MSG_ID);
    config::ConfigItem* cfg_item = nullptr;
    char* tmp_val = nullptr;
    int tmp_val_l = 0;
    asn1::Parameters *p = nullptr;
    asn1::ConfigMessage *cfg = nullptr;

    // check for body
    if(in_msg->_body == nullptr) return;
    // check for config message
    if(!in_msg->_body->_conf->has_linked_data(*in_sess))
        return;
    // reg msg pointer
    cfg = in_msg->_body->_conf;
    // check for GET action
    if (cfg->_action->linked_node->tlv->value[0] !=
        asn1::ConfigAction::_ca_cfg_result) {
        return;
    }
    // check for params part
    if(!cfg->_params) goto stream_continue;
    // check params data
    if(!cfg->_params->has_linked_data(*in_sess)) goto stream_continue;
    // params
    p = cfg->_params;


    // process params
    for(unsigned int i = 0; i<p->children.size(); i++){
        // check for current session
        if(!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if(!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if(!p->get_child(i)->_value->has_linked_data(*in_sess)) continue;
        // check if child exists
        if(!p->get_child(i)->_value->get_child(0)) continue;
        // check if child exists in current sesion
        if(!p->get_child(i)->_value->get_child(0)->has_linked_data(*in_sess))
            continue;
        // check param id, convert from big endian to host
        auto param_id = (uint32_t*)p->get_child(i)->_id->linked_node->tlv->value;
        // set tmp values
        tmp_val = (char*)p->get_child(i)->_value->get_child(0)->linked_node->tlv->value;
        tmp_val_l = p->get_child(i)->_value->get_child(0)->linked_node->tlv->value_length;
        // match param
        switch(be32toh(*param_id)){
            // item count
            case asn1::ParameterType::_pt_mink_config_cfg_item_count:
                cfg_count = be32toh(*(uint32_t*)tmp_val);
                break;

                // config item path
            case asn1::ParameterType::_pt_mink_config_cfg_item_path:
                // start new config item
                cfg_item = new config::ConfigItem();
                cfg_res.children.push_back(cfg_item);
                cfg_item->name.append(tmp_val, tmp_val_l);
                break;

                // config item node value
            case asn1::ParameterType::_pt_mink_config_cfg_item_value:
                if (cfg_item) cfg_item->value.append(tmp_val, tmp_val_l);
                break;

                // config item node type
            case asn1::ParameterType::_pt_mink_config_cfg_item_nt:
                if (cfg_item) cfg_item->node_type = (config::ConfigNodeType)*tmp_val;
                break;

                // config item node state
            case asn1::ParameterType::_pt_mink_config_cfg_item_ns:
                if (cfg_item) cfg_item->node_state = (config::ConfigNodeState)*tmp_val;
                break;

            default:
                break;
        }
    }
stream_continue:
   stream->continue_sequence();

}

config::DistributeCfgStreamNext::DistributeCfgStreamNext() {
    ca_cfg_replicate = asn1::ConfigAction::_ca_cfg_replicate;
    pt_cfg_repl_line = htobe32(asn1::ParameterType::_pt_mink_config_replication_line);
    pt_cfg_auth_id = htobe32(asn1::ParameterType::_pt_mink_auth_id);

}

void config::DistributeCfgStreamNext::run(gdt::GDTCallbackArgs* args){
    // nothing for now
}

void config::DistributeCfgStreamDone::run(gdt::GDTCallbackArgs* args){
    delete snext;
    delete this;
}




config::NtfyUsrStreamNext::NtfyUsrStreamNext() : res_count(0),
                                                 res_index(0),
                                                 cfg_ntf(nullptr),
                                                 ntf_user(nullptr),
                                                 config(nullptr) {
    // big endian parameter ids
    pt_cfg_item_path = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_path);
    pt_cfg_item_value = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_value);
    pt_cfg_item_count = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_count);
    ca_cfg_set = asn1::ConfigAction::_ca_cfg_set;
    pt_cfg_item_ns = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_ns);
    pt_cfg_item_nt = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_nt);

}

void config::NtfyUsrStreamNext::run(gdt::GDTCallbackArgs* args){
    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                 gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage* gdtm = stream->get_gdt_message();
    auto include_body = (bool*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                             gdt::GDT_CB_ARG_BODY);

    // more results
    if(res_index < cfg_flat.children.size()){
        // prepare body
        if(gdtm->_body != nullptr) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        }else{
            gdtm->set_body();
            gdtm->prepare();
        }
        asn1::ConfigMessage *cfg = gdtm->_body->_conf;
        // remove payload
        if(cfg->_payload != nullptr)
            cfg->_payload->unlink(1);
        // set params
        if(cfg->_params == nullptr){
            cfg->set_params();
            // set children, allocate more
            for(int i = 0; i<4; i++){
                cfg->_params->set_child(i);
                cfg->_params->get_child(i)->set_value();
                cfg->_params->get_child(i)->_value->set_child(0);

            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        }else{
            int cc = cfg->_params->children.size();
            if(cc < 4){
                // set children, allocate more
                for(int i = cc; i<4; i++){
                    cfg->_params->set_child(i);
                    cfg->_params->get_child(i)->set_value();
                    cfg->_params->get_child(i)->_value->set_child(0);

                }
                // prepare
                gdtm->prepare();

            }else if(cc > 4){
                // remove extra children if used in some other session, only 4 needed
                for(int i = 4; i<cc; i++) cfg->_params->get_child(i)->unlink(1);
            }
        }

        // set cfg action
        cfg->_action->set_linked_data(1, (unsigned char*)&ca_cfg_set, 1);

        // cfg path
        cfg->_params->get_child(0)->_id->set_linked_data(1,
                                                         (unsigned char*)&pt_cfg_item_path,
                                                         sizeof(uint32_t));
        cfg->_params->get_child(0)->_value->get_child(0)->set_linked_data(1,
                                                                          (unsigned char*)cfg_flat.children[res_index]->name.c_str(),
                                                                          cfg_flat.children[res_index]->name.size());

        // cfg item value
        cfg->_params->get_child(1)->_id->set_linked_data(1,
                                                         (unsigned char*)&pt_cfg_item_value,
                                                         sizeof(uint32_t));
        cfg->_params->get_child(1)->_value->get_child(0)->set_linked_data(1,
                                                                          (unsigned char*)cfg_flat.children[res_index]->value.c_str(),
                                                                          cfg_flat.children[res_index]->value.size());

        // cfg item node type
        cfg->_params->get_child(2)->_id->set_linked_data(1,
                                                         (unsigned char*)&pt_cfg_item_nt,
                                                         sizeof(uint32_t));
        cfg->_params->get_child(2)->_value->get_child(0)->set_linked_data(1,
                                                                          (unsigned char*)&cfg_flat.children[res_index]->node_type,
                                                                          1);

        // cfg item node state
        cfg->_params->get_child(3)->_id->set_linked_data(1,
                                                         (unsigned char*)&pt_cfg_item_ns,
                                                         sizeof(uint32_t));
        cfg->_params->get_child(3)->_value->get_child(0)->set_linked_data(1,
                                                                          (unsigned char*)&cfg_flat.children[res_index]->node_state,
                                                                          1);


        // include body
        *include_body = true;


        // next result item
        ++res_index;

        // continue
        stream->continue_sequence();


    }else{
        stream->end_sequence();

    }


}

void config::NtfyUsrStreamDone::run(gdt::GDTCallbackArgs* args){
    auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                   gdt::GDT_CB_ARG_IN_MSG);
    auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                            gdt::GDT_CB_ARG_IN_MSG_ID);

    if((in_msg->_header->_status != nullptr) &&
       (in_msg->_header->_status->has_linked_data(*in_sess)) &&
       (in_msg->_header->_status->linked_node->tlv->value[0] != 0)){

        // error
        // lock config
        snext->config->lock();
        // remove user
        if(snext->cfg_ntf != nullptr) snext->cfg_ntf->unreg_user(snext->ntf_user);
        // unlock config
        snext->config->unlock();
    }

    // free stream next (allocated in notify_user)
    delete snext;
    // free stream done (allocated in notify_user)
    delete this;
}

int config::replicate(const char* repl_line,
                      gdt::GDTClient* _client,
                      const char* _daemon_id,
                      const config::UserId* _cfg_user_id){
    // used inside GDT in_loop, cannot use semaphore, this method is async
    if(repl_line != nullptr && _client != nullptr && _daemon_id != nullptr && _cfg_user_id != nullptr){
        auto snext = new DistributeCfgStreamNext();
        auto sdone = new DistributeCfgStreamDone();
        sdone->snext = snext;

        snext->repl_line.append(repl_line);
        snext->cfg_user_id = *_cfg_user_id;


        // start new GDT stream
        gdt::GDTStream* gdt_stream = _client->new_stream("config_daemon",
                                                         _daemon_id,
                                                         nullptr,
                                                         snext);
        // if stream cannot be created, return err
        if(gdt_stream == nullptr){
            delete snext;
            delete sdone;
            return 1;
        }
        // set end event handler
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_END, sdone);
        // create body
        asn1::GDTMessage* gdtm = gdt_stream->get_gdt_message();
        // prepare body
        if(gdtm->_body != nullptr) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        }else{
            gdtm->set_body();
            gdtm->prepare();
        }
        asn1::ConfigMessage *cfg = gdtm->_body->_conf;

        // remove payload
        if(cfg->_payload != nullptr) cfg->_payload->unlink(1);
        // set params
        if(cfg->_params == nullptr){
            cfg->set_params();
            // set children, allocate more
            for(int i = 0; i<2; i++){
                cfg->_params->set_child(i);
                cfg->_params->get_child(i)->set_value();
                cfg->_params->get_child(i)->_value->set_child(0);

            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        }else{
            int cc = cfg->_params->children.size();
            if(cc < 2){
                // set children, allocate more
                for(int i = cc; i<2; i++){
                    cfg->_params->set_child(i);
                    cfg->_params->get_child(i)->set_value();
                    cfg->_params->get_child(i)->_value->set_child(0);

                }
                // prepare
                gdtm->prepare();

            }else if(cc > 2){
                // remove extra children if used in some other session, only 2 needed
                for (int i = 2; i < cc; i++)
                    cfg->_params->get_child(i)->unlink(1);
            }
        }

        // set cfg action
        cfg->_action->set_linked_data(1, (unsigned char*)&snext->ca_cfg_replicate, 1);

        // cfg replication line
        cfg->_params
           ->get_child(0)
           ->_id->set_linked_data(1,
                                  (unsigned char*)&snext->pt_cfg_repl_line,
                                  sizeof(uint32_t));
        cfg->_params
           ->get_child(0)
           ->_value
           ->get_child(0)
           ->set_linked_data(1,
                             (unsigned char*)snext->repl_line.c_str(),
                             snext->repl_line.size());

        // auth id
        cfg->_params
           ->get_child(1)
           ->_id
           ->set_linked_data(1,
                             (unsigned char*)&snext->pt_cfg_auth_id,
                             sizeof(uint32_t));
        cfg->_params
           ->get_child(1)
           ->_value
           ->get_child(0)
           ->set_linked_data(1,
                             (unsigned char*)snext->cfg_user_id.user_id,
                             strnlen((char*)snext->cfg_user_id.user_id,
                                     sizeof(snext->cfg_user_id.user_id) - 1));

        // start stream
        gdt_stream->send(true);


        // ok
        return 0;
    }
    // err
    return 1;
}


int config::notify_user(config::Config* config,
                        config::ConfigItem* cfg_flat,
                        config::GDTCfgNtfUser* ntf_user,
                        config::GDTCfgNotification* cfg_ntf){
    // used inside GDT in_loop, cannot use semaphore, this method is async
    if(cfg_flat != nullptr && ntf_user != nullptr){
        auto snext = new NtfyUsrStreamNext();
        auto sdone = new NtfyUsrStreamDone();
        sdone->snext = snext;
        // copy ntf cfg node list
        config->copy_nodes(cfg_flat, &snext->cfg_flat);
        snext->cfg_ntf = cfg_ntf;
        snext->ntf_user = ntf_user;
        snext->res_index = 0;
        snext->config = config;
        // start new GDT stream
        gdt::GDTStream* gdt_stream = ntf_user->gdtc->new_stream(
            (char*)ntf_user->user_type, (char*)ntf_user->user_id, nullptr, snext);

        // if stream cannot be created, return err
        if(gdt_stream == nullptr){
            delete snext;
            delete sdone;
            return 1;
        }
        // set end event handler
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_END, sdone);
        // create body
        asn1::GDTMessage* gdtm = gdt_stream->get_gdt_message();
        // prepare body
        if(gdtm->_body != nullptr) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        }else{
            gdtm->set_body();
            gdtm->prepare();
        }

        // remove payload
        if (gdtm->_body->_conf->_payload != nullptr)
            gdtm->_body->_conf->_payload->unlink(1);
        // set params
        if(gdtm->_body->_conf->_params == nullptr){
            gdtm->_body->_conf->set_params();
            // set children, allocate more
            for(int i = 0; i<1; i++){
                gdtm->_body->_conf->_params->set_child(i);
                gdtm->_body->_conf->_params->get_child(i)->set_value();
                gdtm->_body->_conf->_params->get_child(i)->_value->set_child(0);

            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        }else{
            int cc = gdtm->_body->_conf->_params->children.size();
            if(cc < 1){
                // set children, allocate more
                for(int i = cc; i<1; i++){
                    gdtm->_body->_conf->_params->set_child(i);
                    gdtm->_body->_conf->_params->get_child(i)->set_value();
                    gdtm->_body->_conf->_params->get_child(i)->_value->set_child(0);

                }
                // prepare
                gdtm->prepare();

            }else if(cc > 1){
                // remove extra children if used in some other session, only 2
                // needed
                for (int i = 1; i < cc; i++)
                    gdtm->_body->_conf->_params->get_child(i)->unlink(1);
            }
        }

        // set cfg action
        gdtm->_body->_conf->_action->set_linked_data(
            1, (unsigned char*)&snext->ca_cfg_set, 1);

        // cfg item count
        snext->res_count = htobe32(cfg_flat->children.size());
        gdtm->_body->_conf->_params->get_child(0)->_id->set_linked_data(
            1, (unsigned char*)&snext->pt_cfg_item_count, sizeof(uint32_t));
        gdtm->_body->_conf->_params->get_child(0)
            ->_value->get_child(0)
            ->set_linked_data(1, (unsigned char*)&snext->res_count,
                              sizeof(uint32_t));

        // start stream
        gdt_stream->send(true);


        // return ok
        return 0;
    }
    // return err
    return 1;
}


int config::user_logout(const config::Config* config,
                        gdt::GDTClient* cfgd_gdtc,
                        const char* _daemon_id,
                        config::UserId* cfg_user_id){
    if(config != nullptr && cfgd_gdtc != nullptr){
        // Client registration stream next
        class _InitUserStremDone: public gdt::GDTCallbackMethod {
            public:
                _InitUserStremDone(){
                    sem_init(&signal, 0, 0);

                }
                ~_InitUserStremDone() override{
                    sem_destroy(&signal);
                }
                _InitUserStremDone(const _InitUserStremDone &o) = delete;
                _InitUserStremDone &operator=(const _InitUserStremDone &o) = delete;

                // event handler method
                void run(gdt::GDTCallbackArgs* args) override{
                    sem_post(&signal);
                }

                // signal
                sem_t signal;

        };
        // stream done event
        _InitUserStremDone sdone;

        // start new GDT stream
        gdt::GDTStream* gdt_stream = cfgd_gdtc->new_stream("config_daemon",
                                                           _daemon_id,
                                                           nullptr,
                                                           nullptr);
        // if stream cannot be created, return err
        if(gdt_stream == nullptr) return 1;
        // set end event handler
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_END, &sdone);
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT, &sdone);
        // create body
        asn1::GDTMessage* gdtm = gdt_stream->get_gdt_message();
        // prepare body
        if(gdtm->_body != nullptr) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        }else{
            gdtm->set_body();
            gdtm->prepare();
        }
        // set bodu
        uint32_t auth_id = htobe32(asn1::ParameterType::_pt_mink_auth_id);
        uint32_t cfg_action = asn1::ConfigAction::_ca_cfg_user_logout;

        // remove payload
        if(gdtm->_body->_conf->_payload != nullptr) gdtm->_body->_conf->_payload->unlink(1);
        // set params
        if(gdtm->_body->_conf->_params == nullptr){
            gdtm->_body->_conf->set_params();
            // set children, allocate more
            for(int i = 0; i<1; i++){
                gdtm->_body->_conf->_params->set_child(i);
                gdtm->_body->_conf->_params->get_child(i)->set_value();
                gdtm->_body->_conf->_params->get_child(i)->_value->set_child(0);

            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        }else{
            int cc = gdtm->_body->_conf->_params->children.size();
            if(cc < 1){
                // set children, allocate more
                for(int i = cc; i<1; i++){
                    gdtm->_body->_conf->_params->set_child(i);
                    gdtm->_body->_conf->_params->get_child(i)->set_value();
                    gdtm->_body->_conf->_params->get_child(i)->_value->set_child(0);

                }
                // prepare
                gdtm->prepare();

            }else if(cc > 1){
                // remove extra children if used in some other session, only 2 needed
                for (int i = 1; i < cc; i++)
                    gdtm->_body->_conf->_params->get_child(i)->unlink(1);
            }
        }

        // set cfg action
        gdtm->_body->_conf->_action->set_linked_data(1, (unsigned char*)&cfg_action, 1);


        // user id (daemon_type : daemon_id : socket_id)
        char tmp_user_id[46];
        memset(tmp_user_id, 0, sizeof(tmp_user_id));
        memcpy(tmp_user_id,
               cfgd_gdtc->get_session()->get_daemon_type(),
               strnlen(cfgd_gdtc->get_session()->get_daemon_type(), 49));
        tmp_user_id[strnlen(tmp_user_id, 45)] = ':';
        memcpy(&tmp_user_id[strnlen(tmp_user_id, 45)],
               cfgd_gdtc->get_session()->get_daemon_id(),
               strnlen(cfgd_gdtc->get_session()->get_daemon_id(), 49));

        // set UserId values
        memcpy(cfg_user_id->user_id, tmp_user_id, strnlen(tmp_user_id, 45));
        memcpy(cfg_user_id->user_type,
               cfgd_gdtc->get_session()->get_daemon_type(),
               strnlen(cfgd_gdtc->get_session()->get_daemon_type(), 49));

        // cfg uth id
        gdtm->_body
            ->_conf
            ->_params
            ->get_child(0)
            ->_id
            ->set_linked_data(1, (unsigned char*)&auth_id, sizeof(uint32_t));

        gdtm->_body
            ->_conf
            ->_params
            ->get_child(0)
            ->_value
            ->get_child(0)
            ->set_linked_data(1, (unsigned char*)tmp_user_id, strnlen(tmp_user_id, 45));

        // start stream
        gdt_stream->send(true);

        // wait for signal
        timespec ts;
        clock_gettime(0, &ts);
        ts.tv_sec += 10;
        int sres = sem_wait(&sdone.signal);
        // error check
        if(sres == -1) return 1;

        // return ok
        return 0;
    }

    // return err
    return 1;

}

int config::user_login(const config::Config* config,
                       gdt::GDTClient* cfgd_gdtc,
                       const char* _target_daemon_id,
                       char* _connected_daemon_id,
                       config::UserId* cfg_user_id){
    if(config != nullptr && cfgd_gdtc != nullptr){
        // Client registration stream next
        class _InitUserStremDone: public gdt::GDTCallbackMethod {
        public:
            explicit _InitUserStremDone(char* _out_daemon_id) : out_daemon_id(_out_daemon_id){
                sem_init(&signal, 0, 0);

            }
            _InitUserStremDone(const _InitUserStremDone &o) = delete;
            _InitUserStremDone &operator=(const _InitUserStremDone &o) = delete;
            ~_InitUserStremDone() override{
                sem_destroy(&signal);
            }

            // event handler method
            void run(gdt::GDTCallbackArgs* args) override {
                auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARG_IN_MSG);
                auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                        gdt::GDT_CB_ARG_IN_MSG_ID);

                // timeout if in_msg is nullptr
                if(in_msg == nullptr) {
                    sem_post(&signal);
                    return;
                }
                // check status
                // get connected daemon id
                if((in_msg->_header->_status != nullptr) &&
                   (in_msg->_header->_status->has_linked_data(*in_sess)) &&
                   (in_msg->_header->_status->linked_node->tlv->value[0] == 0) &&
                   (in_msg->_header->_source->_id != nullptr) &&
                   (in_msg->_header->_source->_id->has_linked_data(*in_sess))) {

                    // C string
                    memcpy(out_daemon_id,
                           in_msg->_header
                                 ->_source
                                 ->_id
                                 ->linked_node
                                 ->tlv
                                 ->value,
                           in_msg->_header
                                 ->_source
                                 ->_id
                                 ->linked_node
                                 ->tlv
                                 ->value_length);

                    // null character
                    out_daemon_id[in_msg->_header
                                        ->_source
                                        ->_id
                                        ->linked_node
                                        ->tlv
                                        ->value_length] = '\0';
                }



                sem_post(&signal);
            }

            // signal
            sem_t signal;
            char* out_daemon_id;

        };
        // reset connectd daeon
        _connected_daemon_id[0] = 0;
        // stream done event
        auto sdone = new _InitUserStremDone(_connected_daemon_id);

        // start new GDT stream
        gdt::GDTStream* gdt_stream = cfgd_gdtc->new_stream("config_daemon",
                                                           _target_daemon_id,
                                                           nullptr,
                                                           nullptr);
        // if stream cannot be created, return err
        if(gdt_stream == nullptr) return 1;
        // set end event handler
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_END, sdone);
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT, sdone);
        // create body
        asn1::GDTMessage* gdtm = gdt_stream->get_gdt_message();
        // prepare body
        if(gdtm->_body != nullptr) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        }else{
            gdtm->set_body();
            gdtm->prepare();
        }
        // set bodu
        uint32_t auth_id = htobe32(asn1::ParameterType::_pt_mink_auth_id);
        uint32_t cfg_action = asn1::ConfigAction::_ca_cfg_user_login;

        // remove payload
        if (gdtm->_body->_conf->_payload != nullptr)
            gdtm->_body->_conf->_payload->unlink(1);
        // set params
        if(gdtm->_body->_conf->_params == nullptr){
            gdtm->_body->_conf->set_params();
            // set children, allocate more
            for(int i = 0; i<1; i++){
                gdtm->_body->_conf->_params->set_child(i);
                gdtm->_body->_conf->_params->get_child(i)->set_value();
                gdtm->_body->_conf->_params->get_child(i)->_value->set_child(0);

            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        }else{
            int cc = gdtm->_body->_conf->_params->children.size();
            if(cc < 1){
                // set children, allocate more
                for(int i = cc; i<1; i++){
                    gdtm->_body->_conf->_params->set_child(i);
                    gdtm->_body->_conf->_params->get_child(i)->set_value();
                    gdtm->_body->_conf->_params->get_child(i)->_value->set_child(0);

                }
                // prepare
                gdtm->prepare();

            }else if(cc > 1){
                // remove extra children if used in some other session, only 2 needed
                for (int i = 1; i < cc; i++)
                    gdtm->_body->_conf->_params->get_child(i)->unlink(1);
            }
        }

        // set cfg action
        gdtm->_body->_conf->_action->set_linked_data(
            1, (unsigned char*)&cfg_action, 1);

        // user id (daemon_type : daemon_id : socket_id)
        char tmp_user_id[46];
        memset(tmp_user_id, 0, sizeof(tmp_user_id));
        memcpy(tmp_user_id,
               cfgd_gdtc->get_session()->get_daemon_type(),
               strnlen(cfgd_gdtc->get_session()->get_daemon_type(), 49));
        tmp_user_id[strnlen(tmp_user_id, 45)] = ':';
        memcpy(&tmp_user_id[strnlen(tmp_user_id, 45)],
               cfgd_gdtc->get_session()->get_daemon_id(),
               strnlen(cfgd_gdtc->get_session()->get_daemon_id(), 49));
        // set UserId values
        memcpy(cfg_user_id->user_id,
               tmp_user_id,
               strnlen(tmp_user_id, 45));
        // cfg auth id
        gdtm->_body
            ->_conf
            ->_params
            ->get_child(0)
            ->_id
            ->set_linked_data(1, (unsigned char*)&auth_id, sizeof(uint32_t));

        gdtm->_body
            ->_conf
            ->_params
            ->get_child(0)
            ->_value
            ->get_child(0)
            ->set_linked_data(1, (unsigned char*)tmp_user_id, strnlen(tmp_user_id, 45));

        // start stream
        gdt_stream->send(true);

        // wait for signal
        sem_wait(&sdone->signal);
        // error check

        // free
        delete sdone;

        // return ok
        return 0;
    }

    // return err
    return 1;
}


int config::notification_request(config::Config* config,
                                 gdt::GDTClient* cfgd_gdtc,
                                 const char* usr_root,
                                 config::CfgNtfCallback* update_rcvd,
                                 const char* _daemon_id,
                                 config::UserId* cfg_user_id,
                                 gdt::GDTCallbackMethod* non_cfg_hndlr){

    if(config != nullptr && cfgd_gdtc != nullptr && usr_root != nullptr){

        RegUsrStreamNext snext;
        RegUseStreamDone sdone;
        sdone.snext = &snext;
        // start new GDT stream
        gdt::GDTStream* gdt_stream = cfgd_gdtc->new_stream("config_daemon",
                                                           _daemon_id,
                                                           nullptr,
                                                           &snext);
        // if stream cannot be created, return err
        if(gdt_stream == nullptr) return 1;
        // set end event handler
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_END, &sdone);
        gdt_stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT, &sdone);
        // create body
        asn1::GDTMessage* gdtm = gdt_stream->get_gdt_message();
        // prepare body
        if(gdtm->_body != nullptr) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        }else{
            gdtm->set_body();
            gdtm->prepare();
        }
        // set bodu
        uint32_t cfg_ntfy_id =
            htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_notify);
        uint32_t cfg_path_id =
            htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_path);
        uint32_t auth_id = htobe32(asn1::ParameterType::_pt_mink_auth_id);
        uint32_t cfg_action = asn1::ConfigAction::_ca_cfg_get;
        int cfg_ntfy_flag = 1;
        asn1::ConfigMessage *cfg = gdtm->_body->_conf;
        // remove payload
        if (cfg->_payload != nullptr)
            cfg->_payload->unlink(1);
        // set params
        if(cfg->_params == nullptr){
            cfg->set_params();
            // set children, allocate more
            for(int i = 0; i<3; i++){
                cfg->_params->set_child(i);
                cfg->_params->get_child(i)->set_value();
                cfg->_params->get_child(i)->_value->set_child(0);

            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        }else{
            int cc = cfg->_params->children.size();
            if(cc < 3){
                // set children, allocate more
                for(int i = cc; i<3; i++){
                    cfg->_params->set_child(i);
                    cfg->_params->get_child(i)->set_value();
                    cfg->_params->get_child(i)->_value->set_child(0);

                }
                // prepare
                gdtm->prepare();

            }else if(cc > 3){
                // remove extra children if used in some other session, only 2 needed
                for (int i = 3; i < cc; i++)
                    cfg->_params->get_child(i)->unlink(1);
            }
        }

        // set cfg action
        cfg->_action->set_linked_data(1, (unsigned char*)&cfg_action, 1);

        // cfg path
        cfg->_params
           ->get_child(0)
           ->_id
           ->set_linked_data(1, (unsigned char*)&cfg_path_id, sizeof(uint32_t));

        cfg->_params
           ->get_child(0)
           ->_value
           ->get_child(0)
           ->set_linked_data(1, (unsigned char*)usr_root, strnlen(usr_root, 255));

        // cfg notify flag
        cfg->_params
           ->get_child(1)
           ->_id->set_linked_data(1, (unsigned char*)&cfg_ntfy_id, sizeof(uint32_t));

        cfg->_params
           ->get_child(1)
           ->_value
           ->get_child(0)
           ->set_linked_data(1, (unsigned char*)&cfg_ntfy_flag, 1);

        // auth id
        cfg->_params
           ->get_child(2)
           ->_id
           ->set_linked_data(1, (unsigned char*)&auth_id, sizeof(uint32_t));

        cfg->_params
           ->get_child(2)
           ->_value
           ->get_child(0)
           ->set_linked_data(1,
                             cfg_user_id->user_id,
                             strnlen((char*)cfg_user_id->user_id,
                                     sizeof(cfg_user_id->user_id) - 1));


        // start stream
        gdt_stream->send(true);

        // wait for signal
        timespec ts;
        clock_gettime(0, &ts);
        ts.tv_sec += 10;
        int sres = sem_wait(&sdone.signal);
        // error check
        if (sres == -1 || sdone.status > 0 ||
            snext.cfg_count != snext.cfg_res.children.size())
            return 1;

        // crete new definition if needed
        if(config->get_definition_root() == nullptr) config->new_definition();
        // loop list, only CONFIG_NT_ITEM nodes included
        for (unsigned int i = 0; i < snext.cfg_res.children.size(); i++) {
            ConfigItem* tmp_cfg = (*config->get_definition_root())(
                snext.cfg_res.children[i]->name.c_str(), true,
                snext.cfg_res.children[i]->node_type);
            tmp_cfg->value = snext.cfg_res.children[i]->value;
        }
        // set event handlers
        if (cfgd_gdtc->get_callback(gdt::GDT_ET_STREAM_NEW) == nullptr &&
            cfgd_gdtc->get_callback(gdt::GDT_ET_CLIENT_TERMINATED) == nullptr) {
            auto cfg_snew = new CfgUpdateStreamNew();
            auto cfg_term = new CfgUpdateClientTerm();
            cfg_snew->update_done = update_rcvd;
            cfg_snew->config = config;
            cfg_snew->set_continue_callback(non_cfg_hndlr);
            cfgd_gdtc->set_callback(gdt::GDT_ET_STREAM_NEW, cfg_snew);
            cfgd_gdtc->set_callback(gdt::GDT_ET_CLIENT_TERMINATED, cfg_term);
        }

        // return ok
        return 0;
    }

    // return err
    return 1;
}

gdt::GDTCallbackMethod* config::create_cfg_event_handler(config::Config* config,
                                                         gdt::GDTCallbackMethod* non_cfg_hndlr){
    auto cfg_snew = new CfgUpdateStreamNew();
    cfg_snew->update_done = nullptr;
    cfg_snew->config = config;
    cfg_snew->set_continue_callback(non_cfg_hndlr);
    return cfg_snew;


}

