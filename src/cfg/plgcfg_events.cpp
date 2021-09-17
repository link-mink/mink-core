/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <plgcfg_events.h>

PluginInfo::PluginInfo() : config(nullptr),
                           cli(nullptr),
                           gdts(nullptr),
                           last_gdtc(nullptr),
                           hbeat(nullptr){
    sem_init(&sem_cfgd, 0, 0);
    memset(last_cfgd_id, 0, sizeof(last_cfgd_id));
}

PluginInfo::~PluginInfo(){
    std::all_of(cfgd_lst.cbegin(), cfgd_lst.cend(), [](std::string *s) {
        delete s;
        return true;
    });
    sem_destroy(&sem_cfgd);
}

StreamEnd::StreamEnd(PluginInfo *_pi) : plugin_info(_pi) {}

void StreamEnd::run(gdt::GDTCallbackArgs* args){
    // signal
    sem_post(&plugin_info->sem_cfgd);
}



StreamNext::StreamNext(PluginInfo* _pi, config::ConfigItem* _cfg_res) : plugin_info(_pi),
                                                                        cfg_res(_cfg_res),
                                                                        cm_mode(config::CONFIG_MT_UNKNOWN),
                                                                        ac_mode(config::CONFIG_ACM_TAB),
                                                                        line_stream_lc(0),
                                                                        error_count(0),
                                                                        err_index(0) {}


void StreamNext::process_enter(gdt::GDTCallbackArgs* args){
    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS, 
                                                 gdt::GDT_CB_ARG_STREAM);
    auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS, 
                                                   gdt::GDT_CB_ARG_IN_MSG);
    auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS, 
                                            gdt::GDT_CB_ARG_IN_MSG_ID);
    config::ConfigItem* cfg_item = nullptr;
    char* tmp_val = nullptr;
    int tmp_val_l = 0;
    std::string tmp_str;
    uint32_t* tmp_ivp;
    asn1::Parameters *p = nullptr;
    asn1::ConfigMessage *cfg = nullptr;


    // check for body
    if(in_msg->_body == nullptr) goto params_done;
    // check for config message
    if(!in_msg->_body->_conf->has_linked_data(*in_sess)) goto params_done;
    // conf pointer
    cfg = in_msg->_body->_conf;
    // check for config result
    if(cfg->_action->linked_node->tlv->value[0] != asn1::ConfigAction::_ca_cfg_result) goto params_done;
    // check for params part
    if(cfg->_params == nullptr) goto params_done;
    if(!cfg->_params->has_linked_data(*in_sess)) goto params_done;
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
        if(!p->get_child(i)->_value->get_child(0)->has_linked_data(*in_sess)) continue;
        // check param id, convert from big endian to host
        auto param_id = (uint32_t*)p->get_child(i)->_id->linked_node->tlv->value;
        // set tmp values
        tmp_val = (char*)p->get_child(i)->_value->get_child(0)->linked_node->tlv->value;
        tmp_val_l = p->get_child(i)->_value->get_child(0)->linked_node->tlv->value_length;
        // match param
        switch(be32toh(*param_id)){
            // error count
            case asn1::ParameterType::_pt_mink_config_ac_err_count:
                tmp_ivp = (uint32_t*)tmp_val;
                error_count = be32toh(*tmp_ivp);
                break;

                // result line count
            case asn1::ParameterType::_pt_mink_config_cfg_line_count:
                tmp_ivp = (uint32_t*)tmp_val;
                line_stream_lc = be32toh(*tmp_ivp);
                break;

                // result line
            case asn1::ParameterType::_pt_mink_config_cfg_line:
                tmp_str.clear();
                tmp_str.append(tmp_val, tmp_val_l);
                line_stream << tmp_str << std::endl;
                break;

                // error line
            case asn1::ParameterType::_pt_mink_config_cfg_ac_err:
                tmp_str.clear();
                tmp_str.append(tmp_val, tmp_val_l);
                err_lst[err_index++] = tmp_str;
                break;

                // cli path
            case asn1::ParameterType::_pt_mink_config_cli_path:
                tmp_str.clear();
                tmp_str.append(tmp_val, tmp_val_l);
                // regenerate cli path
                *plugin_info->cli->get_current_path_line() = "";
                plugin_info->cli->generate_path(plugin_info->cli->get_current_path(), 
                                                plugin_info->cli->get_current_path_line());
                // add cfg path to cli path
                plugin_info->cli->get_current_path_line()->append(tmp_str);
                plugin_info->cli->generate_prompt();
                break;

                // ac line
            case asn1::ParameterType::_pt_mink_config_ac_line:
                // update line
                plugin_info->cli->clear_curent_line();
                plugin_info->cli->get_current_line()->append(tmp_val, tmp_val_l);
                // add to history
                plugin_info->cli->add_to_history(plugin_info->cli->get_current_line());
                plugin_info->cli->history_index = plugin_info->cli->get_historu_size();
                break;

                // config item name
            case asn1::ParameterType::_pt_mink_config_cfg_item_name:
                // start new config item
                cfg_item = new config::ConfigItem();
                cfg_res->children.push_back(cfg_item);
                cfg_item->name.append(tmp_val, tmp_val_l);
                break;

                // config item desc
            case asn1::ParameterType::_pt_mink_config_cfg_item_desc:
                if (cfg_item) cfg_item->desc.append(tmp_val, tmp_val_l);
                break;

                // config item node state
            case asn1::ParameterType::_pt_mink_config_cfg_item_ns:
                if (cfg_item) cfg_item->node_state = (config::ConfigNodeState)*tmp_val;
                break;

                // config item node value
            case asn1::ParameterType::_pt_mink_config_cfg_item_value:
                if (cfg_item) cfg_item->value.append(tmp_val, tmp_val_l);
                break;

                // config item node new value
            case asn1::ParameterType::_pt_mink_config_cfg_item_nvalue:
                if (cfg_item) cfg_item->new_value.append(tmp_val, tmp_val_l);
                break;

                // config item node type
            case asn1::ParameterType::_pt_mink_config_cfg_item_nt:
                if (cfg_item) cfg_item->node_type = (config::ConfigNodeType)*tmp_val;
                break;

                // config item mode
            case asn1::ParameterType::_pt_mink_config_cfg_cm_mode:
                if (cfg_item) cm_mode = (config::ConfigModeType)*tmp_val;
                break;

            default:
                break;

        }

    }



params_done:
    // continue
    stream->continue_sequence();

}

void StreamNext::process_tab(gdt::GDTCallbackArgs* args){
    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_STREAM);
    auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_IN_MSG);
    auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS, gdt::GDT_CB_ARG_IN_MSG_ID);
    config::ConfigItem* cfg_item = nullptr;
    char* tmp_val = nullptr;
    int tmp_val_l = 0;
    asn1::Parameters *p = nullptr;
    asn1::ConfigMessage *cfg = nullptr;

    // check for body
    if(in_msg->_body == nullptr) goto params_done;
    // check for config message
    if(!in_msg->_body->_conf->has_linked_data(*in_sess)) goto params_done;
    // conf pointer
    cfg = in_msg->_body->_conf;
    // check for config result
    if(cfg->_action->linked_node->tlv->value[0] != asn1::ConfigAction::_ca_cfg_result) goto params_done;
    // check for params part
    if(cfg->_params == nullptr) goto params_done;
    if(!cfg->_params->has_linked_data(*in_sess)) goto params_done;
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
        if(!p->get_child(i)->_value->get_child(0)->has_linked_data(*in_sess)) continue;
        // check param id, convert from big endian to host
        auto param_id = (uint32_t*)p->get_child(i)->_id->linked_node->tlv->value;
        // set tmp values
        tmp_val = (char*)p->get_child(i)->_value->get_child(0)->linked_node->tlv->value;
        tmp_val_l = p->get_child(i)->_value->get_child(0)->linked_node->tlv->value_length;
        // match param
        switch(be32toh(*param_id)){
            // ac line
            case asn1::ParameterType::_pt_mink_config_ac_line:
                // update line
                plugin_info->cli->clear_curent_line();
                plugin_info->cli->get_current_line()->append(tmp_val, tmp_val_l);
                break;

                // config item name
            case asn1::ParameterType::_pt_mink_config_cfg_item_name:
                // start new config item
                cfg_item = new config::ConfigItem();
                cfg_res->children.push_back(cfg_item);
                cfg_item->name.append(tmp_val, tmp_val_l);
                break;

                // config item desc
            case asn1::ParameterType::_pt_mink_config_cfg_item_desc:
                if (cfg_item) cfg_item->desc.append(tmp_val, tmp_val_l);
                break;

                // config item node state
            case asn1::ParameterType::_pt_mink_config_cfg_item_ns:
                if (cfg_item) cfg_item->node_state = (config::ConfigNodeState)*tmp_val;
                break;

                // config item node value
            case asn1::ParameterType::_pt_mink_config_cfg_item_value:
                if (cfg_item) cfg_item->value.append(tmp_val, tmp_val_l);
                break;

                // config item node new value
            case asn1::ParameterType::_pt_mink_config_cfg_item_nvalue:
                if (cfg_item) cfg_item->new_value.append(tmp_val, tmp_val_l);
                break;

                // config item node type
            case asn1::ParameterType::_pt_mink_config_cfg_item_nt:
                if (cfg_item) cfg_item->node_type = (config::ConfigNodeType)*tmp_val;
                break;

                // config mode
            case asn1::ParameterType::_pt_mink_config_cfg_cm_mode:
                cm_mode = (config::ConfigModeType)*tmp_val;
                break;
            
            default:
                break;

        }

    }
params_done:
    // continue
    stream->continue_sequence();

}

void StreamNext::run(gdt::GDTCallbackArgs* args){
    switch(ac_mode){
        case config::CONFIG_ACM_ENTER:
            process_enter(args);
            break;

        case config::CONFIG_ACM_TAB:
            process_tab(args);
            break;

        default:
            break;
    }

}


