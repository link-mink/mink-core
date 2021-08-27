/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <antlr_utils.h>
#include <events.h>
#include <fstream>

ClientIdle::ClientIdle() { config = NULL; }

void ClientIdle::run(gdt::GDTCallbackArgs *args) {
    // * unlock to avoid deadlock
    // * could happen if client stream was interrupted and not properly closed
    // * if this client did not previously call lock(), unlock() method will
    // fail silently
    config->unlock();
}

ClientDown::ClientDown(config::Config *_config) { config = _config; }

void ClientDown::run(gdt::GDTCallbackArgs *args) {
    // * unlock to avoid deadlock
    // * could happen if client stream was interrupted and not properly closed
    // * if this client did not previously call lock(), unlock() method will
    // fail silently
    config->unlock();
}

ClientDone::ClientDone(config::Config *_config) { config = _config; }

void ClientDone::run(gdt::GDTCallbackArgs *args) {
    // nothing to do for now
}

void NewClient::run(gdt::GDTCallbackArgs *args) {
    gdt::GDTClient *client = (gdt::GDTClient *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_CLIENT);
    // handle new stream event for current client
    client->set_callback(gdt::GDT_ET_STREAM_NEW, &new_stream);
    // handle client idle
    client->set_callback(gdt::GDT_ET_CLIENT_IDLE, &client_idle);
}

NewClient::NewClient(config::Config *_config) {
    config = _config;
    new_stream.config = config;
    client_idle.config = _config;
}

void StreamDone::run(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    StreamNext *snext = (StreamNext *)stream->get_callback(gdt::GDT_ET_STREAM_NEXT);
    gdt::GDTClient *client = stream->get_client();

    // notifications
    if (ntfy_lst.size() > 0) {
        for (unsigned int i = 0; i < ntfy_lst.size(); i++) {
            // gdt notification
            config::GDTCfgNotification *gdtn = (config::GDTCfgNotification *)ntfy_lst[i];
            // notify all users
            unsigned int j = 0;
            while (j < gdtn->get_user_count()) {
                // check if client is still active
                if (client->get_session()->get_client(gdtn->get_user(j)->gdtc)) {
                    // check if ready to send
                    if (gdtn->ready) {
                        config::notify_user(snext->new_stream->config,
                                            &gdtn->ntf_cfg_lst,
                                            gdtn->get_user(j), gdtn);
                    }
                    // next
                    ++j;

                    // client terminated, remove notification
                } else {
                    gdtn->unreg_user(gdtn->get_user(j));
                }
            }
            // clear and deallocate ntf cfg node list
            for (unsigned int i = 0; i < gdtn->ntf_cfg_lst.children.size(); i++)
                delete gdtn->ntf_cfg_lst.children[i];
            gdtn->ntf_cfg_lst.children.clear();
            gdtn->ready = false;
        }
        // clear notification list
        ntfy_lst.clear();
    }

    // unlock config mutex
    snext->new_stream->config->unlock();
    // deallocate NewStream, allocated in NewStream::run
    // clear ac res list or it will be deallocated (big no no)
    snext->new_stream->ac_res.children.clear();
    // clear tmp list
    for (unsigned int i = 0; i < snext->new_stream->tmp_node_lst.children.size(); i++)
        delete snext->new_stream->tmp_node_lst.children[i];
    snext->new_stream->tmp_node_lst.children.clear();
    // free new stream
    delete snext->new_stream;
}

NewStream::NewStream() {
    stream_next.cfg_res = NULL;
    stream_next.new_stream = NULL;
    config_action = -1;
    ac_res_count = 0;
    ca_cfg_result = asn1::ConfigAction::_ca_cfg_result;
    pt_mink_config_ac_line = htobe32(asn1::ParameterType::_pt_mink_config_ac_line);
    pt_mink_config_ac_err_count = htobe32(asn1::ParameterType::_pt_mink_config_ac_err_count);
    pt_mink_config_cli_path = htobe32(asn1::ParameterType::_pt_mink_config_cli_path);
    pt_mink_config_cfg_line_count = htobe32(asn1::ParameterType::_pt_mink_config_cfg_line_count);
    pt_cfg_item_cm_mode = htobe32(asn1::ParameterType::_pt_mink_config_cfg_cm_mode);
    config = NULL;
    cm_mode = config::CONFIG_MT_UNKNOWN;
    res_index = 0;
    error_count = 0;
    ac_mode = config::CONFIG_ACM_TAB;
    line_stream_lc = 0;
    tmp_size = 0;
    last_found = NULL;
    res_size = 0;
    err_index = 0;
}

int NewStream::get_cfg_uid(config::UserId *usr_id,
                           asn1::GDTMessage *in_msg,
                           int sess_id) {
    // null check
    if (usr_id == NULL || in_msg == NULL) return 1;
    // check for body
    if (!in_msg->_body) return 1;
    // check for config message
    if (!in_msg->_body->_conf->has_linked_data(sess_id)) return 1;
    // check for params part
    if (!in_msg->_body->_conf->_params) return 1;
    if (!in_msg->_body->_conf->_params->has_linked_data(sess_id)) return 1;
    asn1::ConfigMessage *c = in_msg->_body->_conf;
    asn1::Parameters *p = c->_params;

    // process params
    for (unsigned int i = 0;  i < p->children.size(); i++) {
        // check for current session
        if (!p->get_child(i)->has_linked_data(sess_id)) continue;
        // check for value
        if (!p->get_child(i)) continue;
        // check if value exists in current session
        if (!p->get_child(i)->_value->has_linked_data(sess_id)) continue;
        // check if child exists
        if (!p->get_child(i)->_value->get_child(0)) continue;
        // check if child exists in current
        // sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(sess_id)) continue;

        // check param id, convert from big endian to host
        uint32_t *param_id = (uint32_t *)p->get_child(i)
                                          ->_id
                                          ->linked_node
                                          ->tlv
                                          ->value;
        // set tmp values
        char *tmp_val = (char *)p->get_child(i)
                                 ->_value
                                 ->get_child(0)
                                 ->linked_node
                                 ->tlv
                                 ->value;

        unsigned int tmp_val_l = p->get_child(i)
                                  ->_value
                                  ->get_child(0)
                                  ->linked_node
                                  ->tlv
                                  ->value_length;

        // match param
        switch (be32toh(*param_id)) {
        // config user auth id
        case asn1::ParameterType::_pt_mink_auth_id:
            // user id - user auth id
            if (tmp_val_l <= sizeof(usr_id->user_id))
                memcpy(usr_id->user_id, tmp_val, tmp_val_l);
            // ok
            return 0;
        }
    }
    // err
    return 1;
}

void NewStream::run(gdt::GDTCallbackArgs *args) {
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);

    // create new instance of NewStream (think of it as forking)
    NewStream *new_stream = new NewStream();
    new_stream->config = config;
    new_stream->stream_next.cfg_res = &new_stream->ac_res;
    new_stream->stream_next.new_stream = new_stream;

    // set cfg user id pointer
    config::UserId *new_cfg_usr_id = &new_stream->cfg_user_id;
    asn1::ConfigMessage *c = NULL;

    // set events
    stream->set_callback(gdt::GDT_ET_STREAM_NEXT, &new_stream->stream_next);
    stream->set_callback(gdt::GDT_ET_STREAM_END, &new_stream->stream_done);
    stream->set_callback(gdt::GDT_ET_STREAM_TIMEOUT,
                         &new_stream->stream_done);

    // create cfg user id
    if (get_cfg_uid(new_cfg_usr_id, in_msg, *in_sess) > 0) {
        stream->end_sequence();
        return;
    }

    // check for body
    if (!in_msg->_body) {
        stream->end_sequence();
        return;
    }
    // check for ConfigMessage
    if (!in_msg->_body->_conf->has_linked_data(*in_sess)) {
        stream->end_sequence();
        return;
    }
    c = in_msg->_body->_conf;


    // User login
    if (c->_action
         ->linked_node
         ->tlv
         ->value[0] == asn1::ConfigAction::_ca_cfg_user_login) {
        new_stream->config_action = asn1::ConfigAction::_ca_cfg_user_login;
        // lock config mutex
        config->lock();
        // set new user
        config::UserInfo *usr_info = new config::UserInfo(config->get_definition_root());
        config->set_definition_wn(new_cfg_usr_id, usr_info);
        // process
        new_stream->process_user_login(args);

    // User logout
    } else if (c->_action
                ->linked_node
                ->tlv
                ->value[0] == asn1::ConfigAction::_ca_cfg_user_logout) {
        new_stream->config_action = asn1::ConfigAction::_ca_cfg_user_logout;
        // lock config mutex
        config->lock();
        // process
        new_stream->process_user_logout(args);

    // AC mode (TAB mode in CLI)
    } else if (c->_action
                ->linked_node
                ->tlv
                ->value[0] == asn1::ConfigAction::_ca_cfg_ac) {
        new_stream->ac_mode = config::CONFIG_ACM_TAB;
        new_stream->config_action = asn1::ConfigAction::_ca_cfg_ac;
        // lock config mutex
        config->lock();
        // check is user id exists
        config->update_definition_wn(new_cfg_usr_id);
        // process
        new_stream->process_tab(args);

    // SET mode (ENTER mode in CLI)
    } else if (c->_action
                ->linked_node
                ->tlv
                ->value[0] == asn1::ConfigAction::_ca_cfg_set) {
        new_stream->ac_mode = config::CONFIG_ACM_ENTER;
        new_stream->config_action = asn1::ConfigAction::_ca_cfg_set;
        // lock config mutex
        config->lock();
        // check is user id exists
        config->update_definition_wn(new_cfg_usr_id);
        // process
        new_stream->process_enter(args);

    // GET mode
    } else if (c->_action
                ->linked_node
                ->tlv
                ->value[0] == asn1::ConfigAction::_ca_cfg_get) {
        new_stream->config_action = asn1::ConfigAction::_ca_cfg_get;
        // lock config mutex
        config->lock();
        // check is user id exists
        config->update_definition_wn(new_cfg_usr_id);
        // process
        new_stream->process_get(args);

    // REPLICATE mode (action from other config daemon)
    } else if (c->_action
                ->linked_node
                ->tlv
                ->value[0] == asn1::ConfigAction::_ca_cfg_replicate) {
        new_stream->config_action = asn1::ConfigAction::_ca_cfg_replicate;
        // lock config mutex
        config->lock();
        // check is user id exists
        config->update_definition_wn(new_cfg_usr_id);
        // process
        new_stream->process_replicate(args);

    } else stream->end_sequence();

}

void NewStream::process_user_logout(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);

    // check if current user started transaction
    bool pretend = (config->get_transaction_owner() != cfg_user_id &&
                    config->transaction_started()
                        ? true
                        : false);
    if (!pretend) {
        // discard changes
        config->discard(config->get_definition_root());
        // end transaction
        config->end_transaction();
    }
    // remove user
    config->remove_wn_user(&cfg_user_id);

    // nothing more to do
    stream->end_sequence();
}

void NewStream::process_user_login(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);

    // nothing more to do
    stream->end_sequence();
}

// new stream, start sending config tree
void NewStream::process_replicate(gdt::GDTCallbackArgs *args) {
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    tmp_size = 0;
    res_size = 0;
    error_count = 0;
    err_index = -1;
    last_found = NULL;
    res_index = 0;
    ac_res.children.clear();
    char *tmp_val = NULL;
    int tmp_val_l = 0;
    line.clear();
    cm_mode = config::CONFIG_MT_UNKNOWN;
    asn1::ConfigMessage *c = NULL;
    asn1::Parameters *p = NULL;


    // check for body
    if (!in_msg->_body) goto process_lines;
    // check for config message
    if (!in_msg->_body->_conf->has_linked_data(*in_sess)) goto process_lines;
    c = in_msg->_body->_conf;
    // check for GET action
    if (c->_action
         ->linked_node
         ->tlv
         ->value[0] != asn1::ConfigAction::_ca_cfg_replicate) goto process_lines;
    // check for params part
    if (!c->_params) goto process_lines;
    if (!c->_params->has_linked_data(*in_sess)) goto process_lines;
    p = c->_params;

    // process params
    for (unsigned int i = 0; i < p->children.size(); i++) {
        // check for current session
        if (!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if (!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if (!p->get_child(i)
              ->_value
              ->has_linked_data(*in_sess)) continue;
        // check if child exists
        if (!p->get_child(i)->_value->get_child(0)) continue;
        // check if child exists in current
        // sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(*in_sess)) continue;

        // check param id, convert from big endian to
        // host
        uint32_t *param_id = (uint32_t *)p->get_child(i)
                                          ->_id
                                          ->linked_node
                                          ->tlv
                                          ->value;

        // set tmp values
        tmp_val = (char *)p->get_child(i)
                           ->_value
                           ->get_child(0)
                           ->linked_node
                           ->tlv
                           ->value;

        tmp_val_l = p->get_child(i)
                     ->_value
                     ->get_child(0)
                     ->linked_node
                     ->tlv
                      ->value_length;

        // match param
        switch (be32toh(*param_id)) {
            // config item path
            case asn1::ParameterType::_pt_mink_config_replication_line:
                line.append(tmp_val, tmp_val_l);
                break;
            }
    }

process_lines:
    // check if replication line was received
    if (line.size() == 0) return;
    // check if replication line was received
    // tokenize
    mink_utils::tokenize(&line, tmp_lst, 50, &tmp_size, true);
    // check for transaction owner
    bool pretend = (config->get_transaction_owner() != cfg_user_id &&
                            config->transaction_started()
                        ? true
                        : false);
    // auto complete
    config->auto_complete(&cm_mode,
                          config::CONFIG_ACM_ENTER,
                          config->get_cmd_tree(),
                          config->get_definition_wn(&cfg_user_id)->wnode,
                          tmp_lst,
                          tmp_size,
                          &ac_res,
                          &res_size,
                          &last_found,
                          &error_count,
                          tmp_err,
                          pretend,
                          &tmp_node_lst);

    // process results
    if (ac_res.children.size() == 0) goto free_nodes;
    // delete mode
    if (cm_mode == config::CONFIG_MT_DEL) {
        // single result
        if (ac_res.children.size() == 1) {
            // item
            if (ac_res.children[0]->node_type != config::CONFIG_NT_ITEM)
                goto free_nodes;
            if (pretend) goto free_nodes;
                // start transaction
                config->start_transaction(&cfg_user_id);
                // mark as deleted
                ac_res.children[0]->node_state = config::CONFIG_NS_DELETED;
                goto free_nodes;
        }

        // multiple results
        if (ac_res.children.size() == 0) goto free_nodes;

        config::ConfigItem *tmp_item = NULL;
        // check if parent is block item
        if (ac_res.children[0]->parent->node_type != config::CONFIG_NT_BLOCK)
            goto free_nodes;

        tmp_item = ac_res.children[0]->parent;
        // only allow deletion of template based node
        if (tmp_item->parent->children.size() <= 1) goto free_nodes;
        // check if template
        if (!tmp_item->parent->children[0]->is_template) goto free_nodes;

        // loop all template based nodes, try to match
        for (unsigned int i = 1; i < tmp_item->parent->children.size(); i++) {
            if (tmp_item->parent
                        ->children[i]
                        ->is_template) continue;

            if (tmp_item->parent->children[i] != tmp_item) continue;
            if (pretend) break;
            // start transaction
            config->start_transaction(&cfg_user_id);
            // mark as deleted
            tmp_item->parent
                    ->children[i]
                    ->node_state = config::CONFIG_NS_DELETED;
            break;
        }
        // cmd without params
    } else if (cm_mode == config::CONFIG_MT_CMD) {
        if (ac_res.children.size() < 1) goto free_nodes;

        // cmd without params
        if (ac_res.children[0]->node_type == config::CONFIG_NT_CMD) {
            if (ac_res.children[0]->name != "discard") goto free_nodes;
            if (pretend) goto free_nodes;
                // set current definition path to top level
                config->reset_all_wns();
                // regenerate cli path
                cli_path = "";
                // discard
                config->discard(config->get_definition_root());
                // end transaction
                config->end_transaction();

            // cmd with params
        } else if (ac_res.children[0]->node_type == config::CONFIG_NT_PARAM) {
            if (!ac_res.children[0]->parent) goto free_nodes;
            if (ac_res.children[0]->parent
                                  ->node_type != config::CONFIG_NT_CMD) goto free_nodes;

            if (ac_res.children[0]->parent->name == "commit") {
                if(pretend) goto free_nodes;
                if (config->commit(config->get_definition_root(),
                                   true) > 0) {
                    // set current definition path to
                    // top level
                    config->reset_all_wns();
                    // regenerate cli path
                    cli_path = "";
                    // get rollback count
                    DIR *dir;
                    int c = 0;
                    stringstream tmp_str;

                    dir = opendir("./commit-log");
                    // if dir
                    if (dir != NULL) {
                        dirent *ent;
                        // get dir contents
                        while ((ent = readdir(dir)) != NULL) {
                            if (strncmp(ent->d_name,
                                        ".rollback",
                                        9) == 0)
                                ++c;
                        }
                        // close dir
                        closedir(dir);
                    }

                    tmp_str << "./commit-log/.rollback."
                            << c
                            << ".pmcfg";
                    // save rollback
                    std::ofstream ofs(tmp_str.str().c_str(),
                                      std::ios::out | std::ios::binary);
                    if (ofs.is_open()) {
                        // save current config excluding
                        // uncommitted changes
                        config->show_config(config->get_definition_root(),
                                            0,
                                            &tmp_size,
                                            false,
                                            &ofs,
                                            true,
                                            &ac_res.children[0]->new_value);
                        ofs.close();

                        // prepare notifications
                        prepare_notifications();

                        // commit new configuration
                        config->commit(config->get_definition_root(), false);

                        // sort
                        config->sort(config->get_definition_root());

                        // end transaction
                        config->end_transaction();

                        // update current configuration
                        // contents file
                        std::ofstream orig_fs(((std::string *)mink::CURRENT_DAEMON->get_param(1))
                                                                                  ->c_str(),
                                              std::ios::out | std::ios::binary);
                        if (orig_fs.is_open()) {
                                config->show_config(config->get_definition_root(),
                                                    0,
                                                    &tmp_size,
                                                    false,
                                                    &orig_fs,
                                                    false,
                                                    NULL);
                                orig_fs.close();
                            }
                        }
                    }
                    // clear value
                    ac_res.children[0]->new_value = "";

                // rollback
            } else if (ac_res.children[0]->parent->name == "rollback") {
                if (pretend) goto free_nodes;
                if (ac_res.children[0]->new_value != "") {
                    std::string tmp_path;
                    std::stringstream istr(ac_res.children[0]->new_value);
                    int rev_num = -1;
                    istr >> rev_num;
                    bool rev_found = false;
                    dirent **fnames;

                    int n = scandir("./commit-log/",
                                    &fnames,
                                    mink_utils::_ac_rollback_revision_filter,
                                    mink_utils::_ac_rollback_revision_sort);
                    if (n > 0) {
                        for (int i = 0; i < n; i++) {
                            if (rev_num == i) {
                                rev_found = true;
                                tmp_path = "./commit-log/";
                                tmp_path.append(fnames[i]->d_name);
                            }
                            free(fnames[i]);
                        }
                        free(fnames);

                        // if revision found
                        if (!rev_found) goto rollback_clear_value;
                        tmp_size = 0;
                        // err check
                        tmp_size = mink_utils::get_file_size(tmp_path.c_str());
                        if (tmp_size == 0) {
                            // nothing

                        } else {
                            char *tmp_file_buff = new char[tmp_size + 1];
                            bzero(tmp_file_buff, tmp_size + 1);
                            mink_utils::load_file(tmp_path.c_str(),
                                                  tmp_file_buff,
                                                  &tmp_size);

                            antlr::MinkParser *pmp = antlr::create_parser();
                            pANTLR3_INPUT_STREAM input = pmp->input;
                            pminkLexer lxr = pmp->lexer;
                            pANTLR3_COMMON_TOKEN_STREAM tstream = pmp->tstream;
                            pminkParser psr = pmp->parser;
                            minkParser_inputConfig_return_struct ast_cfg;
                            config::ConfigItem *cfg_cnt = new config::ConfigItem();

                            // reset error state
                            lxr->pLexer->rec->state->errorCount = 0;
                            psr->pParser->rec->state->errorCount = 0;
                            input->reuse(input,
                                         (unsigned char *)tmp_file_buff,
                                         tmp_size,
                                         (unsigned char *)"file_"
                                                          "stream");

                            // token stream
                            tstream->reset(tstream);
                            // ast
                            ast_cfg = psr->inputConfig(psr);
                            // err check
                            int err_c = lxr->pLexer
                                           ->rec
                                           ->getNumberOfSyntaxErrors(lxr->pLexer->rec);
                            err_c += psr->pParser
                                        ->rec
                                        ->getNumberOfSyntaxErrors(psr->pParser->rec);
                            if (err_c > 0) {
                                // nothing
                            } else {

                                // set current
                                // definition path
                                // to top level
                                config->reset_all_wns();
                                // regenerate cli
                                // path
                                cli_path = "";

                                // get structure
                                antlr::process_config(ast_cfg.tree, cfg_cnt);
                                // validate
                                if (config->validate(config->get_definition_root(),
                                                     cfg_cnt)) {

                                    // prepare for
                                    // config data
                                    // replacement
                                    config->replace_prepare(config->get_definition_root());
                                    // merge new
                                    // data
                                    int res = config->merge(config->get_definition_root(),
                                                            cfg_cnt,
                                                            true);
                                    // err check
                                    if (res != 0) {
                                        // nothing
                                    } else {
                                        // prepare
                                        // notifications
                                        prepare_notifications();

                                        // commit
                                        // new
                                        // config
                                        config->commit(config->get_definition_root(),
                                                       false);

                                        // update
                                        // current
                                        // configuration
                                        // contents
                                        // file
                                        std::ofstream orig_fs(((std::string*)mink::CURRENT_DAEMON->get_param(1))
                                                                                                 ->c_str(),
                                                              std::ios::out | std::ios::binary);
                                        if (orig_fs.is_open()) {
                                            config->show_config(config->get_definition_root(),
                                                                0,
                                                                &tmp_size,
                                                                false,
                                                                &orig_fs,
                                                                false,
                                                                NULL);
                                            orig_fs.close();
                                        }
                                        // sort
                                        config->sort(config->get_definition_root());

                                        // end
                                        // transaction
                                        config->end_transaction();
                                    }
                                }
                            }
                            // free mem
                            delete cfg_cnt;
                            delete[] tmp_file_buff;
                            antlr::free_mem(pmp);
                        }

                    }
                }
rollback_clear_value:
                // clear value
                ac_res.children[0]->new_value = "";
            }
        }

    } else if (cm_mode == config::CONFIG_MT_SET) {
        // do nothing, errors already present in tmp_err
        if (!pretend) {
            config->start_transaction(&cfg_user_id);
        }
    }
free_nodes:
    // free temp nodes and clear res buffer
    ac_res.children.clear();
    for (unsigned int i = 0; i < tmp_node_lst.children.size(); i++)
        delete tmp_node_lst.children[i];
    tmp_node_lst.children.clear();
}

// new stream, start sending config tree
void NewStream::process_get(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    gdt::GDTClient *client = stream->get_client();
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    bool *include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_BODY);
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    tmp_size = 0;
    res_size = 0;
    error_count = 0;
    err_index = -1;
    last_found = NULL;
    res_index = 0;
    ac_res.children.clear();
    char *tmp_val = NULL;
    int tmp_val_l = 0;
    bool cfg_notify = false;
    asn1::ConfigMessage *c = NULL;
    asn1::Parameters *p = NULL;
    line.clear();

    // check for body
    if (!in_msg->_body) goto process_lines;
     // check for config message
    if (!in_msg->_body->_conf->has_linked_data(*in_sess)) goto process_lines;
    c = in_msg->_body->_conf;
    // check for GET action
    if (c->_action
         ->linked_node
         ->tlv
         ->value[0] != asn1::ConfigAction::_ca_cfg_get) goto process_lines;

    // check for params part
    if (!c->_params) goto process_lines;
    if (!c->_params->has_linked_data(*in_sess)) goto process_lines;
    p = c->_params;

    // process params
    for (unsigned int i = 0; i < p->children.size(); i++) {
        // check for current session
        if (!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if (!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if (!p->get_child(i)
              ->_value
              ->has_linked_data(*in_sess)) continue;
        // check if child exists
        if (!p->get_child(i)
              ->_value
              ->get_child(0)) continue;
        // check if child exists in current
        // sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(*in_sess)) continue;

        // check param id, convert from big endian to
        // host
        uint32_t *param_id = (uint32_t *)p->get_child(i)
                                          ->_id
                                          ->linked_node
                                          ->tlv
                                          ->value;
        // set tmp values
        tmp_val = (char *)p->get_child(i)
                           ->_value
                           ->get_child(0)
                           ->linked_node
                           ->tlv
                           ->value;

        tmp_val_l = p->get_child(i)
                     ->_value
                     ->get_child(0)
                     ->linked_node
                     ->tlv
                     ->value_length;

        // match param
        switch (be32toh(*param_id)) {
            // config item path
            case asn1::ParameterType::_pt_mink_config_cfg_item_path:
                line.append(tmp_val, tmp_val_l);
                break;

            // config item notification flag
            case asn1::ParameterType::_pt_mink_config_cfg_item_notify:
                cfg_notify = (tmp_val[0] == 1);
                break;
            }
    }

process_lines:
    // check if config item path item was received
    if (line.size() == 0) {
        stream->end_sequence();
        return;
    }

    // prepare body
    if (gdtm->_body != NULL) {
        gdtm->_body->unlink(1);
        gdtm->_body->_conf->set_linked_data(1);

    } else {
        gdtm->set_body();
        gdtm->prepare();
    }

    // remove payload
    if (gdtm->_body->_conf->_payload != NULL)
        gdtm->_body->_conf->_payload->unlink(1);
    // set params
    if (gdtm->_body->_conf->_params == NULL) {
        gdtm->_body->_conf->set_params();
        p = gdtm->_body->_conf->_params;
        // set children, allocate more
        for (int i = 0; i < 1; i++) {
            p->set_child(i);
            p->get_child(i)->set_value();
            p->get_child(i)->_value->set_child(0);
        }
        // prepare
        gdtm->prepare();

        // unlink params before setting new ones
    } else {
        p = gdtm->_body->_conf->_params;
        int cc = p->children.size();
        if (cc < 1) {
            // set children, allocate more
            for (int i = cc; i < 1; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

        } else if (cc > 1) {
            // remove extra children if used in some other session, only 2
            // needed
            for (int i = 1; i < cc; i++) p->get_child(i)->unlink(1);
        }
    }

    // check if user requested node exists
    config::ConfigItem *tmp_cfg_root = (*config->get_definition_root())(line.c_str());
    // node exists
    if (tmp_cfg_root != NULL) {
        // set node notification
        if (cfg_notify) {
            // check if notification exists
            config::CfgNotification *cfg_ntf = config->get_notification(&line);
            if (cfg_ntf == NULL) {
                // create new notification handler
                cfg_ntf = new config::GDTCfgNotification(&line);
                config->add_notification(cfg_ntf);
            }

            // create ntf user id
            config::GDTCfgNtfUser ntf_usr(client);
            if (in_msg->_header->_source->_id != NULL) {
                if (in_msg->_header->_source->_id->has_linked_data(*in_sess)) {
                    tmp_val = (char *)in_msg->_header
                                            ->_source
                                            ->_id
                                            ->linked_node
                                            ->tlv
                                            ->value;
                    tmp_val_l = in_msg->_header
                                      ->_source
                                      ->_id
                                      ->linked_node
                                      ->tlv
                                      ->value_length;
                    std::string tmp_str(tmp_val, tmp_val_l);
                    // set registered user id
                    if (tmp_str.size() <= sizeof(ntf_usr.user_id))
                        memcpy(ntf_usr.user_id,
                               tmp_str.c_str(),
                               tmp_str.size());
                }
            }
            // set registered user type
            tmp_val = (char *)in_msg->_header
                                    ->_source
                                    ->_type
                                    ->linked_node
                                    ->tlv
                                    ->value;
            tmp_val_l = in_msg->_header
                              ->_source
                              ->_type
                              ->linked_node
                              ->tlv
                              ->value_length;
            std::string tmp_str(tmp_val, tmp_val_l);
            if (tmp_str.size() <= sizeof(ntf_usr.user_type))
                memcpy(ntf_usr.user_type, tmp_str.c_str(), tmp_str.size());

            // unregister user if previously registered
            cfg_ntf->unreg_user(&ntf_usr);
            // register new node user
            cfg_ntf->reg_user(&ntf_usr);
        }

        // flatten node structure to list
        config::Config::flatten(tmp_cfg_root, &ac_res);
        // get result size, convert to big endian
        ac_res_count = htobe32(ac_res.children.size());

        // set result action
        gdtm->_body
            ->_conf
            ->_action
            ->set_linked_data(1, (unsigned char *)&ca_cfg_result, 1);
        // cfg item count
        gdtm->_body
            ->_conf
            ->_params
            ->get_child(0)
            ->_id
            ->set_linked_data(1,
                              (unsigned char *)&stream_next.pt_cfg_item_count,
                              sizeof(uint32_t));
        gdtm->_body
            ->_conf
            ->_params
            ->get_child(0)
            ->_value
            ->get_child(0)
            ->set_linked_data(1,
                              (unsigned char *)&ac_res_count,
                              sizeof(uint32_t));

        // include bodu
        *include_body = true;
        // continue
        stream->continue_sequence();

        if (ac_res.children.size() == 0)
            stream->end_sequence();

        // node does not exist
    } else {
        // node does not exist
        stream->end_sequence();
    }
}

// prepare notifictions
void NewStream::prepare_notifications() {
    // ****** notify *************
    // flatten node structure to list
    config::ConfigItem tmp_res;
    config::Config::flatten(config->get_definition_root(), &tmp_res);
    // remove unmodified nodes, only interested in modified nodes
    unsigned int i = 0;
    while (i < tmp_res.children.size()) {
        if (tmp_res.children[i]->node_state == config::CONFIG_NS_READY)
            tmp_res.children.erase(tmp_res.children.begin() + i);
        else
            ++i;
    }

    config::ConfigItem *tmp_item = NULL;
    bool exists;
    std::string tmp_full_path;
    std::string tmp_str;
    // loop list
    for (unsigned int i = 0; i < tmp_res.children.size(); i++) {
        tmp_item = tmp_res.children[i];
        // check if node has been modified
        if (tmp_item->node_state != config::CONFIG_NS_READY) {
            // get full node path
            config::Config::get_parent_line(tmp_item, &tmp_full_path);
            tmp_full_path.append(tmp_item->name);

            // get users (check parent nodes)
            while (tmp_item != NULL) {
                // get notification
                config::Config::get_parent_line(tmp_item, &tmp_str);
                tmp_str.append(tmp_item->name);
                config::CfgNotification *cfg_ntf = config->get_notification(&tmp_str);
                // user found
                if (cfg_ntf != NULL) {
                    // gdt notification
                    config::GDTCfgNotification *gdtn = (config::GDTCfgNotification *)cfg_ntf;
                    // add to notification list
                    config::ConfigItem *new_cfg_item = new config::ConfigItem();
                    new_cfg_item->name = tmp_full_path;
                    new_cfg_item->value = tmp_res.children[i]->new_value;
                    new_cfg_item->node_state = tmp_res.children[i]->node_state;
                    new_cfg_item->node_type = tmp_res.children[i]->node_type;
                    gdtn->ntf_cfg_lst.children.push_back(new_cfg_item);
                    // ready to send
                    gdtn->ready = true;

                    // check if client was already added to notification client
                    // list
                    exists = false;
                    for (unsigned int j = 0; j < stream_done.ntfy_lst.size();
                         j++)
                        if (stream_done.ntfy_lst[j] == gdtn) {
                            exists = true;
                            break;
                        }
                    // add to list if needed, notifications processed after
                    // commit (Stream done event)
                    if (!exists)
                        stream_done.ntfy_lst.push_back(gdtn);
                }
                // level up (parent)
                tmp_item = tmp_item->parent;
            }
        }
    }

    tmp_res.children.clear();
    // ****** notify *************
}

// new stream, send auto completed line in first packet
void NewStream::process_enter(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    gdt::GDTClient *client = stream->get_client();
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    bool *include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_BODY);
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    tmp_size = 0;
    res_size = 0;
    error_count = 0;
    err_index = -1;
    last_found = NULL;
    res_index = 0;
    line_stream_lc = 0;
    cm_mode = config::CONFIG_MT_UNKNOWN;
    tmp_node_lst.children.clear();
    ac_res.children.clear();
    line_stream.str("");
    line_stream.clear();
    line_stream.seekg(0, std::ios::beg);
    char *tmp_val = NULL;
    int tmp_val_l = 0;
    asn1::ConfigMessage *c = NULL;
    asn1::Parameters *p = NULL;

    // current path
    cli_path = "";
    config->generate_path(config->get_definition_wn(&cfg_user_id)->wnode,
                          &cli_path);

    // prepare body
    if (gdtm->_body != NULL) {
        gdtm->_body->unlink(1);
        gdtm->_body->_conf->set_linked_data(1);

    } else {
        gdtm->set_body();
        gdtm->prepare();
    }
    c = gdtm->_body->_conf;

    // remove payload
    if (c->_payload != NULL)
        c->_payload->unlink(1);
    // set params
    if (c->_params == NULL) {
        c->set_params();
        p = gdtm->_body->_conf->_params;
        // set children, allocate more
        for (int i = 0; i < 5; i++) {
            p->set_child(i);
            p->get_child(i)->set_value();
            p->get_child(i)->_value->set_child(0);
        }
        // prepare
        gdtm->prepare();

        // unlink params before setting new ones
    } else {
        p = c->_params;
        int cc = p->children.size();
        if (cc < 5) {
            // set children, allocate more
            for (int i = cc; i < 5; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

        } else if (cc > 5) {
            // remove extra children if used in some other session, only 2
            // needed
            for (int i = 5; i < cc; i++) p->get_child(i)->unlink(1);
        }
    }

    // get line
    if (!in_msg->_body) goto process_tokens;
    // check for config message
    if (!c->has_linked_data(*in_sess)) goto process_tokens;
    // check for params part
    if (!c->_params) goto process_tokens;
    if (!c->_params->has_linked_data(*in_sess)) goto process_tokens;
    p = c->_params;

    // process params
    for (unsigned int i = 0; i < p->children.size(); i++) {
        // check for current session
        if (!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if (!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if (!p->get_child(i)->_value->has_linked_data(*in_sess)) continue;
        // check if child exists
        if (!p->get_child(i)->_value->get_child(0)) continue;
        // check if child exists in current
        // sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(*in_sess)) continue;



            // check param id, convert from big endian to host
            uint32_t *param_id = (uint32_t *)p->get_child(i)
                                              ->_id
                                              ->linked_node
                                              ->tlv
                                              ->value;
            // set tmp values
            tmp_val = (char *)p->get_child(i)
                               ->_value
                               ->get_child(0)
                               ->linked_node
                               ->tlv
                               ->value;
            tmp_val_l = p->get_child(i)
                         ->_value
                         ->get_child(0)
                         ->linked_node
                         ->tlv
                         ->value_length;

            // match param
            switch (be32toh(*param_id)) {
                // config item count
                case asn1::ParameterType::_pt_mink_config_ac_line:
                    line.clear();
                    line.append(tmp_val, tmp_val_l);
                    mink::CURRENT_DAEMON->log(mink::LLT_DEBUG,
                                             "cmd line received: [%s]",
                                              line.c_str());
                    break;
            }
    }

process_tokens:
    // tokenize
    mink_utils::tokenize(&line, tmp_lst, 50, &tmp_size, true);
    // pretend
    bool pretend = (config->get_transaction_owner() != cfg_user_id &&
                    config->transaction_started()
                        ? true
                        : false);

    // auto complete
    config->auto_complete(&cm_mode,
                          config::CONFIG_ACM_ENTER,
                          config->get_cmd_tree(),
                          config->get_definition_wn(&cfg_user_id)->wnode,
                          tmp_lst,
                          tmp_size,
                          &ac_res,
                          &res_size,
                          &last_found,
                          &error_count,
                          tmp_err,
                          pretend,
                          &tmp_node_lst);

    if (pretend) {
        switch (cm_mode) {
        case config::CONFIG_MT_SET:
        case config::CONFIG_MT_EDIT:
        case config::CONFIG_MT_DEL:
            tmp_err[error_count].clear();
            tmp_err[error_count].assign("Transaction started by other user, "
                                        "cannot execute intrusive operation!");
            ++error_count;
            break;

        default:
            break;
        }
    }

    // replace current line with auto completed values
    line.clear();
    for (int i = 0; i < tmp_size; i++) {
        line.append(tmp_lst[i]);
        if (i < res_size)
            line.append(" ");
        else
            break;
    }

    // process results
    if (ac_res.children.size() == 0) goto set_values;
    // delete mode
    if (cm_mode == config::CONFIG_MT_DEL) {
        // single result
        if (ac_res.children.size() == 1) {
            // check if single item is really only one ITEM node (last one
            // from input and one from ac_res should match)
            if (tmp_lst[tmp_size - 1] == ac_res.children[ac_res.children.size() - 1]->name) {
                // item
                if (ac_res.children[0]->node_type == config::CONFIG_NT_ITEM) {
                if(pretend) goto set_values;
                    // start transaction
                    config->start_transaction(&cfg_user_id);
                    // mark as deleted
                    ac_res.children[0]->node_state = config::CONFIG_NS_DELETED;
                    // replicate
                    std::vector<std::string *> *cfg_daemons =
                        (std::vector<std::string *> *)mink::CURRENT_DAEMON->get_param(2);
                    for (unsigned int i = 0; i < cfg_daemons->size(); i++) {
                        config::replicate(line.c_str(),
                                          client->get_session()
                                                 ->get_registered_client("routingd"),
                                          (*cfg_daemons)[i]->c_str(), &cfg_user_id);
                    }

                } else if (ac_res.children[0]->node_type == config::CONFIG_NT_BLOCK) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].append("Cannot delete non template block node \"");
                    tmp_err[error_count].append(ac_res.children[0]->parent->name);
                    tmp_err[error_count].append("\"!");
                    ++error_count;
                }
                // check if single item is in fact only single child of
                // template node that was set for deletion
            } else {
                config::ConfigItem *tmp_item = NULL;
                // check if parent is block item
                if (ac_res.children[0]->parent->node_type != config::CONFIG_NT_BLOCK) goto set_values;
                tmp_item = ac_res.children[0]->parent;
                // only allow deletion of template based node
                if (!tmp_item->parent) goto set_values;
                if (tmp_item->parent->children.size() <= 1) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].append("Cannot delete non template block node \"");
                    tmp_err[error_count].append(ac_res.children[0]->parent->name);
                    tmp_err[error_count].append("\"!");
                    ++error_count;
                    goto set_values;
                }

                // check if template
                if (!tmp_item->parent->children[0]->is_template) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].append("Cannot delete non template block node \"");
                    tmp_err[error_count].append(ac_res.children[0]->parent->name);
                    tmp_err[error_count].append("\"!");
                    ++error_count;
                    goto set_values;
                }

                // loop all template based nodes, try to
                // match
                for (unsigned int i = 1; i < tmp_item->parent->children.size(); i++){
                    if (tmp_item->parent->children[i]->is_template) continue;
                    if (tmp_item->parent->children[i] != tmp_item) continue;
                    if(pretend) break;
                    // start transaction
                    config->start_transaction(&cfg_user_id);
                    // mark as deleted
                    tmp_item->parent
                            ->children[i]
                            ->node_state = config::CONFIG_NS_DELETED;
                    // replicate
                    std::vector<std::string *> *cfg_daemons =
                        (std::vector<std::string *>*)mink::CURRENT_DAEMON->get_param(2);
                    for (unsigned int i = 0; i < cfg_daemons->size(); i++) {
                        config::replicate(line.c_str(),
                                          client->get_session()
                                                ->get_registered_client("routingd"),
                                          (*cfg_daemons)[i]->c_str(),
                                          &cfg_user_id);
                    }
                }
            }

            // multiple results
        } else if (ac_res.children.size() > 0) {
            config::ConfigItem *tmp_item = NULL;
            // check if parent is block item
            if (ac_res.children[0]->parent
                                  ->node_type != config::CONFIG_NT_BLOCK) goto set_values;

            tmp_item = ac_res.children[0]->parent;
             // only allow deletion of template based node
            if (!tmp_item->parent) goto set_values;
            if (tmp_item->parent->children.size() >= 1) {
                tmp_err[error_count].clear();
                tmp_err[error_count].append("Cannot delete non template block node \"");
                tmp_err[error_count].append(ac_res.children[0]->parent->name);
                tmp_err[error_count].append("\"!");
                ++error_count;
                goto set_values;

            }
            // check if template
            if (!tmp_item->parent->children[0]->is_template) {
                tmp_err[error_count].clear();
                tmp_err[error_count].append("Cannot delete non template block node \"");
                tmp_err[error_count].append(ac_res.children[0]->parent->name);
                tmp_err[error_count].append("\"!");
                ++error_count;
                goto set_values;
            }

            // loop all template based nodes, try to match
            for (unsigned int i = 1; i < tmp_item->parent->children.size(); i++) {
                if (tmp_item->parent->children[i]->is_template) continue;
                if (tmp_item->parent->children[i] != tmp_item) continue;
                if(pretend) break;

                // start transaction
                config->start_transaction(&cfg_user_id);
                // mark as deleted
                tmp_item->parent
                        ->children[i]
                        ->node_state = config::CONFIG_NS_DELETED;
                // replicate
                std::vector<std::string*> *cfg_daemons =
                    (std::vector<std::string *>*)mink::CURRENT_DAEMON->get_param(2);
                for (unsigned int i = 0; i < cfg_daemons->size(); i++) {
                    config::replicate(line.c_str(),
                                      client->get_session()
                                            ->get_registered_client( "routingd"),
                                      (*cfg_daemons)[i]->c_str(),
                                      &cfg_user_id);
                }
                break;
            }
       }

        // special commands
    } else if (cm_mode == config::CONFIG_MT_CMD) {
        if (ac_res.children.size() < 1) goto set_values;

        // cmd without params
        if (ac_res.children[0]->node_type == config::CONFIG_NT_CMD) {
            if (ac_res.children[0]->name == "configuration") {
                int tmp_size = 0;
                // get date size
                line_stream_lc = config->get_config_lc(config->get_definition_wn(&cfg_user_id)->wnode);
                // get data
                config->show_config(config->get_definition_wn(&cfg_user_id)->wnode,
                                    0,
                                    &tmp_size,
                                    false,
                                    &line_stream);

            } else if (ac_res.children[0]->name == "commands") {
                // get date size
                line_stream_lc = config->get_commands_lc(config->get_definition_wn(&cfg_user_id)->wnode);
                // get data
                config->show_commands(config->get_definition_wn(&cfg_user_id)->wnode,
                                      0,
                                      &line_stream);

            } else if (ac_res.children[0]->name == "top") {
                if (!pretend) {
                    // set current cfg path
                    config->get_definition_wn(&cfg_user_id)->wnode =
                        config->get_definition_root();

                    // regenerate cli path
                    cli_path = "";

                } else {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign(
                        "Transaction started by other user, cannot "
                        "execute intrusive operation!");
                    ++error_count;
                }

            } else if (ac_res.children[0]->name == "up") {
                if (!pretend) {
                    if (!config->get_definition_wn(&cfg_user_id)
                               ->wnode->parent) goto set_values;

                    // set current cfg path
                    config->get_definition_wn(&cfg_user_id)->wnode =
                        config->get_definition_wn(&cfg_user_id)
                              ->wnode->parent;

                    // regenerate cli path
                    cli_path = "";

                    // generate cfg path
                    config->generate_path(config->get_definition_wn(&cfg_user_id)->wnode,
                                          &cli_path);

                } else {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign(
                        "Transaction started by other user, cannot "
                        "execute intrusive operation!");
                    ++error_count;
                }
            } else if (ac_res.children[0]->name == "discard") {
                if (!pretend) {
                    // set current definition path to top level
                    config->reset_all_wns();

                    // regenerate cli path
                    cli_path = "";

                    // generate prompt
                    config->discard(config->get_definition_root());

                    // end transaction
                    config->end_transaction();

                    // replicate
                    std::vector<std::string *> *cfg_daemons =
                        (std::vector<std::string *> *)mink::CURRENT_DAEMON->get_param(2);
                    for (unsigned int i = 0; i < cfg_daemons->size(); i++) {
                        config::replicate(line.c_str(),
                                         client->get_session()
                                               ->get_registered_client("routingd"),
                                         (*cfg_daemons)[i]->c_str(),
                                         &cfg_user_id);
                    }

                } else {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign(
                        "Transaction started by other user, cannot "
                        "execute intrusive operation!");
                    ++error_count;
                }
            }
            // cmd with params
        } else if (ac_res.children[0]->node_type == config::CONFIG_NT_PARAM) {
            if (!ac_res.children[0]->parent) goto set_values;
            if (ac_res.children[0]->parent->node_type != config::CONFIG_NT_CMD)
                goto set_values;
            if (ac_res.children[0]->parent->name == "commit") {
                if(pretend){
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign(
                        "Transaction started by other user, "
                        "cannot execute intrusive operation!");
                    ++error_count;
                    goto set_values;
                }
                if (config->commit(config->get_definition_root(),
                                   true) > 0) {
                    // set current definition path to top
                    // level
                    config->reset_all_wns();

                    // regenerate cli path
                    cli_path = "";

                    // generate prompt

                    // get rollback count
                    DIR *dir;
                    int c = 0;
                    stringstream tmp_str;

                    dir = opendir("./commit-log");
                    // if dir
                    if (dir != NULL) {
                        dirent *ent;
                        // get dir contents
                        while ((ent = readdir(dir)) != NULL) {
                            if (strncmp(ent->d_name,
                                        ".rollback",
                                        9) == 0)
                                ++c;
                        }
                        // close dir
                        closedir(dir);
                    }

                    tmp_str << "./commit-log/.rollback." << c
                            << ".pmcfg";
                    // save rollback
                    std::ofstream ofs(tmp_str.str().c_str(),
                                      std::ios::out | std::ios::binary);
                    if (ofs.is_open()) {
                        // save current config excluding
                        // uncommitted changes
                        config->show_config(config->get_definition_root(),
                                            0,
                                            &tmp_size,
                                            false,
                                            &ofs,
                                            true,
                                            &ac_res.children[0]->new_value);
                        ofs.close();

                        // prepare notifications
                        prepare_notifications();

                        // commit new configuration
                        config->commit(config->get_definition_root(),
                                       false);

                        // sort
                        config->sort(config->get_definition_root());

                        // update current configuration
                        // contents file
                        std::ofstream orig_fs(
                            ((std::string *) mink::CURRENT_DAEMON->get_param(1))
                                                                 ->c_str(),
                            std::ios::out | std::ios::binary);
                        if (orig_fs.is_open()) {
                            config->show_config(config->get_definition_root(),
                                                0,
                                                &tmp_size,
                                                false,
                                                &orig_fs,
                                                false,
                                                NULL);
                            orig_fs.close();
                        }

                        // end transaction
                        config->end_transaction();

                        // replicate
                        std::vector<std::string *> *cfg_daemons =
                            (std::vector<std::string *> *)mink::CURRENT_DAEMON->get_param(2);
                        for (unsigned int i = 0; i < cfg_daemons->size(); i++) {
                            config::replicate(line.c_str(),
                                             client->get_session()
                                                   ->get_registered_client("routingd"),
                                            (*cfg_daemons)[i]->c_str(),
                                            &cfg_user_id);
                        }

                    } else {
                        tmp_err[error_count].clear();
                        tmp_err[error_count].assign("Cannot create rollback "
                                                    "configuration!");
                        ++error_count;
                    }
                }
                // clear value
                ac_res.children[0]->new_value = "";

                // rollback
            } else if (ac_res.children[0]->parent->name == "rollback") {
                std::string tmp_path;
                std::stringstream istr(ac_res.children[0]->new_value);
                int rev_num = -1;
                istr >> rev_num;
                bool rev_found = false;
                dirent **fnames;

                int n = scandir("./commit-log/", &fnames,
                                mink_utils::_ac_rollback_revision_filter,
                                mink_utils::_ac_rollback_revision_sort);


                if(pretend){
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign(
                        "Transaction started by other user, "
                        "cannot execute intrusive operation!");
                    ++error_count;
                    goto set_values;
                }

                if (ac_res.children[0]->new_value == "") {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign(
                        "Rollback revision not defined!");
                    ++error_count;
                    goto rollback_clear_value;

                }

                if (n <= 0) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign("Cannot find rollback "
                                                "information!");
                    ++error_count;
                    goto rollback_clear_value;

                }

                for (int i = 0; i < n; i++) {
                    if (rev_num == i) {
                        rev_found = true;
                        tmp_path = "./commit-log/";
                        tmp_path.append(fnames[i]->d_name);
                    }
                    free(fnames[i]);
                }
                free(fnames);

                // no revision found
                if (!rev_found) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].append("Cannot find rollback "
                                                "revision '");
                    tmp_err[error_count].append(ac_res.children[0]->new_value);
                    tmp_err[error_count].append("'!");
                    ++error_count;
                    goto rollback_clear_value;
                }

                tmp_size = 0;
                // err check
                tmp_size = mink_utils::get_file_size(tmp_path.c_str());
                if (tmp_size == 0) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].append("Cannot find rollback "
                                                "revision '");
                    tmp_err[error_count].append(tmp_path);
                    tmp_err[error_count].append("'!");
                    ++error_count;

                } else {
                    char *tmp_file_buff = new char[tmp_size + 1];
                    bzero(tmp_file_buff, tmp_size + 1);
                    mink_utils::load_file(tmp_path.c_str(),
                                          tmp_file_buff,
                                          &tmp_size);
                    line_stream << "Loading rollback "
                                   "configuration..."
                                << std::endl;
                    ++line_stream_lc;

                    antlr::MinkParser *pmp = antlr::create_parser();
                    pANTLR3_INPUT_STREAM input = pmp->input;
                    pminkLexer lxr = pmp->lexer;
                    pANTLR3_COMMON_TOKEN_STREAM tstream = pmp->tstream;
                    pminkParser psr = pmp->parser;
                    minkParser_inputConfig_return_struct ast_cfg;
                    config::ConfigItem *cfg_cnt = new config::ConfigItem();

                    // reset error state
                    lxr->pLexer->rec->state->errorCount = 0;
                    psr->pParser->rec->state->errorCount = 0;
                    input->reuse(input,
                                 (unsigned char *)tmp_file_buff,
                                 tmp_size,
                                 (unsigned char *)"file_stream");

                    // token stream
                    tstream->reset(tstream);
                    // ast
                    ast_cfg = psr->inputConfig(psr);
                    // err check
                    int err_c = lxr->pLexer
                                   ->rec
                                  ->getNumberOfSyntaxErrors(lxr->pLexer->rec);
                    err_c += psr->pParser
                                 ->rec
                                 ->getNumberOfSyntaxErrors(psr->pParser->rec);
                    if (err_c > 0) {
                        tmp_err[error_count].clear();
                        tmp_err[error_count].assign("Invalid "
                                                    "rollback "
                                                    "configuration "
                                                    "file syntax!");
                        ++error_count;
                    } else {
                        line_stream << "Done" << std::endl;
                        ++line_stream_lc;

                        // set current
                        // definition path to
                        // top level
                        config->reset_all_wns();

                        // regenerate cli path
                        cli_path = "";

                        // get structure
                        antlr::process_config(ast_cfg.tree,
                                              cfg_cnt);
                        // validate
                        if (!config->validate(config->get_definition_root(),
                                              cfg_cnt)) {
                            tmp_err[error_count].clear();
                            tmp_err[error_count].assign(
                                "Invalid/undefined "
                                "rollback configuration "
                                "file contents!");
                            ++error_count;
                            goto rollback_free_parser;

                        }

                        // prepare for
                        // config data
                        // replacement
                        config->replace_prepare(config->get_definition_root());
                        // merge new data
                        line_stream << "Merging "
                                       "rollback "
                                       "configurati"
                                       "on file..."
                                    << std::endl;
                        ++line_stream_lc;
                        int res = config->merge(config->get_definition_root(),
                                                cfg_cnt,
                                                true);
                        // err check
                        if (res != 0) {
                            tmp_err[error_count].clear();
                            tmp_err[error_count].assign("Cannot merge "
                                                        "configuration"
                                                        " file contents!");
                            ++error_count;
                        } else {
                            line_stream << "Done"
                                        << std::endl;
                            line_stream
                                << "Committing rollback"
                                << " configuration..."
                                << std::endl;
                            line_stream_lc += 2;

                            // prepare
                            // notifications
                            prepare_notifications();

                            // commit new
                            // config
                            config->commit(config->get_definition_root(),
                                           false);

                            // update
                            // current
                            // configuration
                            // contents file
                            std::ofstream orig_fs(((std::string *)mink::CURRENT_DAEMON->get_param(1))
                                                                                      ->c_str(),
                                                  std::ios::out | std::ios::binary);
                            if (orig_fs.is_open()) {
                                config->show_config(config->get_definition_root(),
                                                    0,
                                                    &tmp_size,
                                                    false,
                                                    &orig_fs,
                                                    false,
                                                    NULL);
                                orig_fs.close();
                            }

                            // sort
                            config->sort(config->get_definition_root());

                            // end
                            // transaction
                            config->end_transaction();

                            // replicate
                            std::vector<std::string*> *cfg_daemons =
                                (std::vector<std::string *> *)mink::CURRENT_DAEMON->get_param(2);
                            for (unsigned int i = 0; i < cfg_daemons->size(); i++) {
                                config::replicate(line.c_str(),
                                                  client->get_session()
                                                        ->get_registered_client("routingd"),
                                                  (*cfg_daemons)[i]->c_str(),
                                                  &cfg_user_id);
                            }
                            line_stream << "Done"
                                        << std::endl;
                            ++line_stream_lc;
                        }

                    }

rollback_free_parser:
                    // free mem
                    delete cfg_cnt;
                    delete[] tmp_file_buff;
                    antlr::free_mem(pmp);
                }


rollback_clear_value:
                // clear value
                ac_res.children[0]->new_value = "";

                // save conf
            } else if (ac_res.children[0]->parent->name == "save") {
                if (ac_res.children[0]->new_value == "") {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign("Filename not defined!");
                    ++error_count;
                    goto set_values;
                }

                std::ofstream ofs(ac_res.children[0]->new_value.c_str(),
                                  std::ios::out | std::ios::binary);
                if (ofs.is_open()) {
                    line_stream << "Saving configuration to \""
                                << ac_res.children[0]->new_value << "\"..."
                                << std::endl;
                    ++line_stream_lc;
                    config->show_config(config->get_definition_wn(&cfg_user_id)->wnode,
                                        0,
                                        &tmp_size,
                                        false,
                                        &ofs,
                                        false,
                                        NULL);
                    ofs.close();
                    line_stream << "Done" << std::endl;
                    ++line_stream_lc;

                } else {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].append("Cannot create file \"");
                    tmp_err[error_count].append(ac_res.children[0]->new_value);
                    tmp_err[error_count].append("\"");
                    ++error_count;
                }

                // clear value
                ac_res.children[0]->new_value = "";

                // load conf
            } else if (ac_res.children[0]->parent->name == "load") {
                if (pretend) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign(
                        "Transaction started by other user, "
                        "cannot execute intrusive operation!");
                    ++error_count;
                    goto set_values;
                }

                if (ac_res.children[0]->new_value == "") {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].assign("Filename not defined!");
                    ++error_count;
                    goto set_values;

                }

                tmp_size = 0;
                // err
                tmp_size = mink_utils::get_file_size(ac_res.children[0]->new_value.c_str());
                if (tmp_size == 0) {
                    tmp_err[error_count].clear();
                    tmp_err[error_count].append("Cannot find file \"");
                    tmp_err[error_count].append(ac_res.children[0]->new_value);
                    tmp_err[error_count].append("\"");
                    ++error_count;

                } else {
                    char *tmp_file_buff = new char[tmp_size + 1];
                    bzero(tmp_file_buff, tmp_size + 1);
                    mink_utils::load_file(ac_res.children[0]->new_value.c_str(),
                                          tmp_file_buff, &tmp_size);
                    line_stream << "Loading new configuration "
                                   "file \""
                                << ac_res.children[0]->new_value << "\"..."
                                << std::endl;
                    ++line_stream_lc;

                    antlr::MinkParser *pmp = antlr::create_parser();
                    pANTLR3_INPUT_STREAM input = pmp->input;
                    pminkLexer lxr = pmp->lexer;
                    pANTLR3_COMMON_TOKEN_STREAM tstream = pmp->tstream;
                    pminkParser psr = pmp->parser;
                    minkParser_inputConfig_return_struct ast_cfg;
                    config::ConfigItem *cfg_cnt = new config::ConfigItem();

                    // reset error state
                    lxr->pLexer->rec->state->errorCount = 0;
                    psr->pParser->rec->state->errorCount = 0;
                    input->reuse(input,
                                 (unsigned char *)tmp_file_buff,
                                 tmp_size,
                                 (unsigned char *)"file_stream");

                    // token stream
                    tstream->reset(tstream);
                    // ast
                    ast_cfg = psr->inputConfig(psr);
                    int res = 0;
                    // err check
                    int err_c = lxr->pLexer
                                   ->rec
                                   ->getNumberOfSyntaxErrors(lxr->pLexer->rec);
                    err_c += psr->pParser
                                ->rec
                                ->getNumberOfSyntaxErrors(psr->pParser->rec);

                    if (err_c > 0) {
                        tmp_err[error_count].clear();
                        tmp_err[error_count].assign("Invalid configuration "
                                                    "file syntax!");
                        ++error_count;
                        goto save_free_parser;
                    }

                    line_stream << "Done" << std::endl;
                    ++line_stream_lc;

                    // get structure
                    antlr::process_config(ast_cfg.tree,
                                          cfg_cnt);

                    // validate
                    if (!config->validate(config->get_definition_root(),
                                          cfg_cnt)) {
                        tmp_err[error_count].clear();
                        tmp_err[error_count].assign("Invalid/undefined "
                                                    "configuration file "
                                                    "contents!");
                        ++error_count;
                        goto save_free_parser;
                    }

                    // prepare for config data
                    // replacement
                    config->replace_prepare(config->get_definition_root());
                    // merge new data
                    line_stream << "Merging new "
                                   "configuration "
                                   "file..."
                                << std::endl;
                    ++line_stream_lc;
                    res = config->merge(config->get_definition_root(),
                                        cfg_cnt,
                                        true);
                    // err check
                    if (res != 0) {
                        tmp_err[error_count].clear();
                        tmp_err[error_count].assign("Cannot merge "
                                                    "configuration "
                                                    "file "
                                                    "contents!");
                        ++error_count;
                    } else {
                        line_stream << "Done" << std::endl;
                        ++line_stream_lc;

                        // start transaction
                        config->start_transaction(&cfg_user_id);
                    }

save_free_parser:
                    // free mem
                    delete cfg_cnt;
                    delete[] tmp_file_buff;
                    antlr::free_mem(pmp);
                }
                // clear value
                ac_res.children[0]->new_value = "";

            }
        }
        // edit mode
    } else if (cm_mode == config::CONFIG_MT_EDIT) {
        if(!last_found) goto set_values;
        if (last_found->node_type != config::CONFIG_NT_BLOCK) {
            tmp_err[error_count].clear();
            tmp_err[error_count].append("Cannot navigate to non block mode \"");
            tmp_err[error_count].append(last_found->name);
            tmp_err[error_count].append("\"!");
            ++error_count;
            goto set_values;
        }
        if(pretend) goto set_values;

        // set current cfg path
        config->get_definition_wn(&cfg_user_id)->wnode = last_found;

        // regenerate cli path
        cli_path = "";

        // generate cfg path
        config->generate_path(config->get_definition_wn(&cfg_user_id)->wnode,
                              &cli_path);

        // show mode
    } else if (cm_mode == config::CONFIG_MT_SHOW) {
        // sitch to TAB mode, send config items
        ac_mode = config::CONFIG_ACM_TAB;

        // set mode
    } else if (cm_mode == config::CONFIG_MT_SET) {
        if(pretend) goto set_values;
        // do nothing, errors already present in tmp_err
        config->start_transaction(&cfg_user_id);
        // replicate
        std::vector<std::string *> *cfg_daemons =
            (std::vector<std::string *> *)mink::CURRENT_DAEMON->get_param(2);
        for (unsigned int i = 0; i < cfg_daemons->size(); i++) {
                config::replicate(line.c_str(),
                                  client->get_session()
                                        ->get_registered_client("routingd"),
                                  (*cfg_daemons)[i]->c_str(),
                                  &cfg_user_id);
        }
    }

set_values:
    // set values
    c->_action->set_linked_data(1, (unsigned char *)&ca_cfg_result, 1);
    // ac lline
    p->get_child(0)
     ->_id
     ->set_linked_data(1, (unsigned char *)&pt_mink_config_ac_line, sizeof(int));
    p->get_child(0)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)line.c_str(), line.size());

    // cli path
    p->get_child(1)
     ->_id
     ->set_linked_data(1, (unsigned char *)&pt_mink_config_cli_path, sizeof(int));
    p->get_child(1)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)cli_path.c_str(), cli_path.size());

    // error count
    err_index = error_count - 1;
    error_count = htobe32(error_count);
    p->get_child(2)
     ->_id
     ->set_linked_data(1, (unsigned char *)&pt_mink_config_ac_err_count, sizeof(int));
    p->get_child(2)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)&error_count, sizeof(int));

    // line count
    line_stream_lc = htobe32(line_stream_lc);
    p->get_child(3)
      ->_id
      ->set_linked_data(1, (unsigned char *)&pt_mink_config_cfg_line_count, sizeof(int));
    p->get_child(3)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)&line_stream_lc, sizeof(int));

    // cm mode
    p->get_child(4)
     ->_id
     ->set_linked_data(1, (unsigned char *)&pt_cfg_item_cm_mode, sizeof(uint32_t));
    p->get_child(4)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)&cm_mode, 1);

    // include body
    *include_body = true;
    // continue
    stream->continue_sequence();
}

// new stream, send auto completed line in first packet
void NewStream::process_tab(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    bool *include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_BODY);
    asn1::GDTMessage *in_msg = (asn1::GDTMessage *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_IN_MSG);
    uint64_t *in_sess = (uint64_t *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                  gdt::GDT_CB_ARG_IN_MSG_ID);
    tmp_size = 0;
    res_size = 0;
    error_count = 0;
    err_index = -1;
    last_found = NULL;
    res_index = 0;
    cm_mode = config::CONFIG_MT_UNKNOWN;
    tmp_node_lst.children.clear();
    ac_res.children.clear();
    line_stream.str("");
    line_stream.clear();
    line_stream.seekg(0, std::ios::beg);
    char *tmp_val = NULL;
    int tmp_val_l = 0;
    asn1::ConfigMessage *c = NULL;
    asn1::Parameters *p = NULL;

    // prepare body
    if (gdtm->_body != NULL) {
        gdtm->_body->unlink(1);
        gdtm->_body->_conf->set_linked_data(1);

    } else {
        gdtm->set_body();
        gdtm->prepare();
    }

    c = gdtm->_body->_conf;

    // remove payload
    if (gdtm->_body->_conf->_payload != NULL)
        gdtm->_body->_conf->_payload->unlink(1);
    // set params
    if (gdtm->_body->_conf->_params == NULL) {
        gdtm->_body->_conf->set_params();
        p = c->_params;
        // set children, allocate more
        for (int i = 0; i < 2; i++) {
            p->set_child(i);
            p->get_child(i)->set_value();
            p->get_child(i)->_value->set_child(0);
        }
        // prepare
        gdtm->prepare();

        // unlink params before setting new ones
    } else {
        p = c->_params;
        int cc = p->children.size();
        if (cc < 2) {
            // set children, allocate more
            for (int i = cc; i < 2; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

        } else if (cc > 2) {
            // remove extra children if used in some other session, only 2
            // needed
            for (int i = 2; i < cc; i++) p->get_child(i)->unlink(1);
        }
    }

    // get line
    if (!in_msg->_body) goto tokenize;
    // check for config message
    if (!c->has_linked_data(*in_sess)) goto tokenize;
    // check for params part
    if (!c->_params) goto tokenize;
    if (!c->_params->has_linked_data(*in_sess)) goto tokenize;
    p = c->_params;


    // process params
    for (unsigned int i = 0; i < p->children.size(); i++) {
        // check for current session
        if (!p->get_child(i)->has_linked_data(*in_sess)) continue;
        // check for value
        if (!p->get_child(i)->_value) continue;
        // check if value exists in current session
        if (!p->get_child(i)
              ->_value
              ->has_linked_data(*in_sess)) continue;
        // check if child exists
        if (!p->get_child(i)
              ->_value
              ->get_child(0)) continue;
        // check if child exists in current
        // sesion
        if (!p->get_child(i)
              ->_value
              ->get_child(0)
              ->has_linked_data(*in_sess)) continue;

        // check param id, convert from big endian to host
        uint32_t *param_id = (uint32_t *)p->get_child(i)
                                          ->_id
                                          ->linked_node
                                          ->tlv
                                          ->value;
        // set tmp values
        tmp_val = (char *)p->get_child(i)
                           ->_value
                           ->get_child(0)
                           ->linked_node
                           ->tlv
                           ->value;
        tmp_val_l = p->get_child(i)
                     ->_value
                     ->get_child(0)
                     ->linked_node
                     ->tlv
                     ->value_length;

        // match param
        switch (be32toh(*param_id)) {
            // config item count
            case asn1::ParameterType::_pt_mink_config_ac_line:
                line.clear();
                line.append(tmp_val, tmp_val_l);
                break;
            }
    }

tokenize:
    // tokenize
    mink_utils::tokenize(&line, tmp_lst, 50, &tmp_size, true);
    // auto complete
    config->auto_complete(&cm_mode,
                          config::CONFIG_ACM_TAB,
                          config->get_cmd_tree(),
                          config->get_definition_wn(&cfg_user_id)->wnode,
                          tmp_lst,
                          tmp_size,
                          &ac_res,
                          &res_size,
                          &last_found,
                          &error_count,
                          tmp_err,
                          false,
                          &tmp_node_lst);

    // replace current line with auto completed values
    line.clear();
    for (int i = 0; i < tmp_size; i++) {
        line.append(tmp_lst[i]);
        if (i < res_size)
            line.append(" ");
        else
            break;
    }

    // set values
    c->_action->set_linked_data(1, (unsigned char *)&ca_cfg_result, 1);
    // ac line
    p->get_child(0)
     ->_id
     ->set_linked_data(1,
                       (unsigned char *)&pt_mink_config_ac_line,
                       sizeof(uint32_t));
    p->get_child(0)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)line.c_str(), line.size());

    // cm mode
    p->get_child(1)
     ->_id
     ->set_linked_data(1,
                       (unsigned char *)&pt_cfg_item_cm_mode,
                       sizeof(uint32_t));
    p->get_child(1)
     ->_value
     ->get_child(0)
     ->set_linked_data(1, (unsigned char *)&cm_mode, 1);

    // include bodu
    *include_body = true;
    // continue
    stream->continue_sequence();
}

StreamNext::StreamNext() {
    cfg_res = NULL;
    new_stream = NULL;
    // big endian parameter ids
    pt_cfg_item_name = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_name);
    pt_cfg_item_path = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_path);
    pt_cfg_item_desc = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_desc);
    pt_cfg_item_ns = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_ns);
    pt_cfg_item_value = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_value);
    pt_cfg_item_nvalue = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_nvalue);
    pt_cfg_item_nt = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_nt);
    pt_cfg_cfg_line = htobe32(asn1::ParameterType::_pt_mink_config_cfg_line);
    pt_cfg_cfg_error = htobe32(asn1::ParameterType::_pt_mink_config_cfg_ac_err);
    pt_cfg_item_count = htobe32(asn1::ParameterType::_pt_mink_config_cfg_item_count);
}

// TAB stream next
void StreamNext::process_tab(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    bool *include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_BODY);

    asn1::ConfigMessage *c = NULL;
    asn1::Parameters *p = NULL;
    // more results
    if (new_stream->res_index < new_stream->ac_res.children.size()) {
        // prepare body
        if (gdtm->_body != NULL) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        } else {
            gdtm->set_body();
            gdtm->prepare();
        }

        // remove payload
        if (gdtm->_body->_conf->_payload != NULL)
            gdtm->_body->_conf->_payload->unlink(1);
        // set params
        if (gdtm->_body->_conf->_params == NULL) {
            gdtm->_body->_conf->set_params();
            p = gdtm->_body->_conf->_params;
            // set children, allocate more
            for (int i = 0; i < 6; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        } else {
            p = gdtm->_body->_conf->_params;
            int cc = p->children.size();
            if (cc < 6) {
                // set children, allocate more
                for (int i = cc; i < 6; i++) {
                    p->set_child(i);
                    p->get_child(i)->set_value();
                    p->get_child(i)->_value->set_child(0);
                }
                // prepare
                gdtm->prepare();

            } else if (cc > 6) {
                // remove extra children if used in some other session, only 2
                // needed
                for (int i = 6; i < cc; i++) p->get_child(i)->unlink(1);
            }
        }
        c = gdtm->_body->_conf;

        // set result action
        c->_action->set_linked_data(1, (unsigned char *)&new_stream->ca_cfg_result, 1);

        // item name
        p->get_child(0)
         ->_id
         ->set_linked_data(1, (unsigned char *)&pt_cfg_item_name, sizeof(uint32_t));
        p->get_child(0)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)new_stream->ac_res.children[new_stream->res_index]
                                                      ->name.c_str(),
                           new_stream->ac_res.children[new_stream->res_index]
                                     ->name.size());
        // item desc
        p->get_child(1)
         ->_id
         ->set_linked_data(1, (unsigned char *)&pt_cfg_item_desc, sizeof(uint32_t));
        p->get_child(1)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)new_stream->ac_res.children[new_stream->res_index]
                                                      ->desc.c_str(),
                           new_stream->ac_res.children[new_stream->res_index]
                                     ->desc.size());
        // node state
        p->get_child(2)
         ->_id
         ->set_linked_data(1, (unsigned char *)&pt_cfg_item_ns, sizeof(uint32_t));
        p->get_child(2)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,(unsigned char *)&new_stream->ac_res.children[new_stream->res_index]
                                                         ->node_state,
                           1);

        // node value
        p->get_child(3)
         ->_id
         ->set_linked_data(1, (unsigned char *)&pt_cfg_item_value, sizeof(uint32_t));
        p->get_child(3)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)new_stream->ac_res.children[new_stream->res_index]
                                                      ->value.c_str(),
                           new_stream->ac_res.children[new_stream->res_index]
                                     ->value.size());
        // node new value
        p->get_child(4)
          ->_id
          ->set_linked_data(1, (unsigned char *)&pt_cfg_item_nvalue, sizeof(uint32_t));
        p->get_child(4)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)new_stream->ac_res.children[new_stream->res_index]
                                                      ->new_value.c_str(),
                           new_stream->ac_res.children[new_stream->res_index]
                                     ->new_value.size());
        // node type
        p->get_child(5)
         ->_id
         ->set_linked_data(1, (unsigned char *)&pt_cfg_item_nt, sizeof(uint32_t));
        p->get_child(5)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)&new_stream->ac_res.children[new_stream->res_index]
                                                       ->node_type,
                           1);
        // include body
        *include_body = true;
        // continue
        stream->continue_sequence();

        // next result item
        ++new_stream->res_index;

        // finished
    } else {
        // end sequence
        stream->end_sequence();
        // free temp nodes and clear res buffer
        new_stream->ac_res.children.clear();
        for (unsigned int i = 0; i < new_stream->tmp_node_lst.children.size();
             i++)
            delete new_stream->tmp_node_lst.children[i];
        new_stream->tmp_node_lst.children.clear();
    }
}

// GET stream next
void StreamNext::process_get(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    bool *include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_BODY);

    asn1::ConfigMessage *c = NULL;
    asn1::Parameters *p = NULL;
    // more results
    if (new_stream->res_index < new_stream->ac_res.children.size()) {
        // prepare body
        if (gdtm->_body != NULL) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        } else {
            gdtm->set_body();
            gdtm->prepare();
        }

        // remove payload
        if (gdtm->_body->_conf->_payload != NULL)
            gdtm->_body->_conf->_payload->unlink(1);
        // set params
        if (gdtm->_body->_conf->_params == NULL) {
            gdtm->_body->_conf->set_params();
            p = gdtm->_body->_conf->_params;
            // set children, allocate more
            for (int i = 0; i < 3; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        } else {
            p = gdtm->_body->_conf->_params;
            int cc = p->children.size();
            if (cc < 3) {
                // set children, allocate more
                for (int i = cc; i < 3; i++) {
                    p->set_child(i);
                    p->get_child(i)->set_value();
                    p->get_child(i)->_value->set_child(0);
                }
                // prepare
                gdtm->prepare();

            } else if (cc > 3) {
                // remove extra children if used in some other session, only 2
                // needed
                for (int i = 3; i < cc; i++) p->get_child(i)->unlink(1);
            }
        }
        c = gdtm->_body->_conf;
        // set result action
        c->_action->set_linked_data(1, (unsigned char *)&new_stream->ca_cfg_result, 1);

        // item path
        // get full path and save to tmp_node_lst
        config::Config::get_parent_line(new_stream->ac_res.children[new_stream->res_index],
                                        &new_stream->tmp_node_lst.name);
        new_stream->tmp_node_lst.name.append(new_stream->ac_res.children[new_stream->res_index]->name);
        p->get_child(0)->_id->set_linked_data(1, (unsigned char *)&pt_cfg_item_path, sizeof(uint32_t));
        p->get_child(0)
          ->_value
          ->get_child(0)
          ->set_linked_data(1,
                            (unsigned char *)new_stream->tmp_node_lst.name.c_str(),
                            new_stream->tmp_node_lst.name.size());
        // node value
        p->get_child(1)
         ->_id
         ->set_linked_data(1,
                           (unsigned char *)&pt_cfg_item_value,
                           sizeof(uint32_t));
        p->get_child(1)
         ->_value
          ->get_child(0)
          ->set_linked_data(1,
                            (unsigned char *)new_stream->ac_res.children[new_stream->res_index]
                                                       ->value.c_str(),
                            new_stream->ac_res.children[new_stream->res_index]
                                      ->value.size());
        // node type
        p->get_child(2)
         ->_id
         ->set_linked_data(1, (unsigned char *)&pt_cfg_item_nt, sizeof(uint32_t));
        p->get_child(2)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)&new_stream->ac_res.children[new_stream->res_index]
                                                       ->node_type,
                           1);

        // include body
        *include_body = true;
        // continue
        stream->continue_sequence();

        // next result item
        ++new_stream->res_index;

        // finished
    } else {
        // end sequence
        stream->end_sequence();
        // free temp nodes and clear res buffer
        new_stream->ac_res.children.clear();
    }
}

// ENTER stream next
void StreamNext::process_enter(gdt::GDTCallbackArgs *args) {
    gdt::GDTStream *stream = (gdt::GDTStream *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                             gdt::GDT_CB_ARG_STREAM);
    asn1::GDTMessage *gdtm = stream->get_gdt_message();
    bool *include_body = (bool *)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                               gdt::GDT_CB_ARG_BODY);

    asn1::ConfigMessage *c = NULL;
    asn1::Parameters *p = NULL;
    // results
    if (getline(new_stream->line_stream, new_stream->line_buffer)) {
        // prepare body
        if (gdtm->_body != NULL) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        } else {
            gdtm->set_body();
            gdtm->prepare();
        }

        // remove payload
        if (gdtm->_body->_conf->_payload != NULL)
            gdtm->_body->_conf->_payload->unlink(1);
        // set params
        if (gdtm->_body->_conf->_params == NULL) {
            gdtm->_body->_conf->set_params();
            p = gdtm->_body->_conf->_params;
            // set children, allocate more
            for (int i = 0; i < 1; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        } else {
            p = gdtm->_body->_conf->_params;
            int cc = p->children.size();
            if (cc < 1) {
                // set children, allocate more
                for (int i = cc; i < 1; i++) {
                    p->set_child(i);
                    p->get_child(i)->set_value();
                    p->get_child(i)->_value->set_child(0);
                }
                // prepare
                gdtm->prepare();

            } else if (cc > 1) {
                // remove extra children if used in some other session, only 2
                // needed
                for (int i = 1; i < cc; i++) p->get_child(i)->unlink(1);
            }
        }
        c = gdtm->_body->_conf;
        // set result action
        c->_action->set_linked_data(1, (unsigned char *)&new_stream->ca_cfg_result, 1);

        // line
        p->get_child(0)->_id->set_linked_data(1,
                                              (unsigned char *)&pt_cfg_cfg_line,
                                              sizeof(uint32_t));
        p->get_child(0)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)new_stream->line_buffer.c_str(),
                           new_stream->line_buffer.size());
        // include body
        *include_body = true;
        // continue
        stream->continue_sequence();

        // errors
    } else if (new_stream->err_index >= 0) {
        // prepare body
        if (gdtm->_body != NULL) {
            gdtm->_body->unlink(1);
            gdtm->_body->_conf->set_linked_data(1);

        } else {
            gdtm->set_body();
            gdtm->prepare();
        }

        // remove payload
        if (gdtm->_body->_conf->_payload != NULL)
            gdtm->_body->_conf->_payload->unlink(1);
        // set params
        if (gdtm->_body->_conf->_params == NULL) {
            gdtm->_body->_conf->set_params();
            p = gdtm->_body->_conf->_params;
            // set children, allocate more
            for (int i = 0; i < 1; i++) {
                p->set_child(i);
                p->get_child(i)->set_value();
                p->get_child(i)->_value->set_child(0);
            }
            // prepare
            gdtm->prepare();

            // unlink params before setting new ones
        } else {
            p = gdtm->_body->_conf->_params;
            int cc = p->children.size();
            if (cc < 1) {
                // set children, allocate more
                for (int i = cc; i < 1; i++) {
                    p->set_child(i);
                    p->get_child(i)->set_value();
                    p->get_child(i)->_value->set_child(0);
                }
                // prepare
                gdtm->prepare();

            } else if (cc > 1) {
                // remove extra children if used in some other session, only 2
                // needed
                for (int i = 1; i < cc; i++) p->get_child(i)->unlink(1);
            }
        }
        c = gdtm->_body->_conf;
        // set result action
        c->_action->set_linked_data(1, (unsigned char *)&new_stream->ca_cfg_result, 1);

        // error line
        p->get_child(0)
         ->_id
         ->set_linked_data(1, (unsigned char *)&pt_cfg_cfg_error, sizeof(uint32_t));
        p->get_child(0)
         ->_value
         ->get_child(0)
         ->set_linked_data(1,
                           (unsigned char *)new_stream->tmp_err[new_stream->err_index].c_str(),
                           new_stream->tmp_err[new_stream->err_index].size());
        // include body
        *include_body = true;
        // continue
        stream->continue_sequence();

        // dec error index
        --new_stream->err_index;

        // finished
    } else {
        // end sequence
        stream->end_sequence();
        // free temp nodes and clear res buffer
        new_stream->ac_res.children.clear();
        for (unsigned int i = 0; i < new_stream->tmp_node_lst.children.size();
             i++)
            delete new_stream->tmp_node_lst.children[i];
        new_stream->tmp_node_lst.children.clear();
    }
}

// stream next, send config item nodes after auto completed line
void StreamNext::run(gdt::GDTCallbackArgs *args) {
    // mink daemons
    if (new_stream->config_action == asn1::ConfigAction::_ca_cfg_get) {
        process_get(args);

        // CLI
    } else {
        switch (new_stream->ac_mode) {
        case config::CONFIG_ACM_TAB:
            process_tab(args);
            break;

        case config::CONFIG_ACM_ENTER:
            process_enter(args);
            break;
        }
    }
}
