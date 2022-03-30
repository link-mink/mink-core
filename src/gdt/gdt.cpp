/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <gdt.h>
#include <arpa/inet.h>
#include <gdt_reg_events.h>

static gdt::GDTPayload* generate_err_unkn_strm(gdt::GDTStateMachine *gdtsm){
    // stats
    gdt::GDTClient *gdtc = gdtsm->gdtc;
    gdtc->in_stats.stream_errors.add_fetch(1);

    // create payload
    gdt::GDTStream* gdts = gdtc->allocate_stream_pool();
    // null check
    if(gdts == nullptr){
        // stats
        gdtc->in_stats.strm_alloc_errors.add_fetch(1);
        // loop end
        return nullptr;
    }
    gdt::GDTPayload* gdtp = gdts->get_gdt_payload();
    gdts->clear_callbacks();
    gdts->set_linked_stream(nullptr);
    // reset
    gdtp->free_on_send = true;
    gdtp->gdt_stream_type = gdt::GDT_ST_UNKNOWN;
    gdtp->client = gdtc;
    gdtp->sctp_sid = gdtsm->rcvinfo.sinfo_stream;
    gdtp->clear_callbacks();
    // generate ERR
    gdtc->generate_err(&gdtsm->gdt_in_message,
                       &gdtsm->gdt_out_message,
                       gdtsm->tmp_in_session_id,
                       1,
                       gdtp,
                       gdtsm->mem_switch,
                       -1,
                       nullptr,
                       nullptr,
                       asn1::ErrorCode::_err_unknown_sequence);
    return gdtp;

}

static void generate_err_uos(gdt::GDTStateMachine *gdtsm,
                             gdt::GDTPayload *gdtp,
                             gdt::GDTStream *tmp_stream){
    // set sctp sid
    gdtp->sctp_sid = gdtsm->rcvinfo.sinfo_stream;
    // generate ERR
    gdtsm->gdtc->generate_err(&gdtsm->gdt_in_message,
                              tmp_stream->get_gdt_message(),
                              gdtsm->tmp_in_session_id,
                              1,
                              gdtp,
                              gdtsm->mem_switch,
                              -1,
                              nullptr,
                              nullptr,
                              asn1::ErrorCode::_err_out_of_sequence);

    // set stream callback args
    gdtsm->cb_stream_args.clear_all_args();
    gdtsm->cb_stream_args.add_arg(gdt::GDT_CB_INPUT_ARGS,
                                  gdt::GDT_CB_ARG_CLIENT,
                                  gdtsm->gdtc);

    gdtsm->cb_stream_args.add_arg(gdt::GDT_CB_INPUT_ARGS,
                                  gdt::GDT_CB_ARG_STREAM,
                                  tmp_stream);

    gdtsm->cb_stream_args.add_arg(gdt::GDT_CB_INPUT_ARGS,
                                  gdt::GDT_CB_ARG_IN_MSG,
                                  &gdtsm->gdt_in_message);

    gdtsm->cb_stream_args.add_arg(gdt::GDT_CB_INPUT_ARGS,
                                  gdt::GDT_CB_ARG_IN_MSG_ID,
                                  &gdtsm->tmp_in_session_id);
    // process callback
    tmp_stream->process_callback(gdt::GDT_ET_STREAM_END,
                                 &gdtsm->cb_stream_args);


}

static void copy_choice_selection(bool has_body,
                                  asn1::Body *bdy,
                                  asn1::Body *ob,
                                  uint64_t _session_id){
    // body
    if(has_body){
        // get original choice selection
        int ci = 0;
        for(unsigned int i = 0; i<ob->children.size(); i++){
            if(ob->children[i] == ob->choice_selection){
                ci = i;
                break;
            }
        }
        bdy->choice_selection = bdy->children[ci];
        bdy->choice_selection
           ->set_linked_data(_session_id,
                             ob->choice_selection
                               ->linked_node
                               ->tlv->value,
                             ob->choice_selection
                               ->linked_node
                               ->tlv
                               ->value_length);

        // override auto complexity
        bdy->choice_selection
           ->tlv
           ->override_auto_complexity = true;
    }
}

static void setup_dest_and_uuid(asn1::Header *hdr,
                                asn1::Header *oh,
                                bool set_dest_id,
                                uint64_t _session_id){
    // destination
    hdr->_destination
       ->_type
       ->set_linked_data(_session_id,
                         oh->_source
                           ->_type
                           ->linked_node
                           ->tlv
                           ->value,
                         oh->_source
                           ->_type
                           ->linked_node
                           ->tlv
                           ->value_length);

    if(set_dest_id){
        hdr->_destination
           ->_id
           ->set_linked_data(_session_id,
                             oh->_source
                               ->_id
                               ->linked_node
                               ->tlv
                               ->value,
                             oh->_source
                               ->_id
                               ->linked_node
                               ->tlv
                               ->value_length);

    }else {
        if(hdr->_destination->_id != nullptr)
            hdr->_destination->_id->unlink(_session_id);
    }


    // uuid
    hdr->_uuid->set_linked_data(_session_id,
                                oh->_uuid
                                  ->linked_node
                                  ->tlv
                                  ->value,
                                oh->_uuid
                                  ->linked_node
                                  ->tlv
                                  ->value_length);
}

/**
 * Genereate stream complete message
 * @param[in]   gdt_orig_message    Pointer to original GDT message
 * @param[out]  gdt_out_message     Pointer to output GDT message
 * @param[in]   _orig_session_id    Current session id of original GDT message
 * @param[in]   _out_session_id     New session id of output message (should be 1)
 * @param[out]  gdtld               Pointer to GDT output payload
 */
static void generate_stream_complete(asn1::GDTMessage *gdt_orig_message,
                                     asn1::GDTMessage *gdt_out_message,
                                     uint64_t _orig_session_id,
                                     uint64_t _out_session_id,
                                     gdt::GDTPayload *gdtld){
    if(gdt_orig_message != nullptr && gdt_out_message != nullptr){

        // next session id
        uint64_t _session_id = _out_session_id;

        // check optional
        bool prepare_needed = false;
        bool source_id = false;
        bool destination_id = false;
        asn1::Header *hdr = gdt_out_message->_header;
        asn1::Header *oh = gdt_orig_message->_header;
        const asn1::Body *bdy = gdt_out_message->_body;

        // check is status is set
        if(hdr->_status == nullptr){
            hdr->set_status();
            prepare_needed = true;
        }

        // check if destination id is present
        if ((oh->_destination->_id != nullptr) &&
            (oh->_destination->_id->has_linked_data(_orig_session_id))) {
            if (hdr->_source->_id == nullptr) {
                hdr->_source->set_id();
                prepare_needed = true;
            }
            destination_id = true;
        }

        // check if source id is present
        if ((oh->_source->_id != nullptr) &&
            (oh->_source->_id->has_linked_data(_orig_session_id))) {
            if (hdr->_destination->_id == nullptr) {
                hdr->_destination->set_id();
                prepare_needed = true;
            }
            source_id = true;
        }

        // prepare only if one of optional fields was not set
        if(prepare_needed) gdt_out_message->prepare();

        // unlink body if exists
        if(bdy != nullptr) gdt_out_message->_body->unlink(_session_id);
        // check is status is set
        if(hdr->_status != nullptr) hdr->_status->unlink(_out_session_id);


        // version
        int ver = gdt::_GDT_VERSION_;
        hdr->_version->set_linked_data(_session_id, (unsigned char*)&ver, 1);

        // source
        hdr->_source->_type->set_linked_data(_session_id,
                                             oh->_destination->_type->linked_node->tlv->value,
                                             oh->_destination->_type->linked_node->tlv->value_length);


        if(destination_id){
            hdr->_source->_id->set_linked_data(_session_id,
                                               oh->_destination->_id->linked_node->tlv->value,
                                               oh->_destination->_id->linked_node->tlv->value_length);

        }else if(hdr->_source->_id != nullptr) hdr->_source->_id->unlink(_session_id);

        setup_dest_and_uuid(hdr, oh, source_id, _session_id);

        // sequence num
        uint32_t seqn = htobe32(gdtld->stream->get_sequence_num());
        hdr->_sequence_num->set_linked_data(_session_id, (unsigned char*)&seqn, 4);



        int sf = asn1::SequenceFlag::_sf_stream_complete;
        hdr->_sequence_flag->set_linked_data(_session_id, (unsigned char*)&sf, 1);

        if (hdr->_status != nullptr) {
            int status = asn1::ErrorCode::_err_ok;
            hdr->_status->set_linked_data(_session_id, (unsigned char *)&status,
                                          1);
        }
        gdtld->raw_data_length = asn1::encode(gdtld->raw_data,
                                              gdt::MEM_CSIZE,
                                              gdt_out_message,
                                              _session_id);


    }

}

/**
 * U[date hop data
 * @param[in]   gdt_orig_message    Pointer to original GDT message
 * @param[out]  gdt_out_message     Pointer to output GDT message
 * @param[in]   _orig_session_id    Current session id of original GDT message
 * @param[in]   _out_session_id     New session id of output message (should be 1)
 * @param[in]   _destination_id     Pointer to destination id
 * @param[out]  gdtld               Pointer to GDT output payload
 */
static int update_hop_info(asn1::GDTMessage *gdt_orig_message,
                           asn1::GDTMessage *gdt_out_message,
                           uint64_t _orig_session_id,
                           uint64_t _out_session_id,
                           gdt::GDTPayload *gdtld){

    // null check
    if(gdt_orig_message != nullptr){
        // next session id
        uint64_t _session_id = _out_session_id;


        // check optional
        bool prepare_needed = false;
        bool source_id = false;
        bool dest_id = false;
        bool has_status = false;
        bool has_body = false;
        int current_hop = 0;
        int max_hops = 10;
        asn1::Header *hdr = gdt_out_message->_header;
        asn1::Header *oh = gdt_orig_message->_header;
        asn1::Body *ob = gdt_orig_message->_body;
        asn1::Body *bdy = gdt_out_message->_body;

        // body
        if ((ob != nullptr) &&
            (ob->choice_selection != nullptr) &&
            ob->choice_selection->has_linked_data(_orig_session_id)) {

            has_body = true;
        }
        if(!has_body){
            if(bdy != nullptr) bdy->unlink(_session_id);
        }else{
            if(bdy == nullptr){
                gdt_out_message->set_body();
                prepare_needed = true;
                bdy = gdt_out_message->_body;
            }
        }


        // status
        if ((oh->_status != nullptr) &&
            (oh->_status->has_linked_data(_orig_session_id))) {
            has_status = true;
        }
        if(has_status){
            if(hdr->_status == nullptr){
                hdr->set_status();
                prepare_needed = true;
            }
        }else{
            if(hdr->_status != nullptr){
                hdr->_status->unlink(_session_id);
            }
        }


        // source id
        if ((oh->_source->_id != nullptr) &&
            (oh->_source->_id->has_linked_data(_orig_session_id))) {
            if (hdr->_source->_id == nullptr) {
                hdr->_source->set_id();
                prepare_needed = true;
            }
            source_id = true;
        }
        if(source_id){
            if(hdr->_source->_id == nullptr) hdr->_source->set_id();

        }else{
            if(hdr->_source->_id != nullptr) hdr->_source->_id->unlink(_session_id);
        }


        // destination
        if ((oh->_destination->_id != nullptr) &&
            (oh->_destination->_id->has_linked_data(_orig_session_id))) {
            if (hdr->_destination->_id == nullptr) {
                hdr->_destination->set_id();
                prepare_needed = true;
            }
            dest_id = true;
        }
        if(source_id){
            if(hdr->_source->_id == nullptr) hdr->_source->set_id();

        }else{
            if(hdr->_source->_id != nullptr) hdr->_source->_id->unlink(_session_id);
        }

        if(dest_id){
            if(hdr->_destination->_id == nullptr) hdr->_destination->set_id();

        }else{
            if(hdr->_destination->_id != nullptr) hdr->_destination->_id->unlink(_session_id);
        }


        // source hop
        if(asn1::node_exists(oh->_hop_info, _orig_session_id)){
            memcpy(&current_hop,
                   oh->_hop_info->_current_hop->linked_node->tlv->value,
                   oh->_hop_info->_current_hop->linked_node->tlv->value_length);

            current_hop = be32toh(current_hop);

            if(current_hop > max_hops) return 1;
        }

        // hop info
        if(hdr->_hop_info == nullptr){
            hdr->set_hop_info();
            prepare_needed = true;
        }

        // prepare only if one of optional fields was not set
        if(prepare_needed) gdt_out_message->prepare();

        // version
        int ver = gdt::_GDT_VERSION_;
        hdr->_version->set_linked_data(_session_id, (unsigned char*)&ver, 1);

        // source
        hdr->_source->_type->set_linked_data(_session_id,
                                             oh->_source->_type->linked_node->tlv->value,
                                             oh->_source->_type->linked_node->tlv->value_length);


        if(source_id){
            hdr->_source->_id->set_linked_data(_session_id,
                                               oh->_source->_id->linked_node->tlv->value,
                                               oh->_source->_id->linked_node->tlv->value_length);

        }else if(hdr->_source->_id != nullptr) hdr->_source->_id->unlink(_session_id);


        // destination
        hdr->_destination->_type->set_linked_data(_session_id,
                                                  oh->_destination->_type->linked_node->tlv->value,
                                                  oh->_destination->_type->linked_node->tlv->value_length);


        if(dest_id){
            hdr->_destination->_id->set_linked_data(_session_id,
                                                    oh->_destination->_id->linked_node->tlv->value,
                                                    oh->_destination->_id->linked_node->tlv->value_length);

        }else if(hdr->_destination->_id != nullptr) hdr->_destination->_id->unlink(_session_id);




        // uuid
        hdr->_uuid->set_linked_data(_session_id,
                                    oh->_uuid->linked_node->tlv->value,
                                    oh->_uuid->linked_node->tlv->value_length);

        // sequence num
        hdr->_sequence_num->set_linked_data(_session_id,
                                            oh->_sequence_num->linked_node->tlv->value,
                                            oh->_sequence_num->linked_node->tlv->value_length);

        // sequence flag
        hdr->_sequence_flag->set_linked_data(_session_id,
                                             oh->_sequence_flag->linked_node->tlv->value,
                                             oh->_sequence_flag->linked_node->tlv->value_length);

        // status
        if(has_status){
            hdr->_status->set_linked_data(_session_id,
                                          oh->_status->linked_node->tlv->value,
                                          oh->_status->linked_node->tlv->value_length);

        }

        // hop info
        current_hop = htobe32(current_hop + 1);
        max_hops = htobe32(max_hops);
        hdr->_hop_info->_current_hop->set_linked_data(_session_id,
                                                      (unsigned char*)&current_hop,
                                                      sizeof(current_hop));
        hdr->_hop_info->_max_hops->set_linked_data(_session_id,
                                                   (unsigned char*)&max_hops,
                                                   sizeof(max_hops));

        copy_choice_selection(has_body, bdy, ob, _session_id);

        // encode
        gdtld->raw_data_length = asn1::encode(gdtld->raw_data,
                                              gdt::MEM_CSIZE,
                                              gdt_out_message,
                                              _session_id,
                                              false);


        // reset auto complexity flag
        if(has_body) bdy->choice_selection->tlv->override_auto_complexity = false;
        return 0;

    }

    return 2;

}

/**
 * Insert destination id in GDT header
 * @param[in]   gdt_orig_message    Pointer to original GDT message
 * @param[out]  gdt_out_message     Pointer to output GDT message
 * @param[in]   _orig_session_id    Current session id of original GDT message
 * @param[in]   _out_session_id     New session id of output message (should be 1)
 * @param[in]   _destination_id     Pointer to destination id
 * @param[in]   _destination_length Length of destination id
 * @param[out]  gdtld               Pointer to GDT output payload
 */
static void set_destination_id(asn1::GDTMessage* gdt_orig_message,
                               asn1::GDTMessage* gdt_out_message,
                               uint64_t _orig_session_id,
                               uint64_t _out_session_id,
                               unsigned char* _destination,
                               int _destination_length,
                               gdt::GDTPayload* gdtld){

    // null check
    if(gdt_orig_message != nullptr){
        // next session id
        uint64_t _session_id = _out_session_id;
        // check optional
        bool prepare_needed = false;
        bool source_id = false;
        bool has_status = false;
        bool has_body = false;
        asn1::Header *hdr = gdt_out_message->_header;
        asn1::Header *oh = gdt_orig_message->_header;
        asn1::Body *ob = gdt_orig_message->_body;
        asn1::Body *bdy = gdt_out_message->_body;

        // body
        if ((ob != nullptr) &&
            (ob->choice_selection != nullptr) &&
            (ob->choice_selection->has_linked_data(_orig_session_id))) {
            has_body = true;
        }
        if(!has_body){
            if(bdy != nullptr) bdy->unlink(_session_id);
        }else{
            if(bdy == nullptr){
                gdt_out_message->set_body();
                prepare_needed = true;
                bdy = gdt_out_message->_body;
            }
        }

        // unlink hop info if exists
        if(hdr->_hop_info != nullptr) hdr->_hop_info->unlink(_session_id);


        // status
        if((oh->_status != nullptr) && (oh->_status->has_linked_data(_orig_session_id))){
            has_status = true;
        }
        if(has_status){
            if(hdr->_status == nullptr){
                hdr->set_status();
                prepare_needed = true;
            }
        }else{
            if(hdr->_status != nullptr){
                hdr->_status->unlink(_session_id);
            }
        }

        // source id
        if ((oh->_source->_id != nullptr) &&
            (oh->_source->_id->has_linked_data(_orig_session_id))) {
            if (hdr->_source->_id == nullptr) {
                hdr->_source->set_id();
                prepare_needed = true;
            }
            source_id = true;
        }
        if(source_id){
            if(hdr->_source->_id == nullptr) hdr->_source->set_id();

        }else{
            if(hdr->_source->_id != nullptr) hdr->_source->_id->unlink(_session_id);
        }


        // destination
        if(hdr->_destination->_id == nullptr){
            hdr->_destination->set_id();
            prepare_needed = true;
        }

        // prepare only if one of optional fields was not set
        if(prepare_needed) gdt_out_message->prepare();


        // version
        int ver = gdt::_GDT_VERSION_;
        hdr->_version->set_linked_data(_session_id, (unsigned char*)&ver, 1);

        // source
        hdr->_source->_type->set_linked_data(_session_id,
                                             oh->_source->_type->linked_node->tlv->value,
                                             oh->_source->_type->linked_node->tlv->value_length);


        if(source_id){
            hdr->_source->_id->set_linked_data(_session_id,
                                               oh->_source->_id->linked_node->tlv->value,
                                               oh->_source->_id->linked_node->tlv->value_length);

        }else if(hdr->_source->_id != nullptr) hdr->_source->_id->unlink(_session_id);


        // destination
        hdr->_destination->_type->set_linked_data(_session_id,
                                                  oh->_destination->_type->linked_node->tlv->value,
                                                  oh->_destination->_type->linked_node->tlv->value_length);

        hdr->_destination->_id->set_linked_data(_session_id,
                                                _destination,
                                                _destination_length);

        // uuid
        hdr->_uuid->set_linked_data(_session_id,
                                    oh->_uuid->linked_node->tlv->value,
                                    oh->_uuid->linked_node->tlv->value_length);

        // sequence num
        hdr->_sequence_num->set_linked_data(_session_id,
                                            oh->_sequence_num->linked_node->tlv->value,
                                            oh->_sequence_num->linked_node->tlv->value_length);

        // sequence flag
        hdr->_sequence_flag->set_linked_data(_session_id,
                                             oh->_sequence_flag->linked_node->tlv->value,
                                             oh->_sequence_flag->linked_node->tlv->value_length);

        // status
        if(has_status){
            hdr->_status->set_linked_data(_session_id,
                                          oh->_status->linked_node->tlv->value,
                                          oh->_status->linked_node->tlv->value_length);

        }

        copy_choice_selection(has_body, bdy, ob, _session_id);

        // encode
        gdtld->raw_data_length = asn1::encode(gdtld->raw_data,
                                              gdt::MEM_CSIZE,
                                              gdt_out_message,
                                              _session_id,
                                              false);


        // reset auto complexity flag
        if(has_body) bdy->choice_selection->tlv->override_auto_complexity = false;

    }

}

/**
 * Validate sequence number
 * @param[in]   data                Raw 4 byte big endian data containing sequence number
 * @param[in]   data_len            Length of data, should be 4
 * @param[in]   expected_seq_num    Expected sequence number
 * @return      True if sequence number equals to expected_seq_num of False otherwise
 */
static bool validate_seq_num(const unsigned char* data,
                             unsigned int data_len,
                             unsigned int expected_seq_num){
    // uint32_t
    if(data_len == 4){
        // convert to little endian
        uint32_t tmp = 0;
        memcpy(&tmp, data, data_len);
        tmp = be32toh(tmp);
        // return result
        return (tmp == expected_seq_num);
    }
    return false;
}

/**
 * Register client
 * @param[in]   client              Pointer to GDTClient
 * @param[in]   dest_daemon_type    Pointer to registration point daemon type
 */
static int register_client(gdt::GDTClient* client, const char* dest_daemon_type){
    // using semaphore, should not be used in GDT client loops (in/out) or events
    if(client != nullptr){

        class _RegClientStreamAllDone: public gdt::GDTCallbackMethod {
            public:
                _RegClientStreamAllDone(){
                    sem_init(&signal, 0, 0);
                }
                _RegClientStreamAllDone(const _RegClientStreamAllDone &o) = delete;
                _RegClientStreamAllDone &operator=(const _RegClientStreamAllDone &o) = delete;

                ~_RegClientStreamAllDone() override{
                    sem_destroy(&signal);
                }

                // event handler method
                void run(gdt::GDTCallbackArgs* args) override{
                    auto pld = (gdt::GDTPayload*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                               gdt::GDT_CB_ARG_PAYLOAD);
                    // check if all mandatory params were received
                    if(status >= 3) pld->client->set_reg_flag(true);
                    // signal
                    sem_post(&signal);

                }

                // signal
                sem_t signal;
                int status = 0;

        };

        // Client registration stream next
        class _RegClientStreamDone: public gdt::GDTCallbackMethod {
            public:
                // event handler method
                void run(gdt::GDTCallbackArgs* args) override{
                    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_STREAM);
                    gdt::GDTClient* client = stream->get_client();
                    auto in_msg = (asn1::GDTMessage*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                   gdt::GDT_CB_ARG_IN_MSG);
                    auto in_sess = (uint64_t*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                            gdt::GDT_CB_ARG_IN_MSG_ID);
                    char* tmp_val = nullptr;
                    int tmp_val_l = 0;
                    std::string tmp_str;
                    asn1::Parameters *p = nullptr;
                    asn1::RegistrationMessage *reg = nullptr;

                    // check for body
                    if(!((in_msg != nullptr) && (in_msg->_body != nullptr))) goto stream_timeout;
                    // check for config message
                    if(!in_msg->_body->_reg->has_linked_data(*in_sess)) goto stream_pld_sent;
                    // reg msg pointer
                    reg = in_msg->_body->_reg;
                    // check for GET action
                    if(reg->_reg_action
                          ->linked_node
                          ->tlv
                          ->value[0] != asn1::RegistrationAction::_ra_reg_result)
                        goto stream_pld_sent;
                    // check for params part
                    if(reg->_params == nullptr) goto stream_pld_sent;
                    if(!reg->_params->has_linked_data(*in_sess)) goto stream_pld_sent;
                    // params
                    p = reg->_params;

                    // process params
                    for(unsigned int i = 0; i<p->children.size(); i++){
                        // check for current session
                        if(!p->get_child(i)->has_linked_data(*in_sess)) continue;
                        // check for value
                        if(p->get_child(i)->_value == nullptr) continue;
                        // check if value exists in current session
                        if(!p->get_child(i)->_value->has_linked_data(*in_sess)) continue;
                        // check if child exists
                        if(p->get_child(i)->_value->get_child(0) == nullptr) continue;
                        // check if child exists in current sesion
                        if(!p->get_child(i)->_value->get_child(0)->has_linked_data(*in_sess)) continue;
                        // check param id, convert from big endian to host
                        auto param_id = (uint32_t*)p->get_child(i)->_id->linked_node->tlv->value;
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
                                ++adone.status;
                                break;

                                // daemon id
                            case asn1::ParameterType::_pt_mink_daemon_id:
                                tmp_str.clear();
                                tmp_str.append(tmp_val, tmp_val_l);
                                client->set_end_point_daemon_id(tmp_str.c_str());
                                ++adone.status;
                                break;

                                // router status
                            case asn1::ParameterType::_pt_mink_router_status:
                                client->set_router_flag((tmp_val[0] == 0) ? false : true);
                                ++adone.status;
                                break;

                            default:
                                break;

                        }

                    }
stream_pld_sent:
                    // wait until stream complete was properly sent
                    stream->set_callback(gdt::GDT_ET_PAYLOAD_SENT, &adone);
                    return;
stream_timeout:
                    // *** stream timeout ***<
                    // signal
                    sem_post(&adone.signal);
                }

                _RegClientStreamAllDone adone;

        };

        // Client registration stream done
        class _RegClientStreamNext: public gdt::GDTCallbackMethod {
            public:
                // event handler method
                void run(gdt::GDTCallbackArgs* args) override{
                    auto stream = (gdt::GDTStream*)args->get_arg(gdt::GDT_CB_INPUT_ARGS,
                                                                 gdt::GDT_CB_ARG_STREAM);
                    // end stream
                    stream->end_sequence();

                }
        };

        // events
        _RegClientStreamDone sdone;
        _RegClientStreamNext snext;
        // start new GDT stream
        gdt::GDTStream* gdt_stream = client->new_stream(dest_daemon_type, nullptr, nullptr, &snext);
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
        uint32_t pm_dtype = htobe32(asn1::ParameterType::_pt_mink_daemon_type);
        uint32_t pm_did = htobe32(asn1::ParameterType::_pt_mink_daemon_id);
        uint32_t pm_router = htobe32(asn1::ParameterType::_pt_mink_router_status);
        uint32_t reg_action = asn1::RegistrationAction::_ra_reg_request;
        int router_flag = (client->get_session()->is_router() ? 1 : 0);
        // set params
        if(gdtm->_body->_reg->_params == nullptr){
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
        asn1::RegistrationMessage *reg = gdtm->_body->_reg;
        // set reg action
        reg->_reg_action->set_linked_data(1, (unsigned char*)&reg_action, 1);

        // set daemon type
        reg->_params
           ->get_child(0)
           ->_id
           ->set_linked_data(1, (unsigned char*)&pm_dtype, sizeof(uint32_t));
        reg->_params
           ->get_child(0)
           ->_value
           ->get_child(0)
           ->set_linked_data(1,
                             (unsigned char*)client->get_session()->get_daemon_type(),
                             strlen(client->get_session()->get_daemon_type()));

        // set daemon id
        reg->_params
           ->get_child(1)
           ->_id
           ->set_linked_data(1, (unsigned char*)&pm_did, sizeof(uint32_t));
        reg->_params
           ->get_child(1)
           ->_value
           ->get_child(0)
           ->set_linked_data(1,
                             (unsigned char*)client->get_session()->get_daemon_id(),
                             strlen(client->get_session()->get_daemon_id()));

        // set router flag
        reg->_params
           ->get_child(2)
           ->_id
           ->set_linked_data(1, (unsigned char*)&pm_router, sizeof(uint32_t));
        reg->_params
           ->get_child(2)
           ->_value
           ->get_child(0)
           ->set_linked_data(1, (unsigned char*)&router_flag, 1);

        // start stream
        gdt_stream->send(true);

        // wait for signal
        timespec ts;
        clock_gettime(0, &ts);
        ts.tv_sec += 10;
        int sres = sem_wait(&sdone.adone.signal);
        // error check
        if(sres == -1) return 1;
        // check if registered
        if(client->is_registered()) return 0; else return 1;
    }

    // err
    return 1;
}

// HeartbeatInfo
gdt::HeartbeatInfo::HeartbeatInfo() : gdtc(nullptr),
                                      interval(0),
                                      on_received(nullptr),
                                      on_missed(nullptr),
                                      on_cleanup(nullptr){
    memset(target_daemon_id, 0, sizeof(target_daemon_id));
    memset(target_daemon_type, 0, sizeof(target_daemon_type));
}

gdt::HeartbeatInfo::~HeartbeatInfo() = default;

void gdt::HeartbeatInfo::set_activity(bool _is_active){
    active.comp_swap(!_is_active, _is_active);

}

void gdt::HeartbeatInfo::set_next(bool _next){
    next.comp_swap(!_next, _next);

}


void gdt::HeartbeatInfo::inc_total_received(){
    total_received_count.fetch_add(1);
}

void gdt::HeartbeatInfo::inc_received(){
    received_count.fetch_add(1);
}

void gdt::HeartbeatInfo::inc_missed(){
    missed_count.fetch_add(1);
}

void gdt::HeartbeatInfo::reset_missed(){
    missed_count.fetch_and(0);
}




void gdt::HeartbeatInfo::inc_total_sent(){
    total_sent_count.fetch_add(1);
}


uint64_t gdt::HeartbeatInfo::get_total_received(){
    return total_received_count.get();

}

uint64_t gdt::HeartbeatInfo::get_received(){
    return received_count.get();
}

uint64_t gdt::HeartbeatInfo::get_missed(){
    return missed_count.get();

}



uint64_t gdt::HeartbeatInfo::get_total_sent(){
    return total_sent_count.get();

}


bool gdt::HeartbeatInfo::is_active(){
    return active.get();

}

bool gdt::HeartbeatInfo::next_ready(){
    return next.get();

}


void* gdt::HeartbeatInfo::heartbeat_loop(void* args){
    if(args != nullptr){
        auto hi = (HeartbeatInfo*)args;
        unsigned int total_sleep = 0;
        gdt::GDTStream* gdt_stream = nullptr;
        GDTCallbackArgs cb_args;

        // stream level heartbeat missed event
        class _tmp_missed: public GDTCallbackMethod {
            public:
                explicit _tmp_missed(HeartbeatInfo* _hi) : hi(_hi) {}

                void run(gdt::GDTCallbackArgs* args) override{
                    hi->inc_missed();
                    args->add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_HBEAT_INFO, hi);
                    if(hi->on_missed != nullptr) hi->on_missed->run(args);
                    hi->inc_total_received();
                    hi->set_next(true);
                }

                HeartbeatInfo* hi;
        };

        // stream level heartbeat received event
        class _tmp_recv: public GDTCallbackMethod {
            public:
                explicit _tmp_recv(HeartbeatInfo* _hi) : hi(_hi) {}

                void run(gdt::GDTCallbackArgs* args) override{
                    hi->inc_received();
                    hi->reset_missed();
                    args->add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_HBEAT_INFO, hi);
                    if(hi->on_received != nullptr) hi->on_received->run(args);
                    hi->inc_total_received();
                    hi->set_next(true);
                }

                HeartbeatInfo* hi;

        };

        // stream level heartbeat sent event
        class _tmp_sent: public GDTCallbackMethod {
            public:
                explicit _tmp_sent(HeartbeatInfo* _hi) : hi(_hi) {}

                void run(gdt::GDTCallbackArgs* args) override{
                    hi->inc_total_sent();
                }

                HeartbeatInfo* hi;

        };



        // stream level events
        auto tmp_missed = new _tmp_missed(hi);
        auto tmp_recv = new _tmp_recv(hi);
        auto tmp_sent = new _tmp_sent(hi);

        // loop
        while(hi->gdtc->is_active() && hi->is_active()){
            // sleep 1 sec
            sleep(1);
            ++total_sleep;
            // check if user timeout has been reached
            if(total_sleep < hi->interval) continue;
            // reset current timeout
            total_sleep = 0;
            // check if new hbeat should be sent
            if(hi->next_ready() && hi->is_active()){
                // start new GDT stream
                gdt_stream = hi->gdtc->new_stream(hi->target_daemon_type,
                                                  hi->target_daemon_id,
                                                  nullptr,
                                                  nullptr);
                // check for valid stream
                if(gdt_stream != nullptr){
                    // set next flag
                    hi->set_next(false);
                    // set heartbeat reply events on stream level
                    gdt_stream->set_callback(GDT_ET_HEARTBEAT_MISSED, tmp_missed);
                    gdt_stream->set_callback(GDT_ET_HEARTBEAT_RECEIVED, tmp_recv);
                    gdt_stream->set_callback(GDT_ET_STREAM_TIMEOUT, tmp_missed);
                    gdt_stream->set_callback(GDT_ET_PAYLOAD_SENT, tmp_sent);
                    // set sequence flag
                    gdt_stream->set_sequence_flag(GDT_SF_HEARTBEAT);
                    // start stream
                    gdt_stream->send(false);

                }
            }
        }
        // wait for streams to finish or timeout
        while(!hi->next_ready()) sleep(1);

        // cleanup
        if(hi->on_cleanup != nullptr){
            cb_args.clear_all_args();
            hi->on_cleanup->run(&cb_args);
        }
        // get gdtc
        GDTClient* tmp_client = hi->gdtc;
        // free
        delete tmp_missed;
        delete tmp_recv;
        delete tmp_sent;
        delete hi;
        // detach
        pthread_detach(pthread_self());
        tmp_client->dec_thread_count();

    }


    return nullptr;
}


// GDTCallbackArgs
void gdt::GDTCallbackArgs::clear_all_args(){
    in_args.clear();
    out_args.clear();
}
void gdt::GDTCallbackArgs::clear_args(GDTCBArgsType _args_type){
    switch(_args_type){
        case GDT_CB_INPUT_ARGS: in_args.clear(); break;
        case GDT_CB_OUTPUT_ARGS: out_args.clear(); break;
        default:
            break;
    }
}
int gdt::GDTCallbackArgs::get_arg_count(GDTCBArgsType _arg_type) const {
    switch(_arg_type){
        case GDT_CB_INPUT_ARGS: return in_args.size();
        case GDT_CB_OUTPUT_ARGS: return out_args.size();
        default:
            break;
    }

    return 0;
}

void gdt::GDTCallbackArgs::add_arg(GDTCBArgsType _args_type,  GDTCBArgType _arg_type, void* _arg){
    switch(_args_type){
        case GDT_CB_INPUT_ARGS: in_args[_arg_type] =_arg; break;
        case GDT_CB_OUTPUT_ARGS: out_args[_arg_type] = _arg; break;
        default:
            break;
    }
}

void* gdt::GDTCallbackArgs::get_arg(GDTCBArgsType _args_type, GDTCBArgType _arg_type){
    switch (_args_type) {
        case GDT_CB_INPUT_ARGS:
            if (in_args.find(_arg_type) != in_args.end())
                return in_args[_arg_type];
            else
                return nullptr;

        case GDT_CB_OUTPUT_ARGS:
            if (out_args.find(_arg_type) != out_args.end())
                return out_args[_arg_type];
            else
                return nullptr;

        default:
            break;
    }

    return nullptr;

}

// GDTCallbackMethod
gdt::GDTCallbackMethod::~GDTCallbackMethod() = default;

void gdt::GDTCallbackMethod::run(GDTCallbackArgs* args){
    // implemented in derived classes
}

void gdt::GDTCallbackMethod::cleanup(GDTCallbackArgs* args){
    // implemented in derived classes
}

void gdt::GDTCallbackMethod::set_continue_callback(GDTCallbackMethod* cb){
    cb_cont = cb;
}

void gdt::GDTCallbackMethod::remove_continue_callback(){
    cb_cont = nullptr;
}

void gdt::GDTCallbackMethod::run_continue(GDTCallbackArgs* args){
    if(cb_cont != nullptr) cb_cont->run(args);
}

// GDTCallbackHandler
gdt::GDTCallbackHandler::~GDTCallbackHandler(){
    callback_map.clear();

}

void gdt::GDTCallbackHandler::set_callback(GDTEventType type, GDTCallbackMethod* method){
    if(method != nullptr) callback_map[type] = method;
}

void gdt::GDTCallbackHandler::remove_callback(GDTEventType type){
    callback_map.erase(type);

}

void gdt::GDTCallbackHandler::clear(){
    callback_map.clear();
}

gdt::GDTCallbackMethod* gdt::GDTCallbackHandler::get_callback(GDTEventType type){
    std::map<GDTEventType, GDTCallbackMethod*>::iterator it = callback_map.find(type);
    // check if found
    if(it != callback_map.end()) return it->second;

    return nullptr;

}



bool gdt::GDTCallbackHandler::process_callback(GDTEventType type, GDTCallbackArgs* args){
    // find callback
    std::map<GDTEventType, GDTCallbackMethod*>::iterator it = callback_map.find(type);
    // check if found
    if(it != callback_map.end()){
        // run callback
        it->second->run(args);
        return true;
    }
    return false;


}

bool gdt::GDTCallbackHandler::process_cleanup(GDTEventType type, GDTCallbackArgs* args){
    // find callback
    std::map<GDTEventType, GDTCallbackMethod*>::iterator it = callback_map.find(type);
    // check if found
    if(it != callback_map.end()){
        // run callback
        it->second->cleanup(args);
        return true;
    }
    return false;


}



// GDTPayload
gdt::GDTPayload::GDTPayload() : free_on_send(true),
                                sctp_sid(0),
                                gdt_stream_type(GDT_ST_UNKNOWN),
                                raw_data(nullptr),
                                raw_data_length(0),
                                client(nullptr),
                                stream(nullptr) {}

gdt::GDTPayload::~GDTPayload() = default;


void gdt::GDTPayload::process_callback(GDTEventType type, GDTCallbackArgs* args){
    callback_handler.process_callback(type, args);
}

void gdt::GDTPayload::remove_callback(GDTEventType callback_type){
    callback_handler.remove_callback(callback_type);

}

void gdt::GDTPayload::clear_callbacks(){
    callback_handler.clear();
}

void gdt::GDTPayload::set_callback(GDTEventType callback_type,
                                   GDTCallbackMethod* callback_method){
    callback_handler.set_callback(callback_type, callback_method);
}

// GDTStats
gdt::GDTStats& gdt::GDTStats::operator=(GDTStats& rhs){
    bytes.set(rhs.bytes.get());
    datagram_bytes.set(rhs.datagram_bytes.get());
    datagram_errors.set(rhs.datagram_errors.get());
    datagrams.set(rhs.datagrams.get());
    discarded.set(rhs.discarded.get());
    malformed.set(rhs.malformed.get());
    packets.set(rhs.packets.get());
    stream_bytes.set(rhs.stream_bytes.get());
    stream_errors.set(rhs.stream_errors.get());
    streams.set(rhs.streams.get());
    socket_errors.set(rhs.socket_errors.get());
    strm_alloc_errors.set(rhs.strm_alloc_errors.get());
    strm_timeout.set(rhs.strm_timeout.get());
    strm_loopback.set(rhs.strm_loopback.get());
    return *this;
}

// GDTStateMachine
gdt::GDTStateMachine::GDTStateMachine() : gdtc(nullptr),
                                          res(0),
                                          sctp_len(0),
                                          poll_timeout(1000),
                                          sctp_ntf(nullptr),
                                          sctp_assoc(nullptr),
                                          sctp_flags(0),
                                          tmp_in_session_id(0),
                                          include_body(false),
                                          mem_switch(false),
                                          route_c(nullptr),
                                          route_this(false),
                                          custom_seq_flag(0),
                                          seq_flag_tlv(nullptr),
                                          seq_num_tlv(nullptr),
                                          header(nullptr),
                                          uuid_tlv(nullptr) {
    memset(d_id, 0, sizeof(d_id));
    memset(d_type, 0, sizeof(d_type));
    memset(tmp_buff, 0, sizeof(tmp_buff));

}

gdt::GDTStateMachine::~GDTStateMachine(){
    root_asn1_node.children.clear();
}

void gdt::GDTStateMachine::init(GDTClient* _gdtc){
    gdtc = _gdtc;
    // monitor POLLIN event
    fds_lst[0].events = POLLIN;
    // update socket in poll structure
    fds_lst[0].fd = gdtc->client_socket;
    // set poll timeout to 5 sec
    poll_timeout = gdtc->poll_interval * 1000;
    sctp_flags = 0;
    include_body = false;
    mem_switch = false;
    route_c = nullptr;
    asn1_pool.set_pool_size(MINK_ASN1_PSIZE, MINK_ASN1_PSIZE);
    asn1_pool.init_pool();
    routes.reserve(100);
    route_this = false;
    seq_flag_tlv = nullptr;
    seq_num_tlv = nullptr;
    header = nullptr;
    uuid_tlv = nullptr;
    memset(d_id, 0, sizeof(d_id));
    memset(d_type, 0, sizeof(d_type));

}

void gdt::GDTStateMachine::process_sf_stream_complete(GDTStream* tmp_stream){
    // update timestamp
    tmp_stream->set_timestamp(time(nullptr));

    // validate sequence number
    if(validate_seq_num(seq_num_tlv->value,
                        seq_num_tlv->value_length,
                        tmp_stream->get_sequence_num())){

        // stats
        gdtc->in_stats.stream_bytes.add_fetch(sctp_len);

    }else{
        // stats
        gdtc->in_stats.stream_errors.add_fetch(1);

    }

    // set stream callback args
    cb_stream_args.clear_all_args();
    cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
    cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_STREAM, tmp_stream);
    cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG, &gdt_in_message);
    cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG_ID, &tmp_in_session_id);
    // GDT_ET_STREAM_NEXT event
    tmp_stream->process_callback(GDT_ET_STREAM_END, &cb_stream_args);

}

void gdt::GDTStateMachine::process_sf_end(GDTStream* tmp_stream, bool remove_stream){
    // validate sequence number
    if(validate_seq_num(seq_num_tlv->value,
                        seq_num_tlv->value_length,
                        tmp_stream->get_sequence_num())){

        // stats
        gdtc->in_stats.stream_bytes.add_fetch(sctp_len);
        // update timestamp
        tmp_stream->set_timestamp(time(nullptr));
        // set sequence flag
        tmp_stream->set_sequence_flag(GDT_SF_END);
        // toggle sequence received flag
        tmp_stream->toggle_seq_reply_received();

        // set stream callback args
        cb_stream_args.clear_all_args();
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_STREAM, tmp_stream);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG, &gdt_in_message);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG_ID, &tmp_in_session_id);
        // GDT_ET_STREAM_END event
        tmp_stream->process_callback(GDT_ET_STREAM_END, &cb_stream_args);

        // inc sequenuce number
        if(tmp_stream->get_seq_reply_received()) tmp_stream->inc_sequence_num();


        // create payload
        GDTPayload* gdtp = tmp_stream->get_gdt_payload();
        // set free_on_send flag
        gdtp->free_on_send = remove_stream;
        if(!remove_stream) gdtp->out.set(true);

        // set sctp id
        gdtp->sctp_sid = rcvinfo.sinfo_stream;
        // generate STREAM_COMPLETE
        generate_stream_complete(&gdt_in_message,
                                 tmp_stream->get_gdt_message(),
                                 tmp_in_session_id,
                                 1,
                                 gdtp);


        // set sequence flag
        tmp_stream->set_sequence_flag(GDT_SF_END);

        // remove from list of active streams
        if(remove_stream) gdtc->remove_stream(tmp_stream);

        // send payload
        gdtc->internal_out_queue.push(1, gdtp);


        // sequence error
    }else{
        // stats
        gdtc->in_stats.stream_errors.add_fetch(1);

        // create payload
        GDTPayload* gdtp = tmp_stream->get_gdt_payload();
        // set free_on_send flag
        gdtp->free_on_send = remove_stream;
        if(!remove_stream) gdtp->out.set(true);

        generate_err_uos(this, gdtp, tmp_stream);
        // remove from list of active streams
        if(remove_stream) gdtc->remove_stream(tmp_stream);

        // send payload
        gdtc->internal_out_queue.push(1, gdtp);


    }

}

void gdt::GDTStateMachine::process_sf_continue(GDTStream* tmp_stream, bool remove_stream){
    // validate sequence number
    if(validate_seq_num(seq_num_tlv->value,
                        seq_num_tlv->value_length,
                        tmp_stream->get_sequence_num())){

        // stats
        gdtc->in_stats.stream_bytes.add_fetch(sctp_len);

        // update timestamp
        tmp_stream->set_timestamp(time(nullptr));
        // toggle sequence received flag
        tmp_stream->toggle_seq_reply_received();

        // reset sequence flag (should be set in event handler, defaults to END)
        tmp_stream->set_sequence_flag(GDT_SF_UNKNOWN);

        // set stream callback args
        cb_stream_args.clear_all_args();
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_STREAM, tmp_stream);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG, &gdt_in_message);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG_ID, &tmp_in_session_id);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_BODY, &include_body);
        cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_MEM_SWITCH, &mem_switch);
        // GDT_ET_STREAM_NEXT event
        tmp_stream->process_callback(GDT_ET_STREAM_NEXT, &cb_stream_args);

        // inc sequenuce number
        if(tmp_stream->get_seq_reply_received()) tmp_stream->inc_sequence_num();

        // create payload
        GDTPayload* gdtp = tmp_stream->get_gdt_payload();
        // set sctp sid
        gdtp->sctp_sid = rcvinfo.sinfo_stream;
        // generate ACK
        gdtc->generate_ack(&gdt_in_message,
                           tmp_stream->get_gdt_message(),
                           tmp_in_session_id,
                           1,
                           gdtp,
                           include_body,
                           mem_switch);

        // send payload
        gdtp->free_on_send = false;
        gdtp->out.set(true);

        // toggle sequence received flag
        tmp_stream->toggle_seq_reply_received();
        // inc sequenuce number
        if(tmp_stream->get_seq_reply_received()) tmp_stream->inc_sequence_num();

        gdtc->internal_out_queue.push(1, gdtp);



        // sequence error
    }else{
        // stats
        gdtc->in_stats.stream_errors.add_fetch(1);

        // create payload
        GDTPayload* gdtp = tmp_stream->get_gdt_payload();
        // set free_on_send flag
        gdtp->free_on_send = remove_stream;
        if(!remove_stream) gdtp->out.set(true);

        generate_err_uos(this, gdtp, tmp_stream);

        // remove from list of active streams
        if(remove_stream) gdtc->remove_stream(tmp_stream);

        // send payload
        gdtc->internal_out_queue.push(1, gdtp);

    }

}


void gdt::GDTStateMachine::run(){
    // check stream timeout
    gdtc->process_timeout();
    // check if reconnect procedure was quued in TX thread
    // due to socket write error
    if(gdtc->reconnect_queued.get()){
        // force timeout of all active streams
        gdtc->process_timeout(true);
        // init re-connect procedure
        gdtc->init_reconnect();
        fds_lst[0].fd = gdtc->client_socket;
        // reset reconnection flag
        gdtc->reconnect_queued.comp_swap(true, false);
    }

    // poll socket
    res = poll(fds_lst, 1, poll_timeout);
    // timeout
    if(res == 0){
        // add more callback args
        cb_args.clear_all_args();
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
        // GDT_ET_STREAM_NEW event
        gdtc->process_callback(GDT_ET_CLIENT_IDLE, &cb_args);


    // error
    }else if(res < 0){
        // stats
        gdtc->in_stats.socket_errors.add_fetch(1);
        // force timeout of all active streams
        gdtc->process_timeout(true);
        // init re-connect procedure
        gdtc->init_reconnect();
        fds_lst[0].fd = gdtc->client_socket;
    }


    // check for timeout
    if(res > 0){
        // check for POLLIN event
        if((fds_lst[0].revents & POLLIN) == POLLIN){
            // receive sctp data chunk
            sctp_len = sctp::rcv_sctp(gdtc->client_socket,
                                      tmp_buff,
                                      sizeof(tmp_buff),
                                      &sctp_flags,
                                      &rcvinfo);
            // check for bytes received
            // sctp connection error
            if(sctp_len <= 0){
                // stats
                gdtc->in_stats.socket_errors.add_fetch(1);
                // force timeout of all active streams
                gdtc->process_timeout(true);
                // init re-connect procedure
                gdtc->init_reconnect();
                fds_lst[0].fd = gdtc->client_socket;

                // process message
            }else{
                // check if sctp notification
                if(sctp_flags & MSG_NOTIFICATION){
                    // notification pointer
                    sctp_ntf = (sctp_notification*)tmp_buff;
                    // check type
                    switch(sctp_ntf->sn_header.sn_type){
                        // shutdown
                        case SCTP_SHUTDOWN_EVENT:
                            // reconnect
                            gdtc->reconnect_queued.comp_swap(false, true);
                            break;

                            // abort
                        case SCTP_ASSOC_CHANGE:
                            sctp_assoc = (sctp_assoc_change*)tmp_buff;
                            if(sctp_assoc->sac_state == SCTP_COMM_LOST){
                                // reconnect
                                gdtc->reconnect_queued.comp_swap(false, true);

                            }
                            break;

                        default:
                            break;
                    }


                    // check for GDT PPID
                }else if(be32toh(rcvinfo.sinfo_ppid) == sctp::GDT){
                    // stats
                    gdtc->in_stats.bytes.add_fetch(sctp_len);
                    gdtc->in_stats.packets.add_fetch(1);

                    // reset BER nodes
                    root_asn1_node.children.clear();
                    root_asn1_node.tlv = nullptr;

                    // next in session id
                    tmp_in_session_id = _in_session_id.get_next_id(&gdt_in_message);

                    // decode GDT packet
                    res = asn1::decode((unsigned char*)tmp_buff,
                                       sctp_len,
                                       &root_asn1_node,
                                       &gdt_in_message,
                                       &asn1_pool,
                                       &tmp_in_session_id);
                    // check for error
                    if(res == 0){
                        // version check
                        if(gdt_in_message._header->_version->linked_node->tlv->value[0] != _GDT_VERSION_){
                            // create payload
                            GDTStream* gdts = gdtc->allocate_stream_pool();
                            // null check
                            if(gdts == nullptr){
                                // stats
                                gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                // loop end
                                return;
                            }
                            gdts->set_timestamp(time(nullptr));
                            gdts->clear_callbacks();
                            gdts->linked_stream = nullptr;
                            GDTPayload* gdtp = gdts->get_gdt_payload();
                            // reset
                            gdtp->free_on_send = true;
                            gdtp->gdt_stream_type = GDT_ST_STATELESS;
                            gdtp->client = gdtc;
                            gdtp->sctp_sid = rcvinfo.sinfo_stream;
                            gdtp->clear_callbacks();

                            // generate response
                            gdtc->generate_err(&gdt_in_message,
                                               &gdt_out_message,
                                               tmp_in_session_id,
                                               1,
                                               gdtp,
                                               mem_switch,
                                               -1,
                                               nullptr,
                                               nullptr,
                                               asn1::ErrorCode::_err_unsupported_version);

                            // send payload
                            gdtc->internal_out_queue.push(1, gdtp);

                            // next iteration
                            return;
                        }

                        // find route
                        gdtc->route(&gdt_in_message, tmp_in_session_id, &routes, d_id, d_type);
                        // no routes found
                        if(routes.empty()){

                            // create payload
                            GDTStream* gdts = gdtc->allocate_stream_pool();
                            // null check
                            if(gdts == nullptr){
                                // stats
                                gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                // loop end
                                return;
                            }
                            gdts->set_timestamp(time(nullptr));
                            gdts->clear_callbacks();
                            gdts->linked_stream = nullptr;
                            GDTPayload* gdtp = gdts->get_gdt_payload();
                            // reset
                            gdtp->free_on_send = true;
                            gdtp->gdt_stream_type = GDT_ST_STATELESS;
                            gdtp->client = gdtc;
                            gdtp->sctp_sid = rcvinfo.sinfo_stream;
                            gdtp->clear_callbacks();

                            // detect custom sequence flag (heartbeat or stream-complete)
                            custom_seq_flag =
                                ((gdt_in_message._header->_sequence_flag
                                             ->linked_node->tlv->value[0] ==
                                         asn1::SequenceFlag::_sf_heartbeat)
                                     ? asn1::SequenceFlag::_sf_heartbeat
                                     : -1);

                            // generate response
                            gdtc->generate_err(&gdt_in_message,
                                               &gdt_out_message,
                                               tmp_in_session_id,
                                               1,
                                               gdtp,
                                               mem_switch,
                                               custom_seq_flag,
                                               gdtc->get_session()->get_daemon_type(),
                                               gdtc->get_session()->get_daemon_id(),
                                               asn1::ErrorCode::_err_unknown_route);

                            // send payload
                            gdtc->internal_out_queue.push(1, gdtp);

                            // next iteration
                            return;

                        }

                        // assume no routing to this client
                        route_this = false;

                        // process routes
                        for(unsigned int i = 0; i<routes.size(); i++){
                            route_c = routes[i];
                            // check if packet needs to be routed to some other client or
                            // sent back to sender (sender sending to himself)
                            if((route_c != gdtc) ||
                               (strcmp(route_c->get_end_point_daemon_type(), d_type) == 0)){
                                // create payload
                                GDTStream* gdts = route_c->allocate_stream_pool();
                                // null check
                                if(gdts == nullptr){
                                    // stats
                                    route_c->out_stats.strm_alloc_errors.add_fetch(1);

                                    // ok
                                }else{
                                    gdts->set_timestamp(time(nullptr));
                                    gdts->clear_callbacks();
                                    gdts->linked_stream = nullptr;
                                    GDTPayload* gdtp = gdts->get_gdt_payload();
                                    // reset
                                    gdtp->free_on_send = true;
                                    gdtp->gdt_stream_type = GDT_ST_STATELESS;
                                    gdtp->client = route_c;
                                    gdtp->sctp_sid = rcvinfo.sinfo_stream;
                                    gdtp->clear_callbacks();

                                    // set new GDT header destination id if destination is final
                                    if(!route_c->is_router()){
                                        set_destination_id(&gdt_in_message,
                                                           &gdt_out_message,
                                                           tmp_in_session_id,
                                                           1,
                                                           (unsigned char*)route_c->get_end_point_daemon_id(),
                                                           strlen(route_c->get_end_point_daemon_id()),
                                                           gdtp);

                                        // in case of router destination, just forward packet
                                        // and update hop info
                                        // or return error
                                    }else{
                                        // hop info
                                        if(update_hop_info(&gdt_in_message,
                                                           &gdt_out_message,
                                                           tmp_in_session_id,
                                                           1,
                                                           gdtp) == 1){

                                            // detect custom sequence flag (heartbeat or stream-complete)
                                            custom_seq_flag =
                                                ((gdt_in_message._header
                                                             ->_sequence_flag
                                                             ->linked_node->tlv
                                                             ->value[0] ==
                                                         asn1::SequenceFlag::_sf_heartbeat)
                                                     ? asn1::SequenceFlag::
                                                           _sf_heartbeat
                                                     : -1);

                                            // generate response
                                            gdtc->generate_err(&gdt_in_message,
                                                               &gdt_out_message,
                                                               tmp_in_session_id,
                                                               1,
                                                               gdtp,
                                                               mem_switch,
                                                               custom_seq_flag,
                                                               gdtc->get_session()->get_daemon_type(),
                                                               gdtc->get_session()->get_daemon_id(),
                                                               asn1::ErrorCode::_err_max_hops_exceeded);


                                        }

                                    }

                                    // send payload
                                    route_c->push_out_queue(gdtp);

                                }
                                // dec refc counter
                                route_c->dec_refc();


                                // route to this client
                            }else route_this = true;

                        }
                        // check if current GDT message has to be routed to this client
                        if(!route_this) return;


                        // set defaults
                        include_body = false;
                        mem_switch = false;

                        // set tlv pointers
                        header = gdt_in_message._header;
                        seq_flag_tlv =  header->_sequence_flag->linked_node->tlv;
                        seq_num_tlv = header->_sequence_num->linked_node->tlv;
                        uuid_tlv = header->_uuid->linked_node->tlv;

                        // update timestamp
                        gdtc->timestamp.set(time(nullptr));

                        // GDT_SF_HEARTBEAT - heartbeat
                        if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_heartbeat){

                            // find stream
                            GDTStream* tmp_stream = gdtc->get_stream(uuid_tlv->value);

                            // nullptr check, received heartbeat reply
                            if(tmp_stream != nullptr){
                                // validate seq num
                                if(validate_seq_num(seq_num_tlv->value,
                                                    seq_num_tlv->value_length,
                                                    tmp_stream->get_sequence_num())){

                                    // stats
                                    gdtc->in_stats.streams.add_fetch(1);
                                    gdtc->in_stats.stream_bytes.add_fetch(sctp_len);


                                    // check heartbeat status
                                    if(asn1::node_exists(header->_status, tmp_in_session_id)){

                                        // heartbeat error
                                        if(header->_status->linked_node->tlv->value[0] != 0){
                                            // add more callback args
                                            cb_args.clear_all_args();
                                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
                                            // GDT_ET_HEARTBEAT_MISSED event
                                            gdtc->process_callback(GDT_ET_HEARTBEAT_MISSED, &cb_args);
                                            tmp_stream->process_callback(GDT_ET_HEARTBEAT_MISSED, &cb_args);

                                            // heartbeat ok
                                        }else{
                                            // add more callback args
                                            cb_args.clear_all_args();
                                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
                                            // GDT_ET_HEARTBEAT_RECEIVED event
                                            gdtc->process_callback(GDT_ET_HEARTBEAT_RECEIVED, &cb_args);
                                            tmp_stream->process_callback(GDT_ET_HEARTBEAT_RECEIVED, &cb_args);

                                        }

                                    }


                                    // remove from list of active streams
                                    gdtc->remove_stream(tmp_stream);
                                    // deallocate stream
                                    gdtc->deallocate_stream_pool(tmp_stream);



                                }else{
                                    // stats
                                    gdtc->in_stats.stream_errors.add_fetch(1);

                                    // add more callback args
                                    cb_args.clear_all_args();
                                    cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
                                    // GDT_ET_HEARTBEAT_MISSED event
                                    gdtc->process_callback(GDT_ET_HEARTBEAT_MISSED, &cb_args);
                                    tmp_stream->process_callback(GDT_ET_HEARTBEAT_MISSED, &cb_args);

                                    // remove from list of active streams
                                    gdtc->remove_stream(tmp_stream);
                                    // deallocate stream
                                    gdtc->deallocate_stream_pool(tmp_stream);

                                }

                                // generate heartbeat reply
                                // hbeat request should not contain status node
                            }else if(!asn1::node_exists(header->_status, tmp_in_session_id)){
                                // new stream
                                GDTStream* gdts = gdtc->allocate_stream_pool();
                                // null check
                                if(gdts == nullptr){
                                    // stats
                                    gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                    // loop end
                                    return;
                                }
                                // update timestamp
                                gdts->set_timestamp(time(nullptr));
                                // reset
                                gdts->clear_callbacks();
                                gdts->reset(false);
                                gdts->set_client(gdtc);

                                // create payload
                                GDTPayload* gdtp = gdts->get_gdt_payload();
                                // reset
                                gdtp->free_on_send = true;
                                gdtp->gdt_stream_type = GDT_ST_STATEFUL;
                                gdtp->client = gdtc;
                                gdtp->sctp_sid = rcvinfo.sinfo_stream;
                                gdtp->clear_callbacks();

                                // set sequence flag
                                gdts->set_sequence_flag(GDT_SF_HEARTBEAT);

                                // generate ACK
                                gdtc->generate_ack(&gdt_in_message,
                                                   gdts->get_gdt_message(),
                                                   tmp_in_session_id,
                                                   1,
                                                   gdtp,
                                                   include_body,
                                                   mem_switch);

                                // send payload
                                gdtc->internal_out_queue.push(1, gdtp);

                            }

                            // GDT_SF_STATELESS - single DATAGRAM
                        }else if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_stateless){
                            // stats
                            gdtc->in_stats.datagrams.add_fetch(1);
                            gdtc->in_stats.datagram_bytes.add_fetch(sctp_len);

                            // validate sequence number
                            if(validate_seq_num(seq_num_tlv->value, seq_num_tlv->value_length, 1)){
                                // no error
                                res = asn1::ErrorCode::_err_ok;
                            }else{
                                // sequence error
                                res = asn1::ErrorCode::_err_out_of_sequence;

                                // stats
                                gdtc->in_stats.datagram_errors.add_fetch(1);

                            }

                            // create payload
                            GDTStream* gdts = gdtc->allocate_stream_pool();
                            // null check
                            if(gdts == nullptr){
                                // stats
                                gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                // loop end
                                return;
                            }
                            gdts->set_timestamp(time(nullptr));
                            gdts->clear_callbacks();
                            gdts->linked_stream = nullptr;
                            GDTPayload* gdtp = gdts->get_gdt_payload();
                            // reset
                            gdtp->free_on_send = true;
                            gdtp->gdt_stream_type = GDT_ST_STATELESS;
                            gdtp->client = gdtc;
                            gdtp->sctp_sid = rcvinfo.sinfo_stream;
                            gdtp->clear_callbacks();

                            // generate response
                            gdtc->generate_err(&gdt_in_message,
                                               &gdt_out_message,
                                               tmp_in_session_id,
                                               1,
                                               gdtp,
                                               mem_switch,
                                               -1,
                                               nullptr,
                                               nullptr,
                                               res);


                            // callback args
                            cb_args.clear_all_args();
                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG, &gdt_in_message);
                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG_ID, &tmp_in_session_id);

                            // GDT_ET_DATAGRAM event
                            gdtc->process_callback(GDT_ET_DATAGRAM, &cb_args);

                            // send payload
                            gdtc->internal_out_queue.push(1, gdtp);




                            // GDT_SF_START -  multi packet stream start
                        }else if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_start){
                            // new sequence num must start from 1
                            if(validate_seq_num(seq_num_tlv->value, seq_num_tlv->value_length, 1)){
                                // loopback flag
                                bool loopback = false;
                                // stats
                                gdtc->in_stats.streams.add_fetch(1);
                                gdtc->in_stats.stream_bytes.add_fetch(sctp_len);
                                // check if stream exists
                                GDTStream* tmp_stream = gdtc->get_stream(uuid_tlv->value);
                                // check if stream exists
                                if(tmp_stream != nullptr){
                                    // check if not yet linked and locally initiated
                                    if((tmp_stream->linked_stream == nullptr) &&
                                       (tmp_stream->initiator == GDT_SIT_LOCAL)){
                                        // new stream
                                        GDTStream* new_stream = gdtc->allocate_stream_pool();
                                        // null check
                                        if(new_stream == nullptr){
                                            // stats
                                            gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                            // return, err
                                            return;
                                        }
                                        // link streams
                                        tmp_stream->linked_stream = new_stream;
                                        // set last used
                                        tmp_stream->last_linked_side = new_stream;
                                        // switch pointer to new stream
                                        tmp_stream = new_stream;
                                        // set flag
                                        loopback = true;
                                        // counter
                                        gdtc->in_stats.strm_loopback.add_fetch(1);

                                        // duplicate stream initialized from remote end, error
                                    }else return;

                                    // new stream
                                }else tmp_stream = gdtc->allocate_stream_pool();

                                // null check
                                if(tmp_stream == nullptr){
                                    // stats
                                    gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                    // loop end
                                    return;
                                }
                                // update timestamp
                                tmp_stream->set_timestamp(time(nullptr));
                                // set uuid
                                tmp_stream->set_uuid(uuid_tlv->value);
                                // reset
                                tmp_stream->clear_callbacks();
                                tmp_stream->reset(false);
                                tmp_stream->set_client(gdtc);
                                // add to list of active streams
                                if(!loopback) gdtc->add_stream(tmp_stream);

                                // create payload
                                GDTPayload* gdtp = tmp_stream->get_gdt_payload();
                                // reset
                                gdtp->free_on_send = false;
                                gdtp->out.set(true);
                                gdtp->gdt_stream_type = GDT_ST_STATEFUL;
                                gdtp->client = gdtc;
                                gdtp->sctp_sid = rcvinfo.sinfo_stream;
                                gdtp->clear_callbacks();

                                // reset sequence flag (should be set in event handler, defaults to END)
                                tmp_stream->set_sequence_flag(GDT_SF_UNKNOWN);

                                // add more callback args
                                cb_args.clear_all_args();
                                cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG, &gdt_in_message);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG_ID, &tmp_in_session_id);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_BODY, &include_body);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_MEM_SWITCH, &mem_switch);
                                cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_STREAM, tmp_stream);

                                // GDT_ET_STREAM_NEW event
                                gdtc->process_callback(GDT_ET_STREAM_NEW, &cb_args);

                                // generate ACK
                                gdtc->generate_ack(&gdt_in_message,
                                                   tmp_stream->get_gdt_message(),
                                                   tmp_in_session_id,
                                                   1,
                                                   gdtp,
                                                   include_body,
                                                   mem_switch);

                                // toggle sequence received flag
                                tmp_stream->toggle_seq_reply_received();
                                // inc sequence number
                                tmp_stream->inc_sequence_num();

                                // send payload
                                gdtc->internal_out_queue.push(1, gdtp);




                                // sequence error
                            }else{
                                // stats
                                gdtc->in_stats.stream_errors.add_fetch(1);

                                // create payload
                                GDTStream* gdts = gdtc->allocate_stream_pool();
                                // null check
                                if(gdts == nullptr){
                                    // stats
                                    gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                    // loop end
                                    return;
                                }
                                GDTPayload* gdtp = gdts->get_gdt_payload();
                                gdts->clear_callbacks();
                                gdts->linked_stream = nullptr;
                                // reset
                                gdtp->free_on_send = true;
                                gdtp->client = gdtc;
                                gdtp->sctp_sid = rcvinfo.sinfo_stream;
                                gdtp->clear_callbacks();

                                // generate ERR
                                gdtc->generate_err(&gdt_in_message,
                                                   &gdt_out_message,
                                                   tmp_in_session_id,
                                                   1,
                                                   gdtp,
                                                   mem_switch,
                                                   -1,
                                                   nullptr,
                                                   nullptr,
                                                   asn1::ErrorCode::_err_out_of_sequence);

                                // send payload
                                gdtc->internal_out_queue.push(1, gdtp);

                            }


                            // GDT_SF_CONTINUE - multi packet stream part
                        }else if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_continue){
                            // find stream
                            GDTStream* tmp_stream = gdtc->get_stream(uuid_tlv->value);
                            if(tmp_stream != nullptr){
                                if(tmp_stream->linked_stream != nullptr){
                                    // check which side needs to process sf_continue

                                    // sender part
                                    if(tmp_stream->last_linked_side == tmp_stream){
                                        // process
                                        process_sf_continue(tmp_stream->linked_stream, false);
                                        // set last used
                                        tmp_stream->last_linked_side = tmp_stream->linked_stream;

                                        // linked part
                                    }else{
                                        // process
                                        process_sf_continue(tmp_stream, false);
                                        // set last used
                                        tmp_stream->last_linked_side = tmp_stream;

                                    }


                                    // no linked stream, process
                                }else process_sf_continue(tmp_stream, true);


                                // unknown stream
                            }else{
                                GDTPayload *gdtp = generate_err_unkn_strm(this);

                                // send payload
                                if(gdtp != nullptr) gdtc->internal_out_queue.push(1, gdtp);

                            }


                            // GDT_SF_CONTINUE_WAIT - multi packet stream part
                            // do nothing, expect another SF-CONTINUE from peer
                        }else if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_continue_wait){
                            // find stream
                            GDTStream* tmp_stream = gdtc->get_stream(uuid_tlv->value);
                            // nullptr check
                            if(tmp_stream != nullptr){
                                // validate sequence number
                                if(validate_seq_num(seq_num_tlv->value,
                                                    seq_num_tlv->value_length,
                                                    tmp_stream->get_sequence_num())){

                                    // stats
                                    gdtc->in_stats.stream_bytes.add_fetch(sctp_len);

                                    // update timestamp
                                    tmp_stream->set_timestamp(time(nullptr));

                                    // set sequence flag
                                    tmp_stream->set_sequence_flag(GDT_SF_CONTINUE_WAIT);

                                    // do nothing

                                    // sequence error
                                }else{
                                    // stats
                                    gdtc->in_stats.stream_errors.add_fetch(1);

                                    // create payload
                                    GDTPayload* gdtp = tmp_stream->get_gdt_payload();
                                    tmp_stream->linked_stream = nullptr;
                                    // set free_on_send flag
                                    gdtp->free_on_send = true;
                                    generate_err_uos(this, gdtp, tmp_stream);

                                    // remove from list of active streams
                                    gdtc->remove_stream(tmp_stream);

                                    // send payload
                                    gdtc->internal_out_queue.push(1, gdtp);

                                }
                                // unknown stream
                            }else{
                                // stats
                                gdtc->in_stats.stream_errors.add_fetch(1);

                                // create payload
                                GDTStream* gdts = gdtc->allocate_stream_pool();
                                // null check
                                if(gdts == nullptr){
                                    // stats
                                    gdtc->in_stats.strm_alloc_errors.add_fetch(1);
                                    // loop end
                                    return;
                                }
                                GDTPayload* gdtp = gdts->get_gdt_payload();
                                gdts->clear_callbacks();
                                gdts->linked_stream = nullptr;
                                // reset
                                gdtp->free_on_send = true;
                                gdtp->gdt_stream_type = GDT_ST_UNKNOWN;
                                gdtp->client = gdtc;
                                gdtp->sctp_sid = rcvinfo.sinfo_stream;
                                gdtp->clear_callbacks();
                                // generate ERR
                                gdtc->generate_err(&gdt_in_message,
                                                   &gdt_out_message,
                                                   tmp_in_session_id,
                                                   1,
                                                   gdtp,
                                                   mem_switch,
                                                   -1,
                                                   nullptr,
                                                   nullptr,
                                                   asn1::ErrorCode::_err_unknown_sequence);

                                // send payload
                                gdtc->internal_out_queue.push(1, gdtp);

                            }

                            // GDT_SF_END - stream ending
                        }else if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_end){
                            // find stream
                            GDTStream* tmp_stream = gdtc->get_stream(uuid_tlv->value);
                            // nullptr check
                            if(tmp_stream != nullptr){
                                if(tmp_stream->linked_stream != nullptr){
                                    // check which side needs to process sf_end

                                    // sender part
                                    if(tmp_stream->last_linked_side == tmp_stream){
                                        // process
                                        process_sf_end(tmp_stream->linked_stream, false);
                                        // set last used
                                        tmp_stream->last_linked_side = tmp_stream->linked_stream;

                                        // linked part
                                    }else{
                                        // process
                                        process_sf_end(tmp_stream, false);
                                        // set last used
                                        tmp_stream->last_linked_side = tmp_stream;

                                    }
                                    // no linked stream, process
                                }else process_sf_end(tmp_stream, true);

                                // unknown stream
                            }else{
                                GDTPayload *gdtp = generate_err_unkn_strm(this);

                                // send payload
                                if(gdtp != nullptr) gdtc->internal_out_queue.push(1, gdtp);

                            }
                            // stream finished
                        }else if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_stream_complete){
                            // find stream
                            GDTStream* tmp_stream = gdtc->get_stream(uuid_tlv->value);
                            // nullptr check
                            if(tmp_stream != nullptr){

                                if(tmp_stream->linked_stream != nullptr){
                                    // check which side needs to process sf_end

                                    // sender part
                                    if(tmp_stream->last_linked_side == tmp_stream){
                                        // process
                                        process_sf_stream_complete(tmp_stream->linked_stream);
                                        // set last used
                                        tmp_stream->last_linked_side = tmp_stream->linked_stream;

                                        // linked part
                                    }else{
                                        // process
                                        process_sf_stream_complete(tmp_stream);
                                        // set last used
                                        tmp_stream->last_linked_side = tmp_stream;

                                    }
                                    // no linked stream, process
                                }else process_sf_stream_complete(tmp_stream);

                                // remove from list of active streams
                                gdtc->remove_stream(tmp_stream);
                                // check linked
                                if(tmp_stream->linked_stream != nullptr){
                                    gdtc->remove_stream(tmp_stream->linked_stream);
                                    gdtc->deallocate_stream_pool(tmp_stream->linked_stream);
                                }
                                // deallocate stream
                                gdtc->deallocate_stream_pool(tmp_stream);


                            }

                            // GDT_ST_STATELESS_NO_REPLY - single DATAGRAM without reply
                        }else if(seq_flag_tlv->value[0] == asn1::SequenceFlag::_sf_stateless_no_reply){
                            // stats
                            gdtc->in_stats.datagram_bytes.add_fetch(sctp_len);
                            gdtc->in_stats.datagrams.add_fetch(1);

                            // do nothing for now, reliability is SCTP dependent

                            // callback args
                            cb_args.clear_all_args();
                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG, &gdt_in_message);
                            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_IN_MSG_ID, &tmp_in_session_id);

                            // GDT_ET_DATAGRAM event
                            gdtc->process_callback(GDT_ET_DATAGRAM, &cb_args);

                        }


                    }else{
                        // stats
                        gdtc->in_stats.malformed.add_fetch(1);
                    }
                }else{
                    // stats
                    gdtc->in_stats.discarded.add_fetch(1);
                }
            }

        }else if(fds_lst[0].revents != 0){
            // force timeout of all active streams
            gdtc->process_timeout(true);
            // init re-connect procedure
            gdtc->init_reconnect();
            fds_lst[0].fd = gdtc->client_socket;


        }
        // socket idle
    }else if(res == 0){
        // add more callback args
        cb_args.clear_all_args();
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
        // GDT_ET_STREAM_NEW event
        gdtc->process_callback(GDT_ET_CLIENT_IDLE, &cb_args);

        // socket error
    }else{
        // stats
        gdtc->in_stats.socket_errors.add_fetch(1);
        // force timeout of all active streams
        gdtc->process_timeout(true);
        // init re-connect procedure
        gdtc->init_reconnect();
        fds_lst[0].fd = gdtc->client_socket;
    }

}

// GDTClient
void gdt::GDTClient::init(){
    client_id = -1;
    client_socket = -1;
    router = false;
    in_thread = 0;
    out_thread = 0;
    timeout_thread = 0;
    exit_thread = 0;
    end_point_port = 0;
    local_point_port = 0;
    direction = GDT_CD_UNKNOWN;
    session = nullptr;
    streams.reserve(max_concurrent_streams);

    // mutexes
    pthread_mutex_init(&mtx_streams, nullptr);
    pthread_spin_init(&slock_callback, 0);
    pthread_spin_init(&slock_uuid, 0);

    // random generator
    timespec tmp_time;
    clock_gettime(0, &tmp_time);

    // queues
    out_queue.set_capacity(max_concurrent_streams);
    internal_out_queue.init(max_concurrent_streams);

    // memory pools
    mc_pool.init(max_concurrent_streams);
    mc_pool.construct_objects();

    pld_pool.init(max_concurrent_streams);
    pld_pool.construct_objects();

    gdtm_pool.init(max_concurrent_streams);
    gdtm_pool.construct_objects();

    stream_pool.init(max_concurrent_streams);
    stream_pool.construct_objects();

    // allocate raw payload buffers for GDTPayload objects
    GDTPayload* tmp_pld[pld_pool.get_chunk_count()];
    for(int i = 0; i<pld_pool.get_chunk_count(); i++){
        tmp_pld[i] = pld_pool.allocate_constructed();
        tmp_pld[i]->raw_data = mc_pool.allocate_constructed()->buffer;
    }
    for(int i = 0; i<pld_pool.get_chunk_count(); i++) pld_pool.deallocate_constructed(tmp_pld[i]);


    // set random generator, pld and msg for GDTStream objects
    GDTStream* tmp_stream[stream_pool.get_chunk_count()];
    for(int i = 0; i<stream_pool.get_chunk_count(); i++){
        tmp_stream[i] = stream_pool.allocate_constructed();
        tmp_stream[i]->set_random_generator(&random_generator);
        tmp_stream[i]->set_client(this);
        tmp_stream[i]->set_gdt_message(gdtm_pool.allocate_constructed());
        tmp_stream[i]->set_gdt_payload(pld_pool.allocate_constructed());
        tmp_stream[i]->get_gdt_payload()->stream = tmp_stream[i];
    }
    for(int i = 0; i<stream_pool.get_chunk_count(); i++) stream_pool.deallocate_constructed(tmp_stream[i]);


}

gdt::GDTClient::GDTClient() : max_concurrent_streams(100) {
    // main init
    init();

}

gdt::GDTClient::GDTClient(int _client_socket,
                          const char* _end_point_address,
                          unsigned int _end_point_port,
                          const char* _local_point_address,
                          unsigned int _local_point_port,
                          GDTConnectionDirection _direction,
                          int _max_concurrent_streams,
                          int _stream_timeout,
                          int _poll_interval) : client_socket(_client_socket),
                                                client_id(_local_point_port),
                                                poll_interval(_poll_interval),
                                                end_point_port(_end_point_port),
                                                local_point_port(_local_point_port),
                                                direction(_direction),
                                                max_concurrent_streams(_max_concurrent_streams),
                                                stream_timeout(_stream_timeout){


    ref_counter.set(1);

    // main init
    init();

    // connection params
    direction = _direction;
    client_socket = _client_socket;
    poll_interval = _poll_interval;
    client_id = _local_point_port;
    end_point_address.assign(_end_point_address);
    local_point_address.assign(_local_point_address);
    end_point_port = _end_point_port;
    local_point_port = _local_point_port;

    // set as active
    set_activity(true);


}

gdt::GDTClient::~GDTClient(){
    // set as inactive
    set_activity(false);
    // wait for threads to fnish
    timespec st = {0, 100000000};
    while(get_thread_count() > 0){
        nanosleep(&st, nullptr);
    }

    // disconnect just in case
    if(client_socket > 0) disconnect();


    // deallocate active streams
    std::all_of(streams.cbegin(), streams.cend(), [this](GDTStream *s) {
        if (s != nullptr) {
            deallocate_stream_pool(s);
        }
        return true;
    });
    // clear active stream list
    streams.clear();

    // deallocate extra stream memory
    GDTStream* tmp_stream[stream_pool.get_chunk_count()];
    for(int i = 0; i<stream_pool.get_chunk_count(); i++){
        tmp_stream[i] = stream_pool.allocate_constructed();
        // sanity check
        if(tmp_stream[i] == nullptr) continue;
        // * deallocate_mc_pool expects a pointer to MemChunk
        // * buffer is the first field in MemChunk class so both MemChunk class and
        // * MemChunk.buffer field share the same address
        // * this makes type casting the MemChunk.raw_data to MemChunk valid
        deallocate_mc_pool((memory::MemChunk<MEM_CSIZE>*)tmp_stream[i]->get_gdt_payload()->raw_data);
        deallocate_pld_pool(tmp_stream[i]->get_gdt_payload());
        deallocate_gdtm_pool(tmp_stream[i]->get_gdt_message());
    }
    for (int i = 0; i < stream_pool.get_chunk_count(); i++)
        stream_pool.deallocate_constructed(tmp_stream[i]);

    // destory mutexes
    pthread_mutex_destroy(&mtx_streams);
    pthread_spin_destroy(&slock_callback);
    pthread_spin_destroy(&slock_uuid);
}


uint32_t gdt::GDTClient::inc_refc(){
    return ref_counter.add_fetch(1);
}

uint32_t gdt::GDTClient::dec_refc(){
    return ref_counter.sub_fetch(1);
}

uint32_t gdt::GDTClient::get_refc(){
    return ref_counter.get();
}


int gdt::GDTClient::deallocate_mc_pool(memory::MemChunk<MEM_CSIZE>* mem_chunk){
    if(mem_chunk != nullptr){
        int res = mc_pool.deallocate_constructed(mem_chunk);
        return res;

    }
    return -1;

}

memory::MemChunk<gdt::MEM_CSIZE>* gdt::GDTClient::allocate_mc_pool(){
    memory::MemChunk<MEM_CSIZE>* tmp = mc_pool.allocate_constructed();
    return tmp;
}



int gdt::GDTClient::deallocate_pld_pool(GDTPayload* gdtpld){
    if(gdtpld != nullptr){
        int res = pld_pool.deallocate_constructed(gdtpld);
        return res;

    }
    return -1;

}

gdt::GDTPayload* gdt::GDTClient::allocate_pld_pool(){
    GDTPayload* tmp = pld_pool.allocate_constructed();
    return tmp;
}



int gdt::GDTClient::deallocate_gdtm_pool(asn1::GDTMessage* gdtm){
    if(gdtm != nullptr){
        int res = gdtm_pool.deallocate_constructed(gdtm);
        return res;

    }
    return -1;

}

asn1::GDTMessage* gdt::GDTClient::allocate_gdtm_pool(){
    asn1::GDTMessage* tmp = gdtm_pool.allocate_constructed();
    return tmp;
}

int gdt::GDTClient::deallocate_stream_pool(GDTStream* stream){
    if(stream != nullptr){
        int res = stream_pool.deallocate_constructed(stream);
        return res;

    }
    return -1;

}

gdt::GDTStream* gdt::GDTClient::allocate_stream_pool(){
    return stream_pool.allocate_constructed();
}

int gdt::GDTClient::push_out_queue(GDTPayload* payload){
    if(payload != nullptr){
        bool res = out_queue.push(payload);
        return !res;

    }

    return -1;
}
gdt::GDTPayload* gdt::GDTClient::pop_out_queue(){
    GDTPayload* tmp = nullptr;
    out_queue.pop(&tmp);
    return tmp;

}

int gdt::GDTClient::generate_uuid(unsigned char* out){
    if(out == nullptr) return 1;
    pthread_spin_lock(&slock_uuid);
    random_generator.generate(out, 16);
    pthread_spin_unlock(&slock_uuid);
    return 0;
}


uint8_t gdt::GDTClient::is_active(){
    return active.get();

}

void gdt::GDTClient::set_activity(bool _is_active){
    active.comp_swap(!_is_active, _is_active);

}

int gdt::GDTClient::get_client_id() const {
    return client_id;
}

int gdt::GDTClient::get_client_socket() const {
    return client_socket;

}
const char* gdt::GDTClient::get_end_point_address() const{
    return end_point_address.c_str();
}

unsigned int gdt::GDTClient::get_end_point_port() const {
    return end_point_port;
}

const char* gdt::GDTClient::get_local_point_address() const {
    return local_point_address.c_str();
}

unsigned int gdt::GDTClient::get_local_point_port() const {
    return local_point_port;
}

void gdt::GDTClient::set_router_flag(bool _is_router){
    router = _is_router;
}

bool gdt::GDTClient::is_router() const {
    return router;
}



int gdt::GDTClient::send(unsigned int sctp_stream_id,
                         const unsigned char* data,
                         unsigned int data_length) const {
    if(data != nullptr){
        return sctp::send_sctp(client_socket, data, data_length, sctp::GDT, sctp_stream_id);
    }
    // err
    return -1;
}

int gdt::GDTClient::send_datagram(asn1::Body* body,
                                  GDTCallbackMethod* on_sent_callback_method,
                                  GDTCallbackMethod* on_reply_callback_method,
                                  const char *dest_daemon_type,
                                  const char *dest_daemon_id){


    GDTStream* gdts = allocate_stream_pool();
    // null check
    if(gdts == nullptr) return 1;
    GDTPayload* gdtp = gdts->get_gdt_payload();
    asn1::GDTMessage* gdt_out_message = gdts->get_gdt_message();
    gdts->clear_callbacks();
    gdts->reset(true);


    // next session id
    uint64_t tmp_session_id = 1;
    bool prepare_needed = false;
    asn1::Header *hdr = gdt_out_message->_header;
    asn1::Body *bdy = gdt_out_message->_body;

    // set optional
    // source id
    if(hdr->_source->_id == nullptr) {
        hdr->_source->set_id();
        prepare_needed = true;
    }

    // destination id
    if(hdr->_destination->_id == nullptr) {
        hdr->_destination->set_id();
        prepare_needed = true;
    }

    // body
    if(bdy == nullptr) {
        gdt_out_message->set_body();
        prepare_needed = true;
        bdy = gdt_out_message->_body;
    }else{
        bdy->unlink(tmp_session_id);

    }



    // prepare only if one of optional fields was not set
    if(prepare_needed) gdt_out_message->prepare();

    // insert body
    bdy->choice_selection = body->choice_selection;
    bdy->choice_selection->parent_node = gdt_out_message->_body;
    // reset old_value_flag to recalculate parent nodes
    bdy->choice_selection->linked_node->tlv->old_value_length = 0;
    // recalculate choice selection and update parent nodes
    bdy->choice_selection->set_linked_data(tmp_session_id);

    // unlink status if exists
    if (hdr->_status != nullptr)
        hdr->_status->unlink(tmp_session_id);

    // header
    int ver = _GDT_VERSION_;
    hdr->_version->set_linked_data(tmp_session_id,
                                   (unsigned char*)&ver,
                                   1);
    hdr->_source->_id->set_linked_data(tmp_session_id,
                                       (unsigned char*)session->get_daemon_id(),
                                       strlen(session->get_daemon_id()));
    hdr->_source->_type->set_linked_data(tmp_session_id,
                                         (unsigned char*)session->get_daemon_type(),
                                         strlen(session->get_daemon_type()));
    hdr->_destination->_id->set_linked_data(tmp_session_id,
                                            (unsigned char*)dest_daemon_id,
                                            strlen(dest_daemon_id));
    hdr->_destination->_type->set_linked_data(tmp_session_id,
                                              (unsigned char*)dest_daemon_type,
                                              strlen(dest_daemon_type));
    hdr->_uuid->set_linked_data(tmp_session_id, gdts->get_uuid(), 16);
    uint32_t seq_num = htobe32(1);
    hdr->_sequence_num->set_linked_data(tmp_session_id,
                                        (unsigned char*)&seq_num,
                                        sizeof(uint32_t));

    // check if waiting for reply
    // do not wait for reply
    if(on_reply_callback_method == nullptr){
        gdtp->free_on_send = true;
        int sf = asn1::SequenceFlag::_sf_stateless_no_reply;
        gdtp->gdt_stream_type = GDT_ST_STATELESS_NO_REPLY;
        hdr->_sequence_flag->set_linked_data(tmp_session_id, (unsigned char*)&sf, 1);
        // wait for reply
    }else{
        int sf = asn1::SequenceFlag::_sf_stateless;
        hdr->_sequence_flag->set_linked_data(tmp_session_id, (unsigned char*)&sf, 1);
        gdtp->free_on_send = false;
        gdtp->sctp_sid = 0;
        gdtp->gdt_stream_type = GDT_ST_STATELESS;
        gdts->set_callback(GDT_ET_STREAM_END, on_reply_callback_method);
        gdts->set_sequence_flag(GDT_SF_STATELESS);
        add_stream(gdts);
    }

    gdtp->raw_data_length = asn1::encode(gdtp->raw_data,
                                         MEM_CSIZE,
                                         gdt_out_message,
                                         tmp_session_id);
    gdtp->client = this;
    gdtp->clear_callbacks();
    gdtp->stream->set_callback(GDT_ET_PAYLOAD_SENT, on_sent_callback_method);
    // send to queue
    push_out_queue(gdtp);


    return 0;

}



int gdt::GDTClient::send_datagram(int payload_type,
                                  unsigned char* payload,
                                  int payload_length,
                                  GDTCallbackMethod* on_sent_callback_method,
                                  GDTCallbackMethod* on_reply_callback_method,
                                  const char* dest_daemon_type,
                                  const char* dest_daemon_id){

    GDTStream* gdts = allocate_stream_pool();
    // null check
    if(gdts == nullptr) return 1;

    GDTPayload* gdtp = gdts->get_gdt_payload();
    asn1::GDTMessage* gdt_out_message = gdts->get_gdt_message();
    gdts->clear_callbacks();
    gdts->reset(true);


    // next session id
    uint64_t tmp_session_id = 1;
    bool prepare_needed = false;
    asn1::Header *hdr = gdt_out_message->_header;
    asn1::Body *bdy = gdt_out_message->_body;

    // set optional
    // source id
    if(hdr->_source->_id == nullptr) {
        hdr->_source->set_id();
        prepare_needed = true;
    }

    // destination id
    if(hdr->_destination->_id == nullptr) {
        hdr->_destination->set_id();
        prepare_needed = true;
    }

    // body
    if(bdy == nullptr) {
        gdt_out_message->set_body();
        prepare_needed = true;
        bdy = gdt_out_message->_body;
    }else{
        bdy->unlink(tmp_session_id);
        bdy->_data->set_linked_data(tmp_session_id);
    }

    // data payload
    if(bdy->_data->_payload == nullptr) {
        bdy->_data->set_payload();
        prepare_needed = true;
    }
    // prepare only if one of optional fields was not set
    if(prepare_needed) gdt_out_message->prepare();



    // unlink status if exists
    if(hdr->_status != nullptr) hdr->_status->unlink(tmp_session_id);

    // header
    int ver = _GDT_VERSION_;
    hdr->_version->set_linked_data(tmp_session_id, (unsigned char*)&ver, 1);
    hdr->_source->_id->set_linked_data(tmp_session_id,
                                       (unsigned char*)session->get_daemon_id(),
                                       strlen(session->get_daemon_id()));
    hdr->_source->_type->set_linked_data(tmp_session_id,
                                         (unsigned char*)session->get_daemon_type(),
                                         strlen(session->get_daemon_type()));
    hdr->_destination->_id->set_linked_data(tmp_session_id,
                                            (unsigned char*)dest_daemon_id,
                                            strlen(dest_daemon_id));
    hdr->_destination->_type->set_linked_data(tmp_session_id,
                                              (unsigned char*)dest_daemon_type,
                                              strlen(dest_daemon_type));

    hdr->_uuid->set_linked_data(tmp_session_id, gdts->get_uuid(), 16);

    uint32_t seq_num = htobe32(1);
    hdr->_sequence_num->set_linked_data(tmp_session_id,
                                        (unsigned char*)&seq_num,
                                        sizeof(uint32_t));

    // body
    uint16_t tmp_i = htobe16(payload_type);
    bdy->_data->_payload_type->set_linked_data(tmp_session_id, (unsigned char*)&tmp_i, 1);
    bdy->_data->_payload->set_linked_data(tmp_session_id, payload, payload_length);


    // gdt payload
    // check if waiting for reply
    // do not wait for reply
    if(on_reply_callback_method == nullptr){
        gdtp->free_on_send = true;
        int sf = asn1::SequenceFlag::_sf_stateless_no_reply;
        gdtp->gdt_stream_type = GDT_ST_STATELESS_NO_REPLY;
        hdr->_sequence_flag->set_linked_data(tmp_session_id, (unsigned char*)&sf, 1);
        // wait for reply
    }else{
        int sf = asn1::SequenceFlag::_sf_stateless;
        hdr->_sequence_flag->set_linked_data(tmp_session_id, (unsigned char*)&sf, 1);

        gdtp->free_on_send = false;
        gdtp->sctp_sid = 0;
        gdtp->gdt_stream_type = GDT_ST_STATELESS;
        gdts->set_callback(GDT_ET_STREAM_END, on_reply_callback_method);
        gdts->set_sequence_flag(GDT_SF_STATELESS);
        add_stream(gdts);
    }

    gdtp->raw_data_length = asn1::encode(gdtp->raw_data,
                                         MEM_CSIZE,
                                         gdt_out_message,
                                         tmp_session_id);
    gdtp->client = this;
    gdtp->clear_callbacks();
    gdtp->stream->set_callback(GDT_ET_PAYLOAD_SENT, on_sent_callback_method);

    // send to queue
    push_out_queue(gdtp);

    return 0;
}


gdt::GDTStream* gdt::GDTStream::get_linked_stream(){
    return linked_stream;
}
void gdt::GDTStream::set_linked_stream(gdt::GDTStream *strm){
    linked_stream = strm;
}


void gdt::GDTStream::set_gdt_payload(GDTPayload* _gdt_payload){
    gdt_payload = _gdt_payload;
}


gdt::GDTClient* gdt::GDTStream::get_client(){
    return client;
}


gdt::GDTPayload* gdt::GDTStream::get_gdt_payload(){
    return gdt_payload;
}

asn1::GDTMessage* gdt::GDTStream::get_gdt_message(){
    return gdt_message;
}

void gdt::GDTStream::set_gdt_message(asn1::GDTMessage* _gdt_message){
    gdt_message = _gdt_message;
}

void gdt::GDTStream::set_destination(const char* _dest_type, const char* _dest_id){
    // null ptr check
    if(_dest_type == nullptr) return;
    destination_type.assign(_dest_type);

    // destination id null ptr check
    if(_dest_id != nullptr) {
        destination_id.assign(_dest_id);
    }

}


gdt::GDTStream* gdt::GDTClient::new_stream(const char* _dest_type,
        const char* _dest_id,
        GDTCallbackMethod* _on_sent_callback,
        GDTCallbackMethod* _on_reply_callback){
    if(_dest_type == nullptr) return nullptr;
    GDTStream* stream = allocate_stream_pool();
    if(stream != nullptr/* && gdtm != nullptr*/){
        stream->set_client(this);
        stream->reset(true);
        stream->clear_callbacks();
        stream->set_destination(_dest_type, _dest_id);
        stream->set_callback(GDT_ET_PAYLOAD_SENT, _on_sent_callback);
        stream->set_callback(GDT_ET_STREAM_NEXT, _on_reply_callback);
        add_stream(stream);
        return stream;


    }
    return nullptr;
}

gdt::GDTStream* gdt::GDTClient::create_stream(){
    GDTStream* stream = allocate_stream_pool();
    if(stream == nullptr) return nullptr;
    stream->set_client(this);
    return stream;
}

void gdt::GDTClient::add_stream(gdt::GDTStream* _stream){
    pthread_mutex_lock(&mtx_streams);
    streams.push_back(_stream);
    streams_active.set(true);
    pthread_mutex_unlock(&mtx_streams);

}

bool gdt::GDTClient::stream_exists(const GDTStream* _stream){
    pthread_mutex_lock(&mtx_streams);
    for(unsigned int i = 0; i<streams.size(); i++) if(streams[i] == _stream) {
        pthread_mutex_unlock(&mtx_streams);
        return true;
    }
    pthread_mutex_unlock(&mtx_streams);
    return false;
}



void gdt::GDTClient::remove_stream(const gdt::GDTStream* _stream){
    pthread_mutex_lock(&mtx_streams);
    for(unsigned int i = 0; i<streams.size(); i++){
        if(streams[i] == _stream){
            streams.erase(streams.begin() + i);
            if(streams.empty()) streams_active.set(false);
            break;
        }
    }
    pthread_mutex_unlock(&mtx_streams);

}

void gdt::GDTClient::remove_stream_unsafe(const gdt::GDTStream* _stream){
    for(unsigned int i = 0; i<streams.size(); i++){
        if(streams[i] == _stream){
            streams.erase(streams.begin() + i);
            if(streams.empty()) streams_active.set(false);
            break;
        }
    }

}

int  gdt::GDTClient::get_stream_count(){
    pthread_mutex_lock(&mtx_streams);
    int c = streams.size();
    pthread_mutex_unlock(&mtx_streams);
    return c;

}
gdt::GDTStream* gdt::GDTClient::get_stream(unsigned int index){
    pthread_mutex_lock(&mtx_streams);
    if(streams.size() > index){
        GDTStream* stream = streams[index];
        pthread_mutex_unlock(&mtx_streams);
        return stream;
    }
    pthread_mutex_unlock(&mtx_streams);

    return nullptr;
}

gdt::GDTStream* gdt::GDTClient::get_stream(const unsigned char* _uuid){
    if(_uuid == nullptr) return nullptr;
    GDTStream* stream = nullptr;
    pthread_mutex_lock(&mtx_streams);
    for(unsigned int i = 0; i<streams.size(); i++){
        stream = streams[i];
        if(memcmp(stream->get_uuid(), _uuid, 16) == 0){
            pthread_mutex_unlock(&mtx_streams);
            return stream;
        }
    }
    pthread_mutex_unlock(&mtx_streams);
    return nullptr;
}

void gdt::GDTClient::remove_callback(GDTEventType callback_type, bool unsafe){
    if(!unsafe) pthread_spin_lock(&slock_callback);
    callback_handler.remove_callback(callback_type);
    if(!unsafe) pthread_spin_unlock(&slock_callback);

}

void gdt::GDTClient::set_callback(GDTEventType callback_type, GDTCallbackMethod* callback_method, bool unsafe){
    if(!unsafe) pthread_spin_lock(&slock_callback);
    callback_handler.set_callback(callback_type, callback_method);
    if(!unsafe) pthread_spin_unlock(&slock_callback);
}

gdt::GDTCallbackMethod* gdt::GDTClient::get_callback(GDTEventType callback_type, bool unsafe){
    if(!unsafe) pthread_spin_lock(&slock_callback);
    GDTCallbackMethod* res = callback_handler.get_callback(callback_type);
    if(!unsafe) pthread_spin_unlock(&slock_callback);
    return res;
}



bool gdt::GDTClient::process_cleanup(GDTEventType type, GDTCallbackArgs* args){
    pthread_spin_lock(&slock_callback);
    bool res = callback_handler.process_cleanup(type, args);
    pthread_spin_unlock(&slock_callback);
    return res;

}

bool gdt::GDTClient::process_callback(GDTEventType type, GDTCallbackArgs* args){
    pthread_spin_lock(&slock_callback);
    bool res = callback_handler.process_callback(type, args);
    pthread_spin_unlock(&slock_callback);
    return res;
}


int gdt::GDTClient::reconnect_socket(){
    int _socket = -1;
    while((_socket <= 0) && is_active()){
        // connect and bind to specific ip:port
        _socket = sctp::init_sctp_client_bind(inet_addr(end_point_address.c_str()),
                                              0,
                                              inet_addr(local_point_address.c_str()),
                                              0,
                                              local_point_port, end_point_port,
                                              16);
        if(_socket > 0){
            // client active
            GDTCallbackArgs cb_args;
            cb_args.clear_all_args();
            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, this);
            // GDT_ET_CLIENT_RECONNECTED event
            process_callback(GDT_ET_CLIENT_RECONNECTED, &cb_args);
            // return
            return _socket;
        }
        // pause
        sleep(poll_interval);
        // force timeout of all active streams
        process_timeout(true);


    }
    return -1;

}

int gdt::GDTClient::disconnect(){
    // set as inactive
    set_activity(false);
    // shutdown client
    int res = sctp::shutdown_sctp_client(client_socket);
    // socket closed
    if(res == 0) {
        client_socket = -1;
        return 0;
    }
    // error while closing socket
    return -1;
}

void gdt::GDTClient::init_threads(){
    // scheduling parameters
    pthread_attr_init(&in_thread_attr);
    pthread_attr_init(&out_thread_attr);
    pthread_attr_init(&timeout_thread_attr);

#ifdef ENABLE_SCHED_FIFO
    // explicit FIFO scheduling for IN thread
    pthread_attr_setinheritsched(&in_thread_attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&in_thread_attr, SCHED_FIFO);

    // explicit FIFO scheduling for OUT thread
    pthread_attr_setinheritsched(&out_thread_attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&out_thread_attr, SCHED_FIFO);

    // explicit FIFO scheduling for TIMEOUT thread
    pthread_attr_setinheritsched(&timeout_thread_attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&timeout_thread_attr, SCHED_FIFO);

    // priority
    sched_param in_sp;
    sched_param out_sp;
    sched_param timeout_sp;

    // max priority for IN/OUT
    in_sp.sched_priority = 99;
    out_sp.sched_priority = 99;
    // half priority for TIMEOUT
    timeout_sp.sched_priority = 50;

    // set priorities
    pthread_attr_setschedparam(&in_thread_attr, &in_sp);
    pthread_attr_setschedparam(&out_thread_attr, &out_sp);
    pthread_attr_setschedparam(&timeout_thread_attr, &timeout_sp);
#endif

    if(pthread_create(&out_thread, &out_thread_attr, &out_loop, this) == 0) {
        pthread_setname_np(out_thread, "gdt_out");
        inc_thread_count();
    }
    if(pthread_create(&timeout_thread, &timeout_thread_attr, &timeout_loop, this) == 0) {
        pthread_setname_np(timeout_thread, "gdt_timeout");
        inc_thread_count();
    }

    // start threads
    if(pthread_create(&in_thread, &in_thread_attr, &in_loop, this) == 0) {
        pthread_setname_np(in_thread, "gdt_in");
        inc_thread_count();
    }


    // destroy atrributes
    pthread_attr_destroy(&in_thread_attr);
    pthread_attr_destroy(&out_thread_attr);
    pthread_attr_destroy(&timeout_thread_attr);


}

gdt::GDTStats* gdt::GDTClient::get_stats(GDTStatsType stats_type) {
    switch(stats_type){
        case GDT_INBOUND_STATS:
            return &in_stats;

        case GDT_OUTBOUND_STATS:
            return &out_stats;

        default: return nullptr;
    }

}


void gdt::GDTClient::get_stats(GDTStatsType stats_type, GDTStats* result) {
    if(result != nullptr){
        switch(stats_type){
            case GDT_INBOUND_STATS:
                *result = in_stats;
                break;

            case GDT_OUTBOUND_STATS:
                *result = out_stats;
                break;

            default:
                break;
        }
    }
}



void gdt::GDTClient::generate_stream_header(asn1::GDTMessage* gdt_out_message,
                                            GDTStream* stream,
                                            uint64_t _session_id,
                                            GDTPayload* gdtld,
                                            bool _include_body,
                                            const char* _dest_type,
                                            const char* _dest_id) const {

    if((gdt_out_message != nullptr) && (stream != nullptr) && (gdtld != nullptr)){
        bool prepare_needed = false;
        asn1::Header *hdr = gdt_out_message->_header;
        asn1::Body *bdy = gdt_out_message->_body;

        // set optional
        // source id
        if(hdr->_source->_id == nullptr) {
            hdr->_source->set_id();
            prepare_needed = true;
        }


        // destination id
        if(_dest_id != nullptr){
            if(hdr->_destination->_id == nullptr) {
                hdr->_destination->set_id();
                prepare_needed = true;
            }

        }else{
            if(hdr->_destination->_id != nullptr) hdr->_destination->_id->unlink(_session_id);
        }


        if(hdr->_status != nullptr) hdr->_status->unlink(_session_id);

        // body
        if(!_include_body && (bdy != nullptr)){
            bdy->unlink(_session_id);
        }

        // prepare only if one of optional fields was not set
        if(prepare_needed) gdt_out_message->prepare();



        // unlink status if exists
        if(hdr->_status != nullptr) hdr->_status->unlink(_session_id);

        // header
        int ver = _GDT_VERSION_;
        hdr->_version->set_linked_data(_session_id, (unsigned char*)&ver, 1);
        hdr->_source->_id->set_linked_data(_session_id,
                                           (unsigned char*)session->get_daemon_id(),
                                           strlen(session->get_daemon_id()));
        hdr->_source->_type->set_linked_data(_session_id,
                                             (unsigned char*)session->get_daemon_type(),
                                             strlen(session->get_daemon_type()));
        if (_dest_id != nullptr)
            hdr->_destination->_id->set_linked_data(_session_id,
                                                    (unsigned char*)_dest_id,
                                                    strlen(_dest_id));
        hdr->_destination->_type->set_linked_data(_session_id,
                                                  (unsigned char*)_dest_type,
                                                  strlen(_dest_type));

        hdr->_uuid->set_linked_data(_session_id, stream->get_uuid(), 16);

        uint32_t seqn = htobe32(stream->get_sequence_num());
        hdr->_sequence_num->set_linked_data(_session_id, (unsigned char*)&seqn, 4);

        int seqf = stream->get_sequence_flag();
        hdr->_sequence_flag->set_linked_data(_session_id, (unsigned char*)&seqf, 1);
        // encode
        gdtld->raw_data_length = asn1::encode(gdtld->raw_data,
                                              MEM_CSIZE,
                                              gdt_out_message,
                                              _session_id);
    }
}

void gdt::GDTClient::generate_err(asn1::GDTMessage* gdt_orig_message,
                                  asn1::GDTMessage* gdt_out_message,
                                  uint64_t _orig_session_id,
                                  uint64_t _out_session_id,
                                  GDTPayload* gdtld,
                                  bool mem_switch,
                                  int _custom_seq_flag,
                                  const char* _custom_dtype,
                                  const char* _custom_did,
                                  int _error_code){
    if(gdt_orig_message != nullptr){

        // next session id
        uint64_t _session_id = _out_session_id;

        // check optional
        bool prepare_needed = false;
        bool source_id = false;
        asn1::Header *hdr = gdt_out_message->_header;
        asn1::Header *oh = gdt_orig_message->_header;
        asn1::Body *bdy = gdt_out_message->_body;

        // check is status is set
        if(hdr->_status == nullptr){
            hdr->set_status();
            prepare_needed = true;
        }


        if(hdr->_source->_id == nullptr){
            hdr->_source->set_id();
            prepare_needed = true;
        }

        // check if source id is present
        if((oh->_source->_id != nullptr) &&
           (oh->_source->_id->has_linked_data(_orig_session_id))){
            if(hdr->_destination->_id == nullptr){
                hdr->_destination->set_id();
                prepare_needed = true;
            }
            source_id = true;
        }

        // prepare only if one of optional fields was not set
        if(prepare_needed) gdt_out_message->prepare();

        // unlink body if exists
        if(bdy != nullptr) bdy->unlink(_session_id);


        // version
        int ver = _GDT_VERSION_;
        hdr->_version->set_linked_data(_session_id, (unsigned char*)&ver, 1);

        // unlink hop info if exists
        if(hdr->_hop_info != nullptr) hdr->_hop_info->unlink(_session_id);


        // source
        if((_custom_did != nullptr) && (_custom_dtype != nullptr)){
            hdr->_source->_type->set_linked_data(_session_id,
                                                 (unsigned char*)_custom_dtype,
                                                 strlen(_custom_dtype));

            hdr->_source->_id->set_linked_data(_session_id,
                                               (unsigned char*)_custom_did,
                                               strlen(_custom_did));

        }else{
            hdr->_source->_type->set_linked_data(_session_id,
                                                 oh->_destination->_type->linked_node->tlv->value,
                                                 oh->_destination->_type->linked_node->tlv->value_length);


            hdr->_source->_id->set_linked_data(_session_id,
                                               (unsigned char*)get_session()->get_daemon_id(),
                                               strlen(get_session()->get_daemon_id()));



        }

        setup_dest_and_uuid(hdr, oh, source_id, _session_id);

        // sequence num
        hdr->_sequence_num->set_linked_data(_session_id,
                                            oh->_sequence_num->linked_node->tlv->value,
                                            oh->_sequence_num->linked_node->tlv->value_length);


        int sf = ((_custom_seq_flag == -1) ? asn1::SequenceFlag::_sf_stream_complete : _custom_seq_flag);
        hdr->_sequence_flag->set_linked_data(_session_id, (unsigned char*)&sf, 1);
        hdr->_status->set_linked_data(_session_id, (unsigned char*)&_error_code, 1);

        // encode
        gdtld->raw_data_length = asn1::encode(gdtld->raw_data,
                                              MEM_CSIZE,
                                              gdt_out_message,
                                              _session_id,
                                              mem_switch);
    }
}

void gdt::GDTClient::generate_ack(asn1::GDTMessage* gdt_orig_message,
                                  asn1::GDTMessage* gdt_out_message,
                                  uint64_t _orig_session_id,
                                  uint64_t _out_session_id,
                                  GDTPayload* gdtld,
                                  bool include_body,
                                  bool mem_switch){
    if(gdt_orig_message != nullptr){
        // next session id
        uint64_t _session_id = _out_session_id;

        // check optional
        bool prepare_needed = false;
        bool source_id = false;
        asn1::Header *hdr = gdt_out_message->_header;
        asn1::Header *oh = gdt_orig_message->_header;
        asn1::Body *bdy = gdt_out_message->_body;

        // check is status is set
        if(hdr->_status == nullptr){
            hdr->set_status();
            prepare_needed = true;
        }


        if(hdr->_source->_id == nullptr){
            hdr->_source->set_id();
            prepare_needed = true;
        }

        // check if source id is present
        if((oh->_source->_id != nullptr) &&
           (oh->_source->_id->has_linked_data(_orig_session_id))){
            if(hdr->_destination->_id == nullptr){
                hdr->_destination->set_id();
                prepare_needed = true;
            }
            source_id = true;
        }

        // prepare only if one of optional fields was not set
        if(prepare_needed) gdt_out_message->prepare();

        // unlink body if exists
        if(!include_body && (bdy != nullptr)){
            bdy->unlink(_session_id);
        }

        // version
        int ver = _GDT_VERSION_;
        hdr->_version->set_linked_data(_session_id, (unsigned char*)&ver, 1);

        // source
        if((oh->_destination->_type->linked_node->tlv->value_length == 1) &&
           (oh->_destination->_type->linked_node->tlv->value[0] == '.')){
            hdr->_source->_type->set_linked_data(_session_id,
                                                 (unsigned char*)get_session()->get_daemon_type(),
                                                 strlen(get_session()->get_daemon_type()));

        }else{
            hdr->_source->_type->set_linked_data(_session_id,
                                                 oh->_destination->_type->linked_node->tlv->value,
                                                 oh->_destination->_type->linked_node->tlv->value_length);

        }


        hdr->_source->_id->set_linked_data(_session_id,
                                           (unsigned char*)get_session()->get_daemon_id(),
                                           strlen(get_session()->get_daemon_id()));


        setup_dest_and_uuid(hdr, oh, source_id, _session_id);

        // sequence num
        uint32_t seqn = htobe32(gdtld->stream->get_sequence_num());
        hdr->_sequence_num->set_linked_data(_session_id, (unsigned char*)&seqn, 4);

        int sf;
        switch (gdtld->stream->get_sequence_flag()) {
            case GDT_SF_START:
                sf = asn1::SequenceFlag::_sf_continue;
                break;
            case GDT_SF_CONTINUE:
                sf = asn1::SequenceFlag::_sf_continue;
                break;
            case GDT_SF_CONTINUE_WAIT:
                sf = asn1::SequenceFlag::_sf_continue_wait;
                break;
            case GDT_SF_STATELESS:
                sf = asn1::SequenceFlag::_sf_end;
                break;
            case GDT_SF_HEARTBEAT:
                sf = asn1::SequenceFlag::_sf_heartbeat;
                break;
            default:
                sf = asn1::SequenceFlag::_sf_end;
                break;
        }
        hdr->_sequence_flag->set_linked_data(_session_id, (unsigned char*)&sf, 1);

        if(!gdtld->stream->get_seq_reply_received()){
            int status = asn1::ErrorCode::_err_ok;
            hdr->_status->set_linked_data(_session_id, (unsigned char*)&status, 1);
        }else hdr->_status->unlink(_session_id);

        // encode
        gdtld->raw_data_length = asn1::encode(gdtld->raw_data,
                                              MEM_CSIZE,
                                              gdt_out_message,
                                              _session_id,
                                              mem_switch);

        // inc sequence number if in GDT_SF_CONTINUE_WAIT state
        if(gdtld->stream->get_sequence_flag() == GDT_SF_CONTINUE_WAIT) {
            gdtld->stream->inc_sequence_num();
        }
    }
}


void* gdt::GDTClient::timeout_loop(void* args){
    if(args != nullptr){
        auto gdtc = (GDTClient*)args;
        GDTCallbackArgs cb_stream_args;
        int total_sleep = 0;

        // loop
        while(gdtc->is_active()){
            // sleep 1 sec
            sleep(1);
            ++total_sleep;
            // check if user timeout has been reached
            if(total_sleep < gdtc->stream_timeout) continue;
            // set flag, timeout will be processed in IN thread
            gdtc->stream_timeout_check.comp_swap(false, true);
            // reset current timeout
            total_sleep = 0;
        }

        // detach thread
        gdtc->timeout_thread = 0;
        pthread_detach(pthread_self());
        gdtc->dec_thread_count();

    }


    return nullptr;
}

void* gdt::GDTClient::reg_timeout_loop(void* args){
    if(args != nullptr){
        auto snew = (RegClientStreamNew*)args;
        GDTClient* gdtc = snew->client;

        timespec ts = {0, 1000000}; // 1msec
        // wait for signal
        while(gdtc->is_active() && !snew->done_signal.get()){
            nanosleep(&ts, nullptr);
        }

        // free event mem
        delete snew->sdone;
        delete snew;

        // detach thread
        pthread_detach(gdtc->reg_timeout_thread);
        gdtc->reg_timeout_thread = 0;

        // dec thread count (this thread_)
        gdtc->dec_thread_count();
    }
    return nullptr;
}

int gdt::GDTClient::register_client(){
    // check if alreday registered
    if(registered.get()) return -2;
    // events
    auto snew = new RegClientStreamNew(this);
    auto sdone = new RegClientStreamDone();
    snew->sdone = sdone;
    sdone->snew = snew;

    // handle new stream event for current client
    set_callback(gdt::GDT_ET_STREAM_NEW, snew);

    // start registration timeout thread
    if(pthread_create(&reg_timeout_thread, nullptr, &reg_timeout_loop, snew) == 0) {
        inc_thread_count();
        // ok
        return 0;
    }
    // err
    return -1;
}

void gdt::GDTClient::set_reg_flag(bool _reg_flag){
    registered.comp_swap(!_reg_flag, _reg_flag);

}

bool gdt::GDTClient::is_registered(){
    return registered.get();
}



void gdt::GDTClient::set_end_point_daemon_id(const char* _did){
    end_point_daemon_id.assign(_did);
}

void gdt::GDTClient::set_end_point_daemon_type(const char* _dtype){
    end_point_daemon_type.assign(_dtype);
}


const char* gdt::GDTClient::get_end_point_daemon_id() const {
    return end_point_daemon_id.c_str();
}

const char* gdt::GDTClient::get_end_point_daemon_type() const {
    return end_point_daemon_type.c_str();
}


int gdt::GDTClient::route(const asn1::GDTMessage* in_msg,
                          uint64_t sess_id,
                          std::vector<GDTClient*>* routes,
                          char* d_id,
                          char* d_type){
    // null check
    if((in_msg == nullptr) || (routes == nullptr)) return 1;
    // clear output
    routes->clear();
    const asn1::Header *oh = in_msg->_header;
    memcpy(d_type,
           oh->_destination->_type->linked_node->tlv->value,
           oh->_destination->_type->linked_node->tlv->value_length);
    d_type[oh->_destination->_type->linked_node->tlv->value_length] = 0;

    // destination id check
    if((oh->_destination->_id != nullptr) &&
       (oh->_destination->_id->has_linked_data(sess_id))){
        memcpy(d_id,
               oh->_destination->_id->linked_node->tlv->value,
               oh->_destination->_id->linked_node->tlv->value_length);
        d_id[oh->_destination->_id->linked_node->tlv->value_length] = 0;

        // route through this client
        if((strcmp(d_id, get_session()->get_daemon_id()) == 0) &&
           (strcmp(d_type, get_session()->get_daemon_type()) == 0)){
            routes->push_back(this);
            return 0;

            // find route
        }else{
            // routing check
            if(get_session()->is_router()){
                // find route
                return get_session()->find_route(this, d_type, d_id, routes);

                // routing not enabled
            }else return 1;
        }
    }

    // *** no destination id ***

    // "." - this daemon
    if(strcmp(d_type, ".") == 0){
        routes->push_back(this);
        return 0;
    }else{
        // find route
        if(get_session()->is_router()){
            return get_session()->find_route(this, d_type, nullptr, routes);

            // routing not enabled
        }else return 1;

    }
    //ok
    return 0;
}

void* gdt::GDTClient::exit_loop(void* args){
    if(args != nullptr){
        // session pointer
        auto gdtc = (GDTClient*)args;
        GDTCallbackArgs cb_args;

        // wait for other threads to finish
        timespec st = {0, 100000000};
        while(gdtc->get_thread_count() > 1){
            nanosleep(&st, nullptr);
            // lock
            pthread_mutex_lock(&gdtc->mtx_streams);
            // loop active streams
            for (auto it = gdtc->streams.begin();
                 it != gdtc->streams.end(); ++it) {
                // set out flag to false (important for process_timeout methos
                // called from exit_loop)
                (*it)->gdt_payload->out.set(false);
            }
            // unlock
            pthread_mutex_unlock(&gdtc->mtx_streams);

            // force timeout of all active streams
            gdtc->process_timeout(true);
        }

        // GDT_ET_CLIENT_TERMINATED event on session level
        // callback args
        if(gdtc->get_session() != nullptr){
            cb_args.clear_all_args();
            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
            gdtc->get_session()->process_callback(GDT_ET_CLIENT_TERMINATED, &cb_args);

        }
        // GDT_ET_CLIENT_TERMINATED event on client level
        cb_args.clear_all_args();
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
        gdtc->process_callback(GDT_ET_CLIENT_TERMINATED, &cb_args);

        // detach thread
        pthread_detach(pthread_self());

        // dec thread count
        gdtc->dec_thread_count();

        // deallocate connection and remove from the list
        gdtc->get_session()->remove_client(gdtc);

    }

    return nullptr;
}


void gdt::GDTClient::process_timeout(bool _override){
    // check stream timeout
    if(stream_timeout_check.comp_swap(true, false) || _override){
        // update now
        time_t tm_now = (_override ? std::numeric_limits<time_t>::max() : time(nullptr));
        GDTCallbackArgs cb_stream_args;
        // lock
        pthread_mutex_lock(&mtx_streams);
        // tmp copy of active streams
        std::vector<GDTStream*> tmp_streams = streams;
        // unlock
        pthread_mutex_unlock(&mtx_streams);
        // stream pointer
        GDTStream* tmp_stream = nullptr;
        // loop active streams
        for (auto it = tmp_streams.begin();
             it != tmp_streams.end(); ++it) {
            // stream pointer
            tmp_stream = *it;
            // skip if still in out_queue
            if(tmp_stream->gdt_payload->out.get()) continue;
            // timeout found
            if(tm_now - tmp_stream->get_timestamp() >= stream_timeout){
                // set timeout flag
                tmp_stream->set_timeout_status(true);
                if (tmp_stream->linked_stream != nullptr)
                    tmp_stream->linked_stream->set_timeout_status(true);

                // run GDT_ET_STREAM_TIMEOUT event
                cb_stream_args.clear_all_args();
                cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, this);
                cb_stream_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_STREAM, tmp_stream);
                tmp_stream->process_callback(GDT_ET_STREAM_TIMEOUT, &cb_stream_args);

                if (tmp_stream->linked_stream != nullptr) {
                    cb_stream_args.clear_all_args();
                    cb_stream_args.add_arg(GDT_CB_INPUT_ARGS,
                                           GDT_CB_ARG_CLIENT,
                                           this);
                    cb_stream_args.add_arg(GDT_CB_INPUT_ARGS,
                                           GDT_CB_ARG_STREAM,
                                           tmp_stream->linked_stream);
                    tmp_stream->linked_stream->process_callback(GDT_ET_STREAM_TIMEOUT,
                                                                &cb_stream_args);
                }
                // stats
                if (tmp_stream->initiator == GDT_SIT_LOCAL)
                    out_stats.strm_timeout.add_fetch(1);
                else
                    in_stats.strm_timeout.add_fetch(1);
            }
        }

        // lock
        pthread_mutex_lock(&mtx_streams);
        // loop active streams
        for (auto it = streams.begin();
             it != streams.end();) {
            // stream pointer
            tmp_stream = *it;
            // free if timeout flag set
            if (tmp_stream->get_timeout_status()) {
                // remove from active stream list
                it = streams.erase(it);
                // return to pool
                if (tmp_stream->linked_stream != nullptr)
                    deallocate_stream_pool(tmp_stream->linked_stream);

                deallocate_stream_pool(tmp_stream);
                // next stream
            } else
                ++it;
        }
        if(streams.empty()) streams_active.set(false);
        // unlock
        pthread_mutex_unlock(&mtx_streams);
    }
}

void gdt::GDTClient::init_reconnect(){
    // set registered to false
    set_reg_flag(false);
    // reconnect mode for OUTBOUND connections
    if(direction == GDT_CD_OUTBOUND){
        // close old socket
        sctp::shutdown_sctp_client(client_socket);
        // client re-connecting
        GDTCallbackArgs cb_args;
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, this);
        // GDT_ET_CLIENT_RECONNECTING event
        process_callback(GDT_ET_CLIENT_RECONNECTING, &cb_args);
        // wait for socket connection
        client_socket = reconnect_socket();
        // register client
        if(client_socket > 0){
            // register client (new thread needed due to blocking nature of
            // register_client method)
            class _tmp_thread {
                public:
                    static void* run(void* args){
                        // client pointer
                        auto tmp_gdtc = (GDTClient*)args;
                        // register
                        ::register_client(tmp_gdtc, ".");
                        // detach
                        pthread_detach(pthread_self());
                        // dec thread count
                        tmp_gdtc->dec_thread_count();
                        // return
                        return nullptr;
                    }
            };
            // tmp thread
            pthread_t tmp_thread_h;
            if (pthread_create(&tmp_thread_h,
                               nullptr,
                               &_tmp_thread::run,
                               this) == 0)
                inc_thread_count();
        }

        // set as inactive if INBOUND connection
    }else {
        set_activity(false);
    }
}



void* gdt::GDTClient::in_loop(void* args){
    if(args != nullptr){
        // session pointer
        auto gdtc = (GDTClient*)args;
        GDTStateMachine* gdt_sm = &gdtc->gdt_sm;
        GDTCallbackArgs cb_args;
        gdt_sm->init(gdtc);

        // loop
        while(gdtc->is_active()){
            // run state machine
            gdt_sm->run();

        }

        // client terminating
        cb_args.clear_all_args();
        cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdtc);
        // GDT_ET_CLIENT_TERMINATING event
        gdtc->process_callback(GDT_ET_CLIENT_TERMINATING, &cb_args);

        // call stream timeout event handler on all active streams
        gdtc->process_timeout(true);

        // start exit cleanup thread
        gdtc->inc_thread_count();
        if(pthread_create(&gdtc->exit_thread, nullptr, &exit_loop, gdtc) == 0){
            pthread_setname_np(gdtc->exit_thread, "gdt_exit");
        }

        // detach thread
        pthread_detach(gdtc->in_thread);
        gdtc->in_thread = 0;
        gdtc->dec_thread_count();
    }

    return nullptr;
}

int gdt::GDTClient::out_process(GDTPayload* gdtpld, GDTCallbackArgs* cb_args){
    // send through socket
    int res = send(gdtpld->sctp_sid, gdtpld->raw_data, gdtpld->raw_data_length);
    if(res == 0){
        // stats
        out_stats.packets.fetch_add(1);
        out_stats.bytes.fetch_add(gdtpld->raw_data_length);

        // process payload callbacks
        cb_args->clear_all_args();
        cb_args->add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_PAYLOAD, gdtpld);
        gdtpld->stream->process_callback(GDT_ET_PAYLOAD_SENT, cb_args);

        // free/return to pool if requested
        if(gdtpld->free_on_send){
            // free memory, return back to pool
            deallocate_stream_pool(gdtpld->stream);

            // set active stream payload out flag to false (leaving out queue)
        }else gdtpld->out.set(false);


        // sctp connection error, close socket
    }else{
        // stats
        out_stats.socket_errors.fetch_add(1);
        // queue reconnect processs
        reconnect_queued.comp_swap(false, true);
        // reconnection will be done in IN thread
        // do nothing here

        // free memory, return back to pool
        if(gdtpld->free_on_send) deallocate_stream_pool(gdtpld->stream);
        // set active stream payload out flag to false (leaving out queue)
        else gdtpld->out.set(false);

    }


    return res;

}


void* gdt::GDTClient::out_loop(void* args){
    // check for args
    if(args == nullptr) return nullptr;
    GDTCallbackArgs cb_args;
    auto gdtc = (GDTClient*)args;
    GDTPayload* gdtpld = nullptr;
    timespec pause_ts = {0, 1}; // 1nsec
    timespec pause_ts_long = {0, 1000000}; // 1msec

    // loop
    while(gdtc->is_active()){
        // reset
        bool internal_data = false;
        bool external_data = false;

        // pop internal
        if(gdtc->internal_out_queue.pop(&gdtpld) == 0){
            internal_data = true;
            gdtc->out_process(gdtpld, &cb_args);
        }


        // pop external
        gdtpld = gdtc->pop_out_queue();
        if(gdtpld != nullptr) {
            external_data = true;
            gdtc->out_process(gdtpld, &cb_args);
        }

        // sleep if both queues are empty
        if(!(external_data || internal_data)) {
            // - use smaller sleep value (1 nsec) if the
            //   following conditions are met:
            //     1. at least one stream is active
            //     2. a packet was received by this client
            //        no longer than 1 sec ago (this is important
            //        in order to avoid seeing timed out streams
            //        as active streams if they still haven't
            //        been removed from the active stream list)
            if(gdtc->streams_active.get() && (time(nullptr) - gdtc->timestamp.get() < 1))
                nanosleep(&pause_ts, nullptr);

            // - sleep longer (1 msec) if there are no
            //   active streams
            else nanosleep(&pause_ts_long, nullptr);
        }
    }

    // detach thread
    pthread_detach(gdtc->out_thread);
    gdtc->out_thread = 0;
    gdtc->dec_thread_count();
    return nullptr;
}

unsigned int gdt::GDTClient::inc_thread_count(){
    return thread_count.add_fetch(1);
}

unsigned int gdt::GDTClient::dec_thread_count(){
    return thread_count.sub_fetch(1);
}


unsigned int gdt::GDTClient::get_thread_count(){
    return thread_count.get();

}

gdt::GDTSession* gdt::GDTClient::get_session(){
    return session;
}


void gdt::GDTClient::set_session(gdt::GDTSession* _session){
    session = _session;
}

// GDTStream
gdt::GDTStream::GDTStream() : random_generator(nullptr),
                              sequence_num(0),
                              sequence_reply_received(false),
                              sequence_flag(GDT_SF_UNKNOWN),
                              client(nullptr),
                              gdt_message(nullptr),
                              gdt_payload(nullptr),
                              timestamp(0),
                              expired(false),
                              linked_stream(nullptr),
                              last_linked_side(nullptr),
                              initiator(GDT_SIT_LOCAL) {
    memset(uuid, 0, 16);
}

gdt::GDTStream::GDTStream(mink_utils::Randomizer *_random_generator) : random_generator(_random_generator),
                                                                       sequence_num(0),
                                                                       sequence_flag(GDT_SF_UNKNOWN),
                                                                       client(nullptr),
                                                                       expired(false),
                                                                       linked_stream(nullptr),
                                                                       last_linked_side(nullptr),
                                                                       initiator(GDT_SIT_LOCAL) {
    memset(uuid, 0, 16);
    generate_uuid();

}

void gdt::GDTStream::set_random_generator(mink_utils::Randomizer  *_random_generator){
    random_generator = _random_generator;
}

unsigned char* gdt::GDTStream::get_uuid(){
    return uuid;
}

void gdt::GDTStream::inc_sequence_num(){
    sequence_num++;
}

void gdt::GDTStream::wait_sequence(){
    sequence_flag = GDT_SF_CONTINUE_WAIT;
}
void gdt::GDTStream::set_continue_flag(){
    if(gdt_message != nullptr){
        gdt_message->_header->_sequence_flag->linked_node->tlv->value[0] = asn1::SequenceFlag::_sf_continue;
    }
}

void gdt::GDTStream::end_sequence(){
    sequence_flag = GDT_SF_END;
}

void gdt::GDTStream::continue_sequence(){
    sequence_flag = GDT_SF_CONTINUE;
}

void gdt::GDTStream::generate_uuid(){
    if (client) client->generate_uuid(uuid);

}

void gdt::GDTStream::set_sequence_flag(GDTSequenceFlag _sequence_flag){
    sequence_flag = _sequence_flag;
}

void gdt::GDTStream::send(bool include_body){
    gdt_payload->free_on_send = false;
    gdt_payload->out.set(true);
    gdt_payload->gdt_stream_type = GDT_ST_STATEFUL;
    gdt_payload->client = client;
    gdt_payload->sctp_sid = 0;
    gdt_payload->clear_callbacks();
    gdt_payload->set_callback(GDT_ET_PAYLOAD_SENT, get_callback(GDT_ET_PAYLOAD_SENT));
    client->generate_stream_header(gdt_message,
                                   this,
                                   1,
                                   gdt_payload,
                                   include_body,
                                   destination_type.c_str(),
                                   (destination_id.empty() ? nullptr: destination_id.c_str()));
    client->push_out_queue(gdt_payload);
}

void gdt::GDTStream::set_client(GDTClient* _client){
    client = _client;
}

void gdt::GDTStream::reset(bool reset_uuid){
    if(reset_uuid) generate_uuid();
    sequence_num = 1;
    sequence_flag = GDT_SF_START;
    sequence_reply_received = false;
    destination_id.clear();
    destination_type.clear();
    timestamp = time(nullptr);
    expired = false;
    linked_stream = nullptr;
    last_linked_side = nullptr;
    if(reset_uuid) initiator = GDT_SIT_LOCAL;
    else initiator = GDT_SIT_REMOTE;

}

void gdt::GDTStream::set_timestamp(time_t _timestamp){
    timestamp = _timestamp;
}

time_t gdt::GDTStream::get_timestamp() const {
    return timestamp;
}



bool gdt::GDTStream::get_seq_reply_received() const {
    return sequence_reply_received;
}

void gdt::GDTStream::toggle_seq_reply_received(){
    sequence_reply_received = !sequence_reply_received;
}


gdt::GDTSequenceFlag gdt::GDTStream::get_sequence_flag() const {
    return sequence_flag;
}
unsigned int gdt::GDTStream::get_sequence_num() const {
    return sequence_num;
}



void gdt::GDTStream::set_uuid(const unsigned char* _uuid){
    memcpy(uuid, _uuid, 16);

}

gdt::GDTStream::~GDTStream() = default;

bool gdt::GDTStream::process_callback(GDTEventType type, GDTCallbackArgs* args){
    return callback_handler.process_callback(type, args);
}

void gdt::GDTStream::remove_callback(GDTEventType callback_type){
    callback_handler.remove_callback(callback_type);

}

void gdt::GDTStream::clear_callbacks(){
    callback_handler.clear();
}

void gdt::GDTStream::set_param(uint32_t param_id, void* param){
    params[param_id] = param;
}

int gdt::GDTStream::remove_param(uint32_t param_id){
    return params.erase(param_id);

}

void* gdt::GDTStream::get_param(uint32_t param_id){
    std::map<uint32_t, void*>::iterator it = params.find(param_id);
    return (it != params.end() ? it->second : nullptr);
}

void gdt::GDTStream::clear_params(){
    params.clear();
}

bool gdt::GDTStream::get_timeout_status() const {
    return expired;
}

void gdt::GDTStream::set_timeout_status(bool _status){
    expired = _status;
}


gdt::GDTCallbackMethod* gdt::GDTStream::get_callback(GDTEventType callback_type){
    return callback_handler.get_callback(callback_type);
}

void gdt::GDTStream::set_callback(GDTEventType callback_type, GDTCallbackMethod* callback_method){
    callback_handler.set_callback(callback_type, callback_method);
}


// RouteHandlerMethod
gdt::RouteHandlerMethod::RouteHandlerMethod(GDTSession* _gdts): gdts(_gdts){

}

gdt::RouteHandlerMethod::~RouteHandlerMethod() = default;

void gdt::RouteHandlerMethod::run(std::vector<GDTClient*>* all_routes,
                                  std::vector<GDTClient*>* chosen_routes){
    if((all_routes != nullptr) && (chosen_routes != nullptr)){
        if(all_routes->size() > 0) chosen_routes->push_back((*all_routes)[0]);
    }
}

void* gdt::RouteHandlerMethod::add_node(GDTClient* gdtc,
                                        const char* node_type,
                                        const char* node_id, mink_utils::PooledVPMap<uint32_t>* params){
    return nullptr;
}
void gdt::RouteHandlerMethod::clear(){}
void* gdt::RouteHandlerMethod::update_client(GDTClient* gdtc,
                                             const char* node_type,
                                             const char* node_id){
    // reserved
    return nullptr;
}
int gdt::RouteHandlerMethod::remove_type(const char* node_type){
    return 0;
}
int gdt::RouteHandlerMethod::remove_node(const char* node_type, const char* node_id){
    return 0;
}
void* gdt::RouteHandlerMethod::get_node(const char* node_type, const char* node_id){
    return nullptr;
}

// WRRRouteHandler
gdt::WRRRouteHandler::WRRRouteHandler(GDTSession* _gdts): RouteHandlerMethod(_gdts){

}

gdt::WRRRouteHandler::~WRRRouteHandler() = default;

void gdt::WRRRouteHandler::run(std::vector<GDTClient*>* all_routes,
                              std::vector<GDTClient*>* chosen_routes){
    if ((all_routes == nullptr) || (chosen_routes == nullptr) || (all_routes->size() == 0))
        return;
    // get session from first in the list
    const GDTSession* gdts = ((*all_routes)[0])->get_session();
    // sanity check
    if(gdts == nullptr) return;
    // get route type from first in the list
    const char* dest_type = ((*all_routes)[0])->get_end_point_daemon_type();
    // create hash from dest type string
    uint32_t hash = mink_utils::hash_fnv1a(dest_type, strlen(dest_type));
    // get wrr for specific dest type
    wrr_map_it_t it = wrr_map.find(hash);
    // if no wrr data found, return first in list (fallback to automatic routing)
    if(it == wrr_map.end()) {
        (*all_routes)[0]->inc_refc();
        chosen_routes->push_back((*all_routes)[0]);
        return;
    }
    // wrr data found, run wrr logic
    mink_utils::WRR<GDTClient*>::items_map_val_t* wrr_res = it->second.run();
    // if no wrr data found, return
    if((wrr_res == nullptr) || (wrr_res->item == nullptr)) return;
    // add route to result
    wrr_res->item->inc_refc();
    chosen_routes->push_back(wrr_res->item);


}

void* gdt::WRRRouteHandler::add_node(GDTClient* gdtc,
                                     const char* node_type,
                                     const char* node_id,
                                     mink_utils::PooledVPMap<uint32_t>* params){

    // sanity check
    if((node_type == nullptr) || (params == nullptr)) return nullptr;
    // create hash from dest type string
    uint32_t hash = mink_utils::hash_fnv1a(node_type, strnlen(node_type, 16));
    // insert or return ref
    wrr_map_insert_t in_it = wrr_map.insert(wrr_map_value_t(hash,
                                                            mink_utils::WRR<gdt::GDTClient*>()));
    // get weight param
    const mink_utils::VariantParam* vp = params->get_param(0);
    if(vp == nullptr) return nullptr;
    uint32_t weight = (int)*vp;
    // add node
    in_it.first->second.add_item(gdtc, node_id, weight);
    // disable or enable
    if(gdtc == nullptr) in_it.first->second.disable(node_id);
    else in_it.first->second.enable(node_id);
    // get
    return in_it.first->second.get(node_id);

}

void* gdt::WRRRouteHandler::get_node(const char* node_type, const char* node_id){
    if((node_type == nullptr) || (node_id == nullptr)) return nullptr;
    // create hash from dest type string
    uint32_t hash = mink_utils::hash_fnv1a(node_type, strnlen(node_type, 16));
    // find
    wrr_map_it_t it = wrr_map.find(hash);
    // sanity check
    if(it == wrr_map.end()) return nullptr;
    // get wrr item
    mink_utils::WRRItem<gdt::GDTClient*>* wrr_item = it->second.get(node_id);
    // sanity check
    if(wrr_item == nullptr) return nullptr;
    // ok
    return wrr_item;
}


int gdt::WRRRouteHandler::remove_type(const char* node_type){
    // sanity check
    if(node_type == nullptr) return 1;
    // create hash from dest type string
    uint32_t hash = mink_utils::hash_fnv1a(node_type, strlen(node_type));
    // find
    wrr_map_it_t it = wrr_map.find(hash);
    // sanity check
    if(it == wrr_map.end()) return 1;
    // remove
    wrr_map.erase(it);
    // ok
    return 0;
}

int gdt::WRRRouteHandler::remove_node(const char* node_type, const char* node_id){
    // sanity check
    if(node_type == nullptr) return 1;
    // create hash from dest type string
    uint32_t hash = mink_utils::hash_fnv1a(node_type, strnlen(node_type, 16));
    // find
    wrr_map_it_t it = wrr_map.find(hash);
    // sanity check
    if(it == wrr_map.end()) return 1;
    // remove node
    it->second.remove(node_id);
    // ok
    return 0;

}


void* gdt::WRRRouteHandler::update_client(GDTClient* gdtc,
        const char* node_type,
        const char* node_id){

    // sanity check
    if((node_type == nullptr) || (node_id == nullptr)) return nullptr;
    // create hash from dest type string
    uint32_t hash = mink_utils::hash_fnv1a(node_type, strnlen(node_type, 16));
    // find
    wrr_map_it_t it = wrr_map.find(hash);
    // sanity check
    if(it == wrr_map.end()) return nullptr;
    // get wrr item
    mink_utils::WRRItem<gdt::GDTClient*>* wrr_item = it->second.get(node_id);
    // sanity check
    if(wrr_item == nullptr) return nullptr;
    // update client data
    wrr_item->item = gdtc;
    // disable if client was seet to null
    if(gdtc == nullptr) it->second.disable(wrr_item);
    // or enable
    else it->second.enable(wrr_item);
    // return wrr item pointer
    return wrr_item;
}


void gdt::WRRRouteHandler::clear(){
    wrr_map.clear();

}



// GDTSession
gdt::GDTSession::GDTSession(const char* _daemon_type,
                            const char* _daemon_id,
                            int _max_concurrent_streams,
                            int _stream_timeout,
                            bool _router,
                            int _poll_interval) : poll_interval(_poll_interval),
                                                  max_concurrent_streams(_max_concurrent_streams),
                                                  router(_router),
                                                  rh_method(nullptr) {
    server_socket.set(-1);
    server_thread = 0;
    stream_timeout = ((_stream_timeout < 1) ? 1 : _stream_timeout);
    daemon_type.assign(_daemon_type);
    daemon_id.assign(_daemon_id);
    pthread_mutex_init(&mtx_callback, nullptr);
    pthread_mutex_init(&mtx_clients, nullptr);
}

gdt::GDTSession::~GDTSession(){
    // children
    clients.clear();

    // mutexes
    pthread_mutex_destroy(&mtx_callback);
    pthread_mutex_destroy(&mtx_clients);

    // algo
    delete get_routing_handler();


}


int gdt::GDTSession::stop_server(){
    if(get_server_mode() && (get_server_socket() > 0)){
        // shutdown connection
        sctp::shutdown_sctp_client(get_server_socket());
        // socket closed
        set_server_mode(false);
        set_server_socket(-1);
        // error while closing socket
        return 0;
    }
    // error
    return -1;
}


int gdt::GDTSession::find_route(GDTClient* _client,
                                const char* _daemon_type,
                                const char* _daemon_id,
                                std::vector<GDTClient*>* routes){
    // error check
    if(_daemon_type == nullptr) return 1;
    // daemon id not present
    if(_daemon_id == nullptr){
        // check self
        // check if current daemon type is acceptable
        if(strcmp(get_daemon_type(), _daemon_type) == 0){
            routes->push_back(_client);
            return 0;
        }else{
            GDTClient* tmp_client = nullptr;
            std::vector<GDTClient*> tmp_client_lst;
            // lock client list
            lock_clients();
            // search
            unsigned int count = get_client_count(true);
            for(unsigned int i = 0; i<count; i++){
                // set pointer
                tmp_client = get_client(i, true);
                // skip if not registered or not active
                if(!tmp_client->is_registered() || !tmp_client->is_active()) continue;
                // check if client end point daemon type is acceptable
                if(strcmp(tmp_client->get_end_point_daemon_type(), _daemon_type) == 0){
                    // inc ref counter
                    tmp_client->inc_refc();
                    // add to list
                    tmp_client_lst.push_back(tmp_client);
                }

            }
            // run routing handler if defined or return first matched route
            if(rh_method != nullptr) rh_method->run(&tmp_client_lst, routes);
            else{
                if(!tmp_client_lst.empty()){
                    tmp_client_lst[0]->inc_refc();
                    routes->push_back(tmp_client_lst[0]);
                }

            }
            // dec ref counters
            std::all_of(tmp_client_lst.cbegin(), tmp_client_lst.cend(),
                        [](GDTClient *c) {
                            c->dec_refc();
                            return true;
                        });

            // unlock client list
            unlock_clients();
        }
        // daemon id present
    }else{
        // check for special '*' id (should only be used with GDT_ST_STATELESS_NO_REPLY to
        // avoid stream uuid conflicts)
        if(strcmp("*", _daemon_id) == 0){
            GDTClient* tmp_client = nullptr;
            // lock client list
            lock_clients();
            // search
            unsigned int count = get_client_count(true);
            for(unsigned int i = 0; i<count; i++){
                // set pointer
                tmp_client = get_client(i, true);
                // skip if not registered or not active
                if(!tmp_client->is_registered() || !tmp_client->is_active()) continue;
                if(strcmp(tmp_client->get_end_point_daemon_type(), _daemon_type) == 0 &&
                   tmp_client != _client)
                    routes->push_back(tmp_client);
            }
            // unlock client list
            unlock_clients();

            // check if current daemon type and id are acceptable
        }else if((strcmp(get_daemon_type(), _daemon_type) == 0) &&
                 (strcmp(get_daemon_id(), _daemon_id) == 0)){
            routes->push_back(_client);
            return 0;

        }else{
            GDTClient* tmp_client = nullptr;
            std::vector<GDTClient*> tmp_client_lst;
            // lock client list
            lock_clients();
            // search
            unsigned int count = get_client_count(true);
            for(unsigned int i = 0; i<count; i++){
                // set pointer
                tmp_client = get_client(i, true);
                // skip if not registered or not active
                if(!tmp_client->is_registered() || !tmp_client->is_active()) continue;
                // check if client end point daemon type and id are acceptable
                if((strcmp(tmp_client->get_end_point_daemon_type(), _daemon_type) == 0) &&
                   (strcmp(tmp_client->get_end_point_daemon_id(), _daemon_id) == 0)) {

                    // inc ref counter
                    tmp_client->inc_refc();
                    // add to list
                    routes->push_back(tmp_client);
                    // unlock client list
                    unlock_clients();
                    // return (perfect match)
                    return 0;
                    // if client has routing capabilities, add to list
                }
            }

            // run routing handler if defined or return first matched route
            // routing list will be filled with routing capable clients
            if(rh_method != nullptr) rh_method->run(&tmp_client_lst, routes);
            else{
                if(!tmp_client_lst.empty()){
                    tmp_client_lst[0]->inc_refc();
                    routes->push_back(tmp_client_lst[0]);
                }
            }
            // dec ref counters
            std::all_of(tmp_client_lst.cbegin(), tmp_client_lst.cend(),
                        [](GDTClient *c) {
                            c->dec_refc();
                            return true;
                        });

            // unlock client list
            unlock_clients();

        }
    }
    // ok
    return 0;
}




bool gdt::GDTSession::is_router() const {
    return router;
}

void gdt::GDTSession::remove_callback(GDTEventType callback_type){
    pthread_mutex_lock(&mtx_callback);
    callback_handler.remove_callback(callback_type);
    pthread_mutex_unlock(&mtx_callback);

}

void gdt::GDTSession::set_callback(GDTEventType callback_type, GDTCallbackMethod* callback_method){
    pthread_mutex_lock(&mtx_callback);
    callback_handler.set_callback(callback_type, callback_method);
    pthread_mutex_unlock(&mtx_callback);
}


void gdt::GDTSession::process_callback(GDTEventType type, GDTCallbackArgs* args){
    pthread_mutex_lock(&mtx_callback);
    callback_handler.process_callback(type, args);
    pthread_mutex_unlock(&mtx_callback);
}


unsigned int gdt::GDTSession::inc_thread_count(){
    return thread_count.add_fetch(1);

}

unsigned int gdt::GDTSession::dec_thread_count(){
    return thread_count.sub_fetch(1);
}


unsigned int gdt::GDTSession::get_thread_count(){
    return thread_count.get();
}

void gdt::GDTSession::set_server_socket(int _socket){
    server_socket.set(_socket);

}

int gdt::GDTSession::get_server_socket(){
    return server_socket.get();
}

void gdt::GDTSession::set_server_mode(bool _server_mode){
    server_mode.comp_swap(!_server_mode, _server_mode);

}

bool gdt::GDTSession::get_server_mode(){
    return server_mode.get();
}

const char* gdt::GDTSession::get_daemon_id() const {
    return daemon_id.c_str();
}

const char* gdt::GDTSession::get_daemon_type() const {
    return daemon_type.c_str();
}


void* gdt::GDTSession::server_loop(void* args){
    if(args == nullptr) return nullptr;

    // session pointer
    auto gdts = (GDTSession*)args;
    sockaddr_in si, pi;
    int size_si = sizeof(sockaddr_in);
    pollfd fds_lst[1];
    // set poll timeout to 5 sec
    int poll_timeout = gdts->poll_interval * 1000;

    // monitor POLLIN event
    fds_lst[0].events = POLLIN;

    // loop
    while(gdts->get_server_mode()){
        // get server socket
        int tmp_s = gdts->get_server_socket();
        // update socket in poll structure
        fds_lst[0].fd = tmp_s;
        // poll
        int res = poll(fds_lst, 1, poll_timeout);
        // check for timeout or  POLLIN event
        if((res > 0) && ((fds_lst[0].revents & POLLIN) == POLLIN)){
            // get client socket and remote peer info
            int tmp_c = sctp::get_client(tmp_s, &pi);
            // check if socket is valid
            if(tmp_c > 0) {
                // get local socket info
                getsockname(tmp_c, (sockaddr*)&si, (socklen_t*)&size_si);
                // add client
                auto client = new GDTClient(tmp_c,
                                            inet_ntoa(pi.sin_addr),
                                            ntohs(pi.sin_port),
                                            inet_ntoa(si.sin_addr),
                                            ntohs(si.sin_port),
                                            GDT_CD_INBOUND,
                                            gdts->max_concurrent_streams,
                                            gdts->stream_timeout,
                                            gdts->poll_interval);

                // set session
                client->set_session(gdts);
                // add to list
                gdts->add_client(client);
                // inc thread count
                gdts->inc_thread_count();
                // start registration
                client->register_client();
                // start client threads
                client->init_threads();

            }
        }
    }
    // detach thread
    pthread_detach(gdts->server_thread);
    gdts->server_thread = 0;
    gdts->dec_thread_count();

    return nullptr;

}
int gdt::GDTSession::start_server(const char* bind_address, unsigned int bind_port){
    // server not started
    if(!get_server_mode() && (get_server_socket() < 0)){
        // bind to specific address
        if(bind_address != nullptr){
            set_server_socket(sctp::init_sctp_server(inet_addr(bind_address), 0, bind_port));
            if (get_server_socket() > 0)
                set_server_mode(true);

        // bind to INADDR_ANY
        }else{
            set_server_socket(sctp::init_sctp_server(0, 0, bind_port));
            if (get_server_socket() > 0)
                set_server_mode(true);
        }
        // start server thread
        if(get_server_mode()){
            // server thread attribures
            pthread_attr_init(&server_thread_attr);
#ifdef ENABLE_SCHED_FIFO
            // explicit FIFO scheduling for SERVER thread
            pthread_attr_setinheritsched(&server_thread_attr, PTHREAD_EXPLICIT_SCHED);
            pthread_attr_setschedpolicy(&server_thread_attr, SCHED_FIFO);
            // priority
            sched_param server_sp;
            // half priority for SERVER
            server_sp.sched_priority = 50;
            // set priorities
            pthread_attr_setschedparam(&server_thread_attr, &server_sp);
#endif
            // start
            if(pthread_create(&server_thread, &server_thread_attr, &server_loop, this) == 0){
                // inc thread count
                inc_thread_count();
                // set name
                pthread_setname_np(server_thread, "gdt_server");
                // destroy atrributes
                pthread_attr_destroy(&server_thread_attr);
            }
        }
    }

    // return server socket
    return get_server_socket();
}


gdt::GDTClient* gdt::GDTSession::get_client(GDTClient* client){
    pthread_mutex_lock(&mtx_clients);
    GDTClient* tmp = nullptr;
    for(unsigned int i = 0; i<clients.size(); i++) if(clients[i] == client) {
        tmp = client;
        break;
    }
    pthread_mutex_unlock(&mtx_clients);
    return tmp;
}

gdt::GDTClient* gdt::GDTSession::get_client(unsigned int client_index, bool unsafe){
    if(!unsafe) pthread_mutex_lock(&mtx_clients);
    GDTClient* tmp = nullptr;
    if(clients.size() > client_index) tmp = clients[client_index];
    if(!unsafe) pthread_mutex_unlock(&mtx_clients);
    return tmp;
}

gdt::GDTClient* gdt::GDTSession::get_registered_client(unsigned int client_index, bool unsafe){
    if(!unsafe) pthread_mutex_lock(&mtx_clients);
    GDTClient* tmp = nullptr;
    std::vector<GDTClient*> tmp_lst;
    // get registered clients
    std::all_of(clients.cbegin(), clients.cend(),
        [&tmp_lst](GDTClient *c) {
            if (c->is_registered()) tmp_lst.push_back(c);
            return true;
        }
    );

    // get registered client with index of client_index
    if(tmp_lst.size() > client_index) tmp = tmp_lst[client_index];
    if(!unsafe) pthread_mutex_unlock(&mtx_clients);
    return tmp;
}

gdt::GDTClient* gdt::GDTSession::get_registered_client(const char* dt, bool unsafe){
    if(!unsafe) pthread_mutex_lock(&mtx_clients);
    GDTClient* tmp = nullptr;
    std::vector<GDTClient*> tmp_lst;
    // get registered clients
    std::all_of(clients.cbegin(), clients.cend(),
        [&tmp_lst, dt](GDTClient *c) {
            if (c->is_registered() &&
                strcmp(dt, c->get_end_point_daemon_type()) == 0) {
                tmp_lst.push_back(c);
            }
            return true;
        }
    );
    // get first in the list
    if(!tmp_lst.empty()) tmp = tmp_lst[0];
    if(!unsafe) pthread_mutex_unlock(&mtx_clients);
    return tmp;
}

gdt::GDTClient* gdt::GDTSession::get_registered_client(const char* dt,
                                                       const char* did,
                                                       bool unsafe){
    if(!unsafe) pthread_mutex_lock(&mtx_clients);
    GDTClient* tmp = nullptr;
    // get registered clients
    for (unsigned int i = 0; i < clients.size(); i++)
        if (clients[i]->is_registered() &&
            strcmp(dt, clients[i]->get_end_point_daemon_type()) == 0 &&
            strcmp(did, clients[i]->get_end_point_daemon_id()) == 0) {
            tmp = clients[i];
            if (!unsafe) pthread_mutex_unlock(&mtx_clients);
            // found
            return tmp;
        }
    if(!unsafe) pthread_mutex_unlock(&mtx_clients);
    // not found
    return nullptr;

}



void gdt::GDTSession::set_routing_algo(GDTRoutingAlgorithm algo){
    WRRRouteHandler* wrr_rh = nullptr;
    switch(algo){
        case GDT_RA_AUTO:
            set_routing_handler(nullptr);
            break;

        case GDT_RA_WRR:
            wrr_rh = new WRRRouteHandler(this);
            set_routing_handler(wrr_rh);
            break;

        default:
            break;
    }
}


void gdt::GDTSession::set_routing_handler(RouteHandlerMethod* rhandler){
    // using mtx_clients mutex, used only by find_route method
    rh_method = rhandler;
}

gdt::RouteHandlerMethod* gdt::GDTSession::get_routing_handler(){
    // using mtx_clients mutex, used only by find_route method
    return rh_method;
}


void gdt::GDTSession::add_client(GDTClient* client){
    pthread_mutex_lock(&mtx_clients);
    clients.push_back(client);
    pthread_mutex_unlock(&mtx_clients);

}

void gdt::GDTSession::lock_clients(){
    pthread_mutex_lock(&mtx_clients);

}

void gdt::GDTSession::unlock_clients(){
    pthread_mutex_unlock(&mtx_clients);

}

unsigned int gdt::GDTSession::get_client_count(bool unsafe){
    if(!unsafe) pthread_mutex_lock(&mtx_clients);
    unsigned int tmp = clients.size();
    if(!unsafe) pthread_mutex_unlock(&mtx_clients);
    return tmp;
}

int gdt::GDTSession::remove_client(unsigned int client_index){
    // lock mutex
    pthread_mutex_lock(&mtx_clients);
    // validate index
    if(clients.size() > client_index){
        // save pointer to erased client
        GDTClient* tmp = clients[client_index];
        // erase
        clients.erase(clients.begin() + client_index);
        // unlock mutex
        pthread_mutex_unlock(&mtx_clients);
        // free mem
        delete tmp;
        // ok
        return 0;
    }
    //unlock mutex
    pthread_mutex_unlock(&mtx_clients);
    // return error, not found
    return -1;

}

int gdt::GDTSession::remove_client(GDTClient* gdt_client){
    //lock mutex
    pthread_mutex_lock(&mtx_clients);
    if(gdt_client != nullptr){
        for(unsigned int i = 0; i<clients.size(); i++) if(clients[i] == gdt_client) {
            // erase
            clients.erase(clients.begin() + i);
            // remove from routing
            if(rh_method != nullptr){
                rh_method->update_client(nullptr,
                                         gdt_client->get_end_point_daemon_type(),
                                         gdt_client->get_end_point_daemon_id());
            }

            // unlock mutex
            pthread_mutex_unlock(&mtx_clients);
            // wait for ref counter to become zero
            if(gdt_client->dec_refc() > 0){
                // pause 100msec
                timespec st = {0, 100000000};
                // loop wait
                while(gdt_client->get_refc() > 0) nanosleep(&st, nullptr);
            }


            // **** free out queues ****
            GDTPayload* gdtpld = nullptr;
            // internal out
            while(gdt_client->internal_out_queue.pop(&gdtpld) == 0){
                // free memory, return back to pool
                if(gdtpld->free_on_send){
                    if (gdtpld->stream->linked_stream != nullptr)
                        gdt_client->deallocate_stream_pool(
                            gdtpld->stream->linked_stream);
                    gdt_client->deallocate_stream_pool(gdtpld->stream);
                }
            }
            // external out
            while((gdtpld = gdt_client->pop_out_queue()) != nullptr){
                // free memory, return back to pool
                if(gdtpld->free_on_send){
                    if (gdtpld->stream->linked_stream != nullptr)
                        gdt_client->deallocate_stream_pool(
                            gdtpld->stream->linked_stream);
                    gdt_client->deallocate_stream_pool(gdtpld->stream);
                }
            }

            // process callback
            GDTCallbackArgs cb_args;
            cb_args.clear_all_args();
            cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, gdt_client);
            process_callback(GDT_ET_CLIENT_DESTROYED, &cb_args);

            // free mem, no refs present
            delete gdt_client;

            // dec thread count
            dec_thread_count();
            // found, return ok
            return 0;
        }
    }
    // unlock mutex
    pthread_mutex_unlock(&mtx_clients);
    // return error, not found
    return -1;
}



gdt::GDTClient* gdt::GDTSession::connect(const char* end_point_address,
                                         unsigned int end_point_port,
                                         int stream_count,
                                         const char* local_address,
                                         unsigned int local_port,
                                         bool skip_gdt_reg){

    if((end_point_address == nullptr) || (end_point_port == 0) || (stream_count == 0))
        return nullptr;
    // client
    int client_id = -1;
    if(local_address == nullptr){
        // connect
        // connect and bind to specific ip:port
        client_id = sctp::init_sctp_client_bind(inet_addr(end_point_address),
                                                0,
                                                0,
                                                0,
                                                0,
                                                end_point_port,
                                                stream_count);

    }else{
        // connect and bind to specific ip:port
        client_id = sctp::init_sctp_client_bind(inet_addr(end_point_address),
                                                0,
                                                inet_addr(local_address),
                                                0,
                                                local_port,
                                                end_point_port,
                                                stream_count);

    }

    // create client if socket is valid
    if(client_id > 0){
        // socket info
        sockaddr_in si;
        int size_si = sizeof(sockaddr_in);
        // get local socket info
        getsockname(client_id, (sockaddr*)&si, (socklen_t*)&size_si);
        // add client
        auto client = new GDTClient(client_id,
                                    end_point_address,
                                    end_point_port,
                                    inet_ntoa(si.sin_addr),
                                    ntohs(si.sin_port),
                                    GDT_CD_OUTBOUND,
                                    max_concurrent_streams,
                                    stream_timeout,
                                    poll_interval);
        client->set_session(this);
        inc_thread_count();
        // start client threads
        client->init_threads();
        // GDT registration
        if(!skip_gdt_reg){
            // add client if registered
            if(register_client(client, ".") == 0){
                // process callback
                GDTCallbackArgs cb_args;
                cb_args.clear_all_args();
                cb_args.add_arg(GDT_CB_INPUT_ARGS, GDT_CB_ARG_CLIENT, client);
                process_callback(GDT_ET_CLIENT_CREATED, &cb_args);

                add_client(client);

                // free client on registration error
            }else{
                client->get_session()->remove_client(client);
                client = nullptr;
            }

        }else{
            add_client(client);

        }

        // return client
        return client;
    }
    // connection error
    return nullptr;
}


// namespace methods
gdt::GDTSession* gdt::init_session(const char* _daemon_type,
                                   const char* _daemon_id,
                                   int _max_concurrent_streams,
                                   int _stream_timeout,
                                   bool _router,
                                   int _poll_interval){
    return new GDTSession(_daemon_type,
                          _daemon_id,
                          _max_concurrent_streams,
                          _stream_timeout,
                          _router,
                          _poll_interval);
}

int gdt::destroy_session(GDTSession* gdt_session){
    if(gdt_session != nullptr){
        gdt_session->lock_clients();
        for(unsigned int i = 0; i<gdt_session->get_client_count(true); i++){
            gdt_session->get_client(i, true)->disconnect();
        }
        gdt_session->unlock_clients();

        // wait for session threads to finish

        timespec st = {0, 100000000};
        while(gdt_session->get_thread_count() > 0){
            nanosleep(&st, nullptr);
        }
        // free session
        delete gdt_session;
        // ok
        return 0;
    }
    // error
    return 1;

}

void gdt::stop_heartbeat(HeartbeatInfo* hi){
    if(hi != nullptr) hi->set_activity(false);
}

gdt::HeartbeatInfo* gdt::init_heartbeat(const char* _daemon_type,
                                        const char* _daemon_id,
                                        GDTClient* _client,
                                        unsigned int interval,
                                        GDTCallbackMethod* _on_received,
                                        GDTCallbackMethod* _on_missed,
                                        GDTCallbackMethod* _on_cleanup){

    if((_daemon_type != nullptr) && (_daemon_id != nullptr) && (_client != nullptr)){
        // check size
        if (strnlen(_daemon_type, 16) > 16 || strnlen(_daemon_id, 16) > 16)
            return nullptr;
        // crete heartbeat info object
        auto hi = new HeartbeatInfo();
        hi->set_activity(true);
        hi->set_next(true);
        hi->gdtc = _client;
        hi->interval = ((interval < 1) ? 1 : interval);
        hi->on_missed = _on_missed;
        hi->on_received = _on_received;
        hi->on_cleanup = _on_cleanup;
        memcpy(hi->target_daemon_type, _daemon_type, strlen(_daemon_type) + 1);
        memcpy(hi->target_daemon_id, _daemon_id, strlen(_daemon_id) + 1);
        // start thread
        pthread_t tmp_thr;
        if(pthread_create(&tmp_thr, nullptr, &hi->heartbeat_loop, hi) == 0){
            _client->inc_thread_count();
            pthread_setname_np(tmp_thr, "gdt_hbeat");
            return hi;
        }else{
            delete hi;
            return nullptr;
        }
    }

    // err
    return nullptr;
}


