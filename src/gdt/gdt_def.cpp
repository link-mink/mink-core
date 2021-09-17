/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <gdt_def.h>
#include <iostream>

//Header
asn1::Header::Header(){
    node_type_name.assign("Header");
    // version
    _version = nullptr;
    _version = new Integer();
    _version->tlv->tag_class = CONTEXT_SPECIFIC;
    _version->tlv->tag_value = 0;
    children.push_back(_version);

    // source
    _source = nullptr;
    _source = new EndPointDescriptor();
    _source->tlv->tag_class = CONTEXT_SPECIFIC;
    _source->tlv->tag_value = 1;
    children.push_back(_source);

    // destination
    _destination = nullptr;
    _destination = new EndPointDescriptor();
    _destination->tlv->tag_class = CONTEXT_SPECIFIC;
    _destination->tlv->tag_value = 2;
    children.push_back(_destination);

    // uuid
    _uuid = nullptr;
    _uuid = new Octet_string();
    _uuid->tlv->tag_class = CONTEXT_SPECIFIC;
    _uuid->tlv->tag_value = 3;
    children.push_back(_uuid);

    // sequence_num
    _sequence_num = nullptr;
    _sequence_num = new Integer();
    _sequence_num->tlv->tag_class = CONTEXT_SPECIFIC;
    _sequence_num->tlv->tag_value = 4;
    children.push_back(_sequence_num);

    // sequence_flag
    _sequence_flag = nullptr;
    _sequence_flag = new SequenceFlag();
    _sequence_flag->tlv->tag_class = CONTEXT_SPECIFIC;
    _sequence_flag->tlv->tag_value = 5;
    children.push_back(_sequence_flag);

    // enc_info
    _enc_info = nullptr;
    children.push_back(_enc_info);

    // hop_info
    _hop_info = nullptr;
    children.push_back(_hop_info);

    // status
    _status = nullptr;
    children.push_back(_status);
}
asn1::Header::~Header() = default;

static void copy_Header(asn1::Header &t, const asn1::Header &o){
    t.node_type_name.assign(o.node_type_name);
     // version
    t._version = nullptr;
    if (o._version) {
        t._version = new asn1::Integer();
        *t._version->tlv = *o._version->tlv;
    }
    t.children.push_back(t._version);

    // source
    t._source = nullptr;
    if (o._source) {
        t._source = new asn1::EndPointDescriptor();
        *t._source->tlv = *o._source->tlv;
    }
    t.children.push_back(t._source);

    // destination
    t._destination = nullptr;
    if (o._destination) {
        t._destination = new asn1::EndPointDescriptor();
        *t._destination->tlv = *o._destination->tlv;
    }
    t.children.push_back(t._destination);

    // uuid
    t._uuid = nullptr;
    if (o._uuid) {
        t._uuid = new asn1::Octet_string();
        *t._uuid->tlv = *o._uuid->tlv;
    }
    t.children.push_back(t._uuid);

    // sequence_num
    if (o._sequence_num) {
        t._sequence_num = new asn1::Integer();
        *t._sequence_num->tlv = *o._sequence_num->tlv;
    }
    t.children.push_back(t._sequence_num);

    // sequence_flag
    t._sequence_flag = nullptr;
    if (o._sequence_flag) {
        t._sequence_flag = new asn1::SequenceFlag();
        *t._sequence_flag->tlv = *o._sequence_flag->tlv;
    }
    t.children.push_back(t._sequence_flag);

    // enc_info
    t._enc_info = nullptr;
    if (o._enc_info) {
        t._enc_info = new asn1::EncryptionInfo();
        *t._enc_info->tlv = *o._enc_info->tlv;
    }
    t.children.push_back(t._enc_info);

    // hop_info
    t._hop_info = nullptr;
    if (o._hop_info) {
        t._hop_info = new asn1::HopInfo();
        *t._hop_info->tlv = *o._hop_info->tlv;
    }
    t.children.push_back(t._hop_info);

    // status
    t._status = nullptr;
    if (o._status) {
        t._status = new asn1::ErrorCode();
        *t._status->tlv = *o._status->tlv;
    }
    t.children.push_back(t._status);

}

asn1::Header::Header(const Header &o){
    copy_Header(*this, o);
}

asn1::Header &asn1::Header::operator=(const Header &o){
    if (this == &o) return *this;
    copy_Header(*this, o);
    return *this;
}

asn1::ASN1Node* asn1::Header::create_node(unsigned int _index){
    switch(_index){
        case 6:
            {
                _enc_info = new EncryptionInfo();
                _enc_info->tlv->tag_class = CONTEXT_SPECIFIC;
                _enc_info->tlv->tag_value = 6;
                children[6] = _enc_info;
                return _enc_info;
            }
        case 7:
            {
                _hop_info = new HopInfo();
                _hop_info->tlv->tag_class = CONTEXT_SPECIFIC;
                _hop_info->tlv->tag_value = 7;
                children[7] = _hop_info;
                return _hop_info;
            }
        case 8:
            {
                _status = new ErrorCode();
                _status->tlv->tag_class = CONTEXT_SPECIFIC;
                _status->tlv->tag_value = 8;
                children[8] = _status;
                return _status;
            }

        default: return nullptr;
    }
}

void asn1::Header::set_enc_info(){
    if(_enc_info == nullptr) _enc_info = (EncryptionInfo*)create_node(6);
}

void asn1::Header::set_hop_info(){
    if(_hop_info == nullptr) _hop_info = (HopInfo*)create_node(7);
}

void asn1::Header::set_status(){
    if(_status == nullptr) _status = (ErrorCode*)create_node(8);
}

//SequenceFlag
asn1::SequenceFlag::SequenceFlag(){
    node_type_name.assign("SequenceFlag");

}
asn1::SequenceFlag::~SequenceFlag() = default;

//EndPointDescriptor
asn1::EndPointDescriptor::EndPointDescriptor(){
    node_type_name.assign("EndPointDescriptor");
    // type
    _type = nullptr;
    _type = new IA5String();
    _type->tlv->tag_class = CONTEXT_SPECIFIC;
    _type->tlv->tag_value = 1;
    children.push_back(_type);

    // id
    _id = nullptr;
    children.push_back(_id);


}

static void copy_EndPointDescriptor(asn1::EndPointDescriptor &t, 
                                    const asn1::EndPointDescriptor  &o){
    t.node_type_name.assign(o.node_type_name);
    // type
    t._type = nullptr;
    if (o._type) {
        t._type = new asn1::IA5String();
        *t._type->tlv = *o._type->tlv;
    }
    t.children.push_back(t._type);

    // id
    t._id = nullptr;
    if (o._id) {
        t._id= new asn1::IA5String();
        *t._id->tlv = *o._id->tlv;
    }
    t.children.push_back(t._id);

}

asn1::EndPointDescriptor::EndPointDescriptor(const EndPointDescriptor &o){
    copy_EndPointDescriptor(*this, o);
}

asn1::EndPointDescriptor &asn1::EndPointDescriptor::operator=(const EndPointDescriptor &o){
    if (this == &o) return *this;
    copy_EndPointDescriptor(*this, o);
    return *this;
}

asn1::EndPointDescriptor::~EndPointDescriptor() = default;

asn1::ASN1Node* asn1::EndPointDescriptor::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _id = new IA5String();
                _id->tlv->tag_class = CONTEXT_SPECIFIC;
                _id->tlv->tag_value = 2;
                children[1] = _id;
                return _id;
            }

        default: return nullptr;
    }
}

void asn1::EndPointDescriptor::set_id(){
    if(_id == nullptr) _id = (IA5String*)create_node(1);
}

//Body
asn1::Body::Body(){
    node_type_name.assign("Body");
    // encrypted_data
    _encrypted_data = nullptr;
    _encrypted_data = new Octet_string();
    _encrypted_data->tlv->tag_class = CONTEXT_SPECIFIC;
    _encrypted_data->tlv->tag_value = 1;
    children.push_back(_encrypted_data);

    // packet_fwd
    _packet_fwd = nullptr;
    _packet_fwd = new PacketFwdMessage();
    _packet_fwd->tlv->tag_class = CONTEXT_SPECIFIC;
    _packet_fwd->tlv->tag_value = 2;
    children.push_back(_packet_fwd);

    // filter
    _filter = nullptr;
    _filter = new FilterMessage();
    _filter->tlv->tag_class = CONTEXT_SPECIFIC;
    _filter->tlv->tag_value = 3;
    children.push_back(_filter);

    // data_retention
    _data_retention = nullptr;
    _data_retention = new DataRetentionMessage();
    _data_retention->tlv->tag_class = CONTEXT_SPECIFIC;
    _data_retention->tlv->tag_value = 4;
    children.push_back(_data_retention);

    // conf
    _conf = nullptr;
    _conf = new ConfigMessage();
    _conf->tlv->tag_class = CONTEXT_SPECIFIC;
    _conf->tlv->tag_value = 6;
    children.push_back(_conf);

    // stats
    _stats = nullptr;
    _stats = new StatsMessage();
    _stats->tlv->tag_class = CONTEXT_SPECIFIC;
    _stats->tlv->tag_value = 7;
    children.push_back(_stats);

    // auth
    _auth = nullptr;
    _auth = new AuthMessage();
    _auth->tlv->tag_class = CONTEXT_SPECIFIC;
    _auth->tlv->tag_value = 8;
    children.push_back(_auth);

    // reg
    _reg = nullptr;
    _reg = new RegistrationMessage();
    _reg->tlv->tag_class = CONTEXT_SPECIFIC;
    _reg->tlv->tag_value = 9;
    children.push_back(_reg);

    // ntfy
    _ntfy = nullptr;
    _ntfy = new NotifyMessage();
    _ntfy->tlv->tag_class = CONTEXT_SPECIFIC;
    _ntfy->tlv->tag_value = 10;
    children.push_back(_ntfy);

    // data
    _data = nullptr;
    _data = new DataMessage();
    _data->tlv->tag_class = CONTEXT_SPECIFIC;
    _data->tlv->tag_value = 11;
    children.push_back(_data);

    // routing
    _routing = nullptr;
    _routing = new RoutingMessage();
    _routing->tlv->tag_class = CONTEXT_SPECIFIC;
    _routing->tlv->tag_value = 12;
    children.push_back(_routing);

    // service_msg
    _service_msg = nullptr;
    _service_msg = new ServiceMessage();
    _service_msg->tlv->tag_class = CONTEXT_SPECIFIC;
    _service_msg->tlv->tag_value = 13;
    children.push_back(_service_msg);

    // state_msg
    _state_msg = nullptr;
    _state_msg = new StateMessage();
    _state_msg->tlv->tag_class = CONTEXT_SPECIFIC;
    _state_msg->tlv->tag_value = 14;
    children.push_back(_state_msg);


}


static void copy_Body(asn1::Body &t, const asn1::Body &o){
    t.node_type_name.assign(o.node_type_name);
    // encrypted_data
    t._encrypted_data = nullptr;
    if (o._encrypted_data) {
        t._encrypted_data = new asn1::Octet_string();
        *t._encrypted_data->tlv = *o._encrypted_data->tlv;
    }
    t.children.push_back(t._encrypted_data);

    // packet_fwd
    t._packet_fwd = nullptr;
    if (o._packet_fwd) {
        t._packet_fwd = new asn1::PacketFwdMessage();
        *t._packet_fwd->tlv = *o._packet_fwd->tlv;
    }
    t.children.push_back(t._packet_fwd);

    // filter
    t._filter = nullptr;
    if (o._filter) {
        t._filter = new asn1::FilterMessage();
        *t._filter->tlv = *o._filter->tlv;
    }
    t.children.push_back(t._filter);

    // data_retention
    t._data_retention = nullptr;
    if (o._data_retention) {
        t._data_retention = new asn1::DataRetentionMessage();
        *t._data_retention->tlv = *o._data_retention->tlv;
    }
    t.children.push_back(t._data_retention);

    // conf
    t._conf = nullptr;
    if (o._conf) {
        t._conf = new asn1::ConfigMessage();
        *t._conf->tlv = *o._conf->tlv;
    }
    t.children.push_back(t._conf);

    // stats
    t._stats = nullptr;
    if (o._stats) {
        t._stats = new asn1::StatsMessage();
        *t._stats->tlv = *o._stats->tlv;
    }
    t.children.push_back(t._stats);

    // auth
    t._auth = nullptr;
    if (o._auth) {
        t._auth = new asn1::AuthMessage();
        *t._auth->tlv = *o._auth->tlv;
    }
    t.children.push_back(t._auth);

    // reg
    t._reg = nullptr;
    if (o._reg) {
        t._reg = new asn1::RegistrationMessage();
        *t._reg->tlv = *o._reg->tlv;
    }
    t.children.push_back(t._reg);

    // ntfy
    t._ntfy = nullptr;
    if (o._ntfy) {
        t._ntfy = new asn1::NotifyMessage();
        *t._ntfy->tlv = *o._ntfy->tlv;
    }
    t.children.push_back(t._ntfy);

    // data
    t._data = nullptr;
    if (o._data) {
        t._data = new asn1::DataMessage();
        *t._data->tlv = *o._data->tlv;
    }
    t.children.push_back(t._data);

    // routing
    t._routing = nullptr;
    if (o._routing) {
        t._routing = new asn1::RoutingMessage();
        *t._routing->tlv = *o._routing->tlv;
    }
    t.children.push_back(t._routing);

    // service_msg
    t._service_msg = nullptr;
    if (o._service_msg) {
        t._service_msg = new asn1::ServiceMessage();
        *t._service_msg->tlv = *o._service_msg->tlv;
    }
    t.children.push_back(t._service_msg);

    // state_msg
    t._state_msg = nullptr;
    if (o._state_msg) {
        t._state_msg = new asn1::StateMessage();
        *t._state_msg->tlv = *o._state_msg->tlv;
    }
    t.children.push_back(t._state_msg);


}

asn1::Body::Body(const Body &o){
    copy_Body(*this, o);
}

asn1::Body &asn1::Body::operator=(const Body &o){
    if (this == &o) return *this;
    copy_Body(*this, o);
    return *this;
}

asn1::Body::~Body() = default;

//StateMessage
asn1::StateMessage::StateMessage(){
    node_type_name.assign("StateMessage");
    // stmch_id
    _stmch_id = nullptr;
    _stmch_id = new Octet_string();
    children.push_back(_stmch_id);

    // state_action
    _state_action = nullptr;
    _state_action = new StateAction();
    children.push_back(_state_action);

    // params
    _params = nullptr;
    children.push_back(_params);
}

static void copy_StateMessage(asn1::StateMessage &t, const asn1::StateMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // stmch_id
    t._stmch_id = nullptr;
    if (o._stmch_id) {
        t._stmch_id = new asn1::Octet_string();
        *t._stmch_id->tlv = *o._stmch_id->tlv;
    }
    t.children.push_back(t._stmch_id);

    // state_action
    t._state_action = nullptr;
    if (o._state_action) {
        t._state_action = new asn1::StateAction();
        *t._state_action->tlv = *o._state_action->tlv;
    }
    t.children.push_back(t._state_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);
}


asn1::StateMessage::StateMessage(const StateMessage &o){
    copy_StateMessage(*this, o);
}

asn1::StateMessage &asn1::StateMessage::operator=(const StateMessage &o){
    if (this == &o) return *this;
    copy_StateMessage(*this, o);
    return *this;
}


asn1::StateMessage::~StateMessage() = default;

asn1::ASN1Node* asn1::StateMessage::create_node(unsigned int _index){
    switch(_index){
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::StateMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(2);
}

//StateAction
asn1::StateAction::StateAction(){
    node_type_name.assign("StateAction");

}
asn1::StateAction::~StateAction() = default;

//ServiceMessage
asn1::ServiceMessage::ServiceMessage(){
    node_type_name.assign("ServiceMessage");
    // service_id
    _service_id = nullptr;
    _service_id = new ServiceId();
    children.push_back(_service_id);

    // service_action
    _service_action = nullptr;
    _service_action = new ServiceAction();
    children.push_back(_service_action);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_ServiceMessage(asn1::ServiceMessage &t, const asn1::ServiceMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // service_id
    t._service_id = nullptr;
    if (o._service_id) {
        t._service_id = new asn1::ServiceId();
        *t._service_id->tlv = *o._service_id->tlv;
    }
    t.children.push_back(t._service_id);

    // service_action
    t._service_action = nullptr;
    if (o._service_action) {
        t._service_action = new asn1::ServiceAction();
        *t._service_action->tlv = *o._service_action->tlv;
    }
    t.children.push_back(t._service_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);


}

asn1::ServiceMessage::ServiceMessage(const ServiceMessage &o){
    copy_ServiceMessage(*this, o);
}

asn1::ServiceMessage &asn1::ServiceMessage::operator=(const ServiceMessage &o){
    if (this == &o) return *this;
    copy_ServiceMessage(*this, o);
    return *this;
}



asn1::ServiceMessage::~ServiceMessage() = default;

asn1::ASN1Node* asn1::ServiceMessage::create_node(unsigned int _index){
    switch(_index){
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::ServiceMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(2);
}

//ServiceId
asn1::ServiceId::ServiceId(){
    node_type_name.assign("ServiceId");

}
asn1::ServiceId::~ServiceId() = default;

//ServiceAction
asn1::ServiceAction::ServiceAction(){
    node_type_name.assign("ServiceAction");

}
asn1::ServiceAction::~ServiceAction() = default;

//RoutingMessage
asn1::RoutingMessage::RoutingMessage(){
    node_type_name.assign("RoutingMessage");
    // routing_action
    _routing_action = nullptr;
    _routing_action = new RoutingAction();
    children.push_back(_routing_action);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_RoutingMessage(asn1::RoutingMessage &t, const asn1::RoutingMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // routing_action
    t._routing_action = nullptr;
    if (o._routing_action) {
        t._routing_action = new asn1::RoutingAction();
        *t._routing_action->tlv = *o._routing_action->tlv;
    }
    t.children.push_back(t._routing_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);


}

asn1::RoutingMessage::RoutingMessage(const RoutingMessage &o){
    copy_RoutingMessage(*this, o);
}

asn1::RoutingMessage &asn1::RoutingMessage::operator=(const RoutingMessage &o){
    if (this == &o) return *this;
    copy_RoutingMessage(*this, o);
    return *this;
}


asn1::RoutingMessage::~RoutingMessage() = default;

asn1::ASN1Node* asn1::RoutingMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::RoutingMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(1);
}

//RoutingAction
asn1::RoutingAction::RoutingAction(){
    node_type_name.assign("RoutingAction");

}
asn1::RoutingAction::~RoutingAction() = default;

//RegistrationMessage
asn1::RegistrationMessage::RegistrationMessage(){
    node_type_name.assign("RegistrationMessage");
    // reg_action
    _reg_action = nullptr;
    _reg_action = new RegistrationAction();
    children.push_back(_reg_action);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_RegistrationMessage(asn1::RegistrationMessage &t, 
                                     const asn1::RegistrationMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // reg_action
    t._reg_action = nullptr;
    if (o._reg_action) {
        t._reg_action = new asn1::RegistrationAction();
        *t._reg_action->tlv = *o._reg_action->tlv;
    }
    t.children.push_back(t._reg_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);


}

asn1::RegistrationMessage::RegistrationMessage(const RegistrationMessage &o){
    copy_RegistrationMessage(*this, o);
}

asn1::RegistrationMessage &asn1::RegistrationMessage::operator=(const RegistrationMessage &o){
    if (this == &o) return *this;
    copy_RegistrationMessage(*this, o);
    return *this;
}

asn1::RegistrationMessage::~RegistrationMessage() = default;

asn1::ASN1Node* asn1::RegistrationMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::RegistrationMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(1);
}

//RegistrationAction
asn1::RegistrationAction::RegistrationAction(){
    node_type_name.assign("RegistrationAction");

}
asn1::RegistrationAction::~RegistrationAction() = default;

//StatsMessage
asn1::StatsMessage::StatsMessage(){
    node_type_name.assign("StatsMessage");
    // stats_action
    _stats_action = nullptr;
    _stats_action = new StatsAction();
    children.push_back(_stats_action);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_StatsMessage(asn1::StatsMessage &t, const asn1::StatsMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // stats_action
    t._stats_action = nullptr;
    if (o._stats_action) {
        t._stats_action = new asn1::StatsAction();
        *t._stats_action->tlv = *o._stats_action->tlv;
    }
    t.children.push_back(t._stats_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);


}

asn1::StatsMessage::StatsMessage(const StatsMessage &o){
    copy_StatsMessage(*this, o);
}

asn1::StatsMessage &asn1::StatsMessage::operator=(const StatsMessage &o){
    if (this == &o) return *this;
    copy_StatsMessage(*this, o);
    return *this;
}

asn1::StatsMessage::~StatsMessage() = default;

asn1::ASN1Node* asn1::StatsMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::StatsMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(1);
}

//StatsAction
asn1::StatsAction::StatsAction(){
    node_type_name.assign("StatsAction");

}
asn1::StatsAction::~StatsAction() = default;

//AuthMessage
asn1::AuthMessage::AuthMessage(){
    node_type_name.assign("AuthMessage");
    // auth_action
    _auth_action = nullptr;
    _auth_action = new AuthAction();
    children.push_back(_auth_action);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_AuthMessage(asn1::AuthMessage &t, const asn1::AuthMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // auth_action
    t._auth_action = nullptr;
    if (o._auth_action) {
        t._auth_action = new asn1::AuthAction();
        *t._auth_action->tlv = *o._auth_action->tlv;
    }
    t.children.push_back(t._auth_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);


}


asn1::AuthMessage::AuthMessage(const AuthMessage &o){
    copy_AuthMessage(*this, o);
}

asn1::AuthMessage &asn1::AuthMessage::operator=(const AuthMessage &o){
    if (this == &o) return *this;
    copy_AuthMessage(*this, o);
    return *this;
}

asn1::AuthMessage::~AuthMessage() = default;

asn1::ASN1Node* asn1::AuthMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::AuthMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(1);
}

//AuthAction
asn1::AuthAction::AuthAction(){
    node_type_name.assign("AuthAction");

}
asn1::AuthAction::~AuthAction() = default;

//DataRetentionMessage
asn1::DataRetentionMessage::DataRetentionMessage(){
    node_type_name.assign("DataRetentionMessage");
    // payload_type
    _payload_type = nullptr;
    children.push_back(_payload_type);

    // payload
    _payload = nullptr;
    children.push_back(_payload);

    // dr_action
    _dr_action = nullptr;
    _dr_action = new DataRetentionAction();
    children.push_back(_dr_action);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_DataRetentionMessage(asn1::DataRetentionMessage &t, 
                                      const asn1::DataRetentionMessage &o){

    t.node_type_name.assign(o.node_type_name);
    // payload_type 
    t._payload_type = nullptr;
    if (o._payload_type) {
        t._payload_type = new asn1::PayloadType();
        *t._payload_type->tlv = *o._payload_type->tlv;
    }
    t.children.push_back(t._payload_type);

    // payload
    t._payload = nullptr;
    if (o._payload) {
        t._payload = new asn1::Octet_string();
        *t._payload->tlv = *o._payload->tlv;
    }
    t.children.push_back(t._payload);

    // dr_action
    t._dr_action = nullptr;
    if (o._dr_action) {
        t._dr_action = new asn1::DataRetentionAction();
        *t._dr_action->tlv = *o._dr_action->tlv;
    }
    t.children.push_back(t._dr_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);


}

asn1::DataRetentionMessage::DataRetentionMessage(const DataRetentionMessage &o){
    copy_DataRetentionMessage(*this, o);
}

asn1::DataRetentionMessage &asn1::DataRetentionMessage::operator=(const DataRetentionMessage &o){
    if (this == &o) return *this;
    copy_DataRetentionMessage(*this, o);
    return *this;
}

asn1::DataRetentionMessage::~DataRetentionMessage() = default;

asn1::ASN1Node* asn1::DataRetentionMessage::create_node(unsigned int _index){
    switch(_index){
        case 0:
            {
                _payload_type = new PayloadType();
                children[0] = _payload_type;
                return _payload_type;
            }
        case 1:
            {
                _payload = new Octet_string();
                children[1] = _payload;
                return _payload;
            }
        case 3:
            {
                _params = new Parameters();
                children[3] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::DataRetentionMessage::set_payload_type(){
    if(_payload_type == nullptr) _payload_type = (PayloadType*)create_node(0);
}

void asn1::DataRetentionMessage::set_payload(){
    if(_payload == nullptr) _payload = (Octet_string*)create_node(1);
}

void asn1::DataRetentionMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(3);
}

//DataRetentionAction
asn1::DataRetentionAction::DataRetentionAction(){
    node_type_name.assign("DataRetentionAction");

}
asn1::DataRetentionAction::~DataRetentionAction() = default;

//FilterMessage
asn1::FilterMessage::FilterMessage(){
    node_type_name.assign("FilterMessage");
    // filter_action
    _filter_action = nullptr;
    _filter_action = new FilterAction();
    children.push_back(_filter_action);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_FilterMessage(asn1::FilterMessage &t, const asn1::FilterMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // filter_action
    t._filter_action = nullptr;
    if (o._filter_action) {
        t._filter_action = new asn1::FilterAction();
        *t._filter_action->tlv = *o._filter_action->tlv;
    }
    t.children.push_back(t._filter_action);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);
}

asn1::FilterMessage::FilterMessage(const FilterMessage &o){
    copy_FilterMessage(*this, o);
}

asn1::FilterMessage &asn1::FilterMessage::operator=(const FilterMessage &o){
    if (this == &o) return *this;
    copy_FilterMessage(*this, o);
    return *this;
}

asn1::FilterMessage::~FilterMessage() = default;

asn1::ASN1Node* asn1::FilterMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::FilterMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(1);
}

//FilterAction
asn1::FilterAction::FilterAction(){
    node_type_name.assign("FilterAction");

}
asn1::FilterAction::~FilterAction() = default;

//PacketFwdMessage
asn1::PacketFwdMessage::PacketFwdMessage(){
    node_type_name.assign("PacketFwdMessage");
    // payload_type
    _payload_type = nullptr;
    _payload_type = new PayloadType();
    children.push_back(_payload_type);

    // payload
    _payload = nullptr;
    children.push_back(_payload);

    // params
    _params = nullptr;
    children.push_back(_params);
}


static void copy_PacketFwdMessage(asn1::PacketFwdMessage &t, 
                                  const asn1::PacketFwdMessage &o){

    t.node_type_name.assign(o.node_type_name);
    // payload_type 
    t._payload_type = nullptr;
    if (o._payload_type) {
        t._payload_type = new asn1::PayloadType();
        *t._payload_type->tlv = *o._payload_type->tlv;
    }
    t.children.push_back(t._payload_type);

    // payload
    t._payload = nullptr;
    if (o._payload) {
        t._payload = new asn1::Octet_string();
        *t._payload->tlv = *o._payload->tlv;
    }
    t.children.push_back(t._payload);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);
}


asn1::PacketFwdMessage::PacketFwdMessage(const PacketFwdMessage &o){
    copy_PacketFwdMessage(*this, o);
}

asn1::PacketFwdMessage &asn1::PacketFwdMessage::operator=(const PacketFwdMessage &o){
    if (this == &o) return *this;
    copy_PacketFwdMessage(*this, o);
    return *this;
}

asn1::PacketFwdMessage::~PacketFwdMessage() = default;

asn1::ASN1Node* asn1::PacketFwdMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _payload = new Octet_string();
                children[1] = _payload;
                return _payload;
            }
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::PacketFwdMessage::set_payload(){
    if(_payload == nullptr) _payload = (Octet_string*)create_node(1);
}

void asn1::PacketFwdMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(2);
}

//NotifyMessage
asn1::NotifyMessage::NotifyMessage(){
    node_type_name.assign("NotifyMessage");
    // message_type
    _message_type = nullptr;
    _message_type = new NotifyMessageType();
    children.push_back(_message_type);

    // message
    _message = nullptr;
    children.push_back(_message);

    // params
    _params = nullptr;
    children.push_back(_params);


}


static void copy_NotifyMessage(asn1::NotifyMessage &t, const asn1::NotifyMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // message_type 
    t._message_type = nullptr;
    if (o._message_type) {
        t._message_type = new asn1::NotifyMessageType();
        *t._message_type->tlv = *o._message_type->tlv;
    }
    t.children.push_back(t._message_type);

    // message
    t._message = nullptr;
    if (o._message) {
        t._message = new asn1::Octet_string();
        *t._message->tlv = *o._message->tlv;
    }
    t.children.push_back(t._message);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);
}


asn1::NotifyMessage::NotifyMessage(const NotifyMessage &o){
    copy_NotifyMessage(*this, o);
}

asn1::NotifyMessage &asn1::NotifyMessage::operator=(const NotifyMessage &o){
    if (this == &o) return *this;
    copy_NotifyMessage(*this, o);
    return *this;
}

asn1::NotifyMessage::~NotifyMessage() = default;

asn1::ASN1Node* asn1::NotifyMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _message = new Octet_string();
                children[1] = _message;
                return _message;
            }
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::NotifyMessage::set_message(){
    if(_message == nullptr) _message = (Octet_string*)create_node(1);
}

void asn1::NotifyMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(2);
}

//NotifyMessageType
asn1::NotifyMessageType::NotifyMessageType(){
    node_type_name.assign("NotifyMessageType");

}
asn1::NotifyMessageType::~NotifyMessageType() = default;

//DataMessage
asn1::DataMessage::DataMessage(){
    node_type_name.assign("DataMessage");
    // payload_type
    _payload_type = nullptr;
    _payload_type = new PayloadType();
    children.push_back(_payload_type);

    // payload
    _payload = nullptr;
    children.push_back(_payload);

    // params
    _params = nullptr;
    children.push_back(_params);


}

static void copy_DataMessage(asn1::DataMessage &t, const asn1::DataMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // payload_type 
    t._payload_type = nullptr;
    if (o._payload_type) {
        t._payload_type = new asn1::PayloadType();
        *t._payload_type->tlv = *o._payload_type->tlv;
    }
    t.children.push_back(t._payload_type);

    // payload
    t._payload = nullptr;
    if (o._payload) {
        t._payload = new asn1::Octet_string();
        *t._payload->tlv = *o._payload->tlv;
    }
    t.children.push_back(t._payload);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);
}

asn1::DataMessage::DataMessage(const DataMessage &o){
    copy_DataMessage(*this, o);
}

asn1::DataMessage &asn1::DataMessage::operator=(const DataMessage &o){
    if (this == &o) return *this;
    copy_DataMessage(*this, o);
    return *this;
}

asn1::DataMessage::~DataMessage() = default;

asn1::ASN1Node* asn1::DataMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _payload = new Octet_string();
                children[1] = _payload;
                return _payload;
            }
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::DataMessage::set_payload(){
    if(_payload == nullptr) _payload = (Octet_string*)create_node(1);
}

void asn1::DataMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(2);
}

//PayloadType
asn1::PayloadType::PayloadType(){
    node_type_name.assign("PayloadType");

}
asn1::PayloadType::~PayloadType() = default;

//ConfigMessage
asn1::ConfigMessage::ConfigMessage(){
    node_type_name.assign("ConfigMessage");
    // action
    _action = nullptr;
    _action = new ConfigAction();
    children.push_back(_action);

    // payload
    _payload = nullptr;
    children.push_back(_payload);

    // params
    _params = nullptr;
    children.push_back(_params);

}

static void copy_ConfigMessage(asn1::ConfigMessage &t, const asn1::ConfigMessage &o){
    t.node_type_name.assign(o.node_type_name);
    //action 
    t._action = nullptr;
    if (o._action) {
        t._action = new asn1::ConfigAction();
        *t._action->tlv = *o._action->tlv;
    }
    t.children.push_back(t._action);

    // payload
    t._payload = nullptr;
    if (o._payload) {
        t._payload = new asn1::Octet_string();
        *t._payload->tlv = *o._payload->tlv;
    }
    t.children.push_back(t._payload);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);
}

asn1::ConfigMessage::ConfigMessage(const ConfigMessage &o){
    copy_ConfigMessage(*this, o);
}

asn1::ConfigMessage &asn1::ConfigMessage::operator=(const ConfigMessage &o){
    if (this == &o) return *this;
    copy_ConfigMessage(*this, o);
    return *this;
}

asn1::ConfigMessage::~ConfigMessage() = default;

asn1::ASN1Node* asn1::ConfigMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _payload = new Octet_string();
                children[1] = _payload;
                return _payload;
            }
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::ConfigMessage::set_payload(){
    if(_payload == nullptr) _payload = (Octet_string*)create_node(1);
}

void asn1::ConfigMessage::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(2);
}

//ConfigAction
asn1::ConfigAction::ConfigAction(){
    node_type_name.assign("ConfigAction");

}
asn1::ConfigAction::~ConfigAction() = default;

//Parameter
asn1::Parameter::Parameter(){
    node_type_name.assign("Parameter");
    // id
    _id = nullptr;
    _id = new ParameterType();
    children.push_back(_id);

    // value
    _value = nullptr;
    children.push_back(_value);


}

static void copy_Parameter(asn1::Parameter &t, const asn1::Parameter &o){
    t.node_type_name.assign(o.node_type_name);
    // id 
    t._id = nullptr;
    if (o._id) {
        t._id = new asn1::ParameterType();
        *t._id->tlv = *o._id->tlv;
    }
    t.children.push_back(t._id);

    // value
    t._value = nullptr;
    if (o._value) {
        t._value = new asn1::Parameter_value();
        *t._value->tlv = *o._value->tlv;
    }
    t.children.push_back(t._value);
}

asn1::Parameter::Parameter(const Parameter &o){
    copy_Parameter(*this, o);
}

asn1::Parameter &asn1::Parameter::operator=(const Parameter &o){
    if (this == &o) return *this;
    copy_Parameter(*this, o);
    return *this;
}


asn1::Parameter::~Parameter() = default;

asn1::ASN1Node* asn1::Parameter::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _value = new Parameter_value();
                children[1] = _value;
                return _value;
            }

        default: return nullptr;
    }
}

void asn1::Parameter::set_value(){
    if(_value == nullptr) _value = (Parameter_value*)create_node(1);
}

//Parameter_value
asn1::Parameter_value::Parameter_value(){
    node_type_name.assign("Parameter_value");

}
asn1::Parameter_value::~Parameter_value() = default;

asn1::Octet_string* asn1::Parameter_value::get_child(unsigned int child_index){
    if(child_index < children.size()) return (Octet_string*)children[child_index]; else return nullptr;
}

void asn1::Parameter_value::set_child(unsigned int child_index){
    if(child_index < children.size()){
        if(children[child_index] == nullptr) children[child_index] = create_node(child_index);
    }else get_next_node(child_index);
}

asn1::ASN1Node* asn1::Parameter_value::create_node(unsigned int _index){
    children[_index] = new Octet_string();
    return children[_index];
}

asn1::ASN1Node* asn1::Parameter_value::get_next_node(unsigned int _index){
    if(_index < children.size()) return children[_index]; else{
        children.push_back(new Octet_string());
        return children[children.size() - 1];
    }

}

//Parameters
asn1::Parameters::Parameters(){
    node_type_name.assign("Parameters");

}
asn1::Parameters::~Parameters() = default;

asn1::Parameter* asn1::Parameters::get_child(unsigned int child_index){
    if(child_index < children.size()) return (Parameter*)children[child_index]; else return nullptr;
}

void asn1::Parameters::set_child(unsigned int child_index){
    if(child_index < children.size()){
        if(children[child_index] == nullptr) children[child_index] = create_node(child_index);
    }else get_next_node(child_index);
}

asn1::ASN1Node* asn1::Parameters::create_node(unsigned int _index){
    children[_index] = new Parameter();
    return children[_index];
}

asn1::ASN1Node* asn1::Parameters::get_next_node(unsigned int _index){
    if(_index < children.size()) return children[_index]; else{
        children.push_back(new Parameter());
        return children[children.size() - 1];
    }

}

//PdCommandId
asn1::PdCommandId::PdCommandId(){
    node_type_name.assign("PdCommandId");

}
asn1::PdCommandId::~PdCommandId() = default;

//FilterResultType
asn1::FilterResultType::FilterResultType(){
    node_type_name.assign("FilterResultType");

}
asn1::FilterResultType::~FilterResultType() = default;

//ParameterType
asn1::ParameterType::ParameterType(){
    node_type_name.assign("ParameterType");

}
asn1::ParameterType::~ParameterType() = default;

//GeneralMessage
asn1::GeneralMessage::GeneralMessage(){
    node_type_name.assign("GeneralMessage");

}
asn1::GeneralMessage::~GeneralMessage() = default;

//HopInfo
asn1::HopInfo::HopInfo(){
    node_type_name.assign("HopInfo");
    // current_hop
    _current_hop = nullptr;
    _current_hop = new Integer();
    _current_hop->tlv->tag_class = CONTEXT_SPECIFIC;
    _current_hop->tlv->tag_value = 1;
    children.push_back(_current_hop);

    // max_hops
    _max_hops = nullptr;
    _max_hops = new Integer();
    _max_hops->tlv->tag_class = CONTEXT_SPECIFIC;
    _max_hops->tlv->tag_value = 2;
    children.push_back(_max_hops);


}

static void copy_HopInfo(asn1::HopInfo &t, const asn1::HopInfo &o){
    t.node_type_name.assign(o.node_type_name);
    // current_hop 
    t._current_hop = nullptr;
    if (o._current_hop) {
        t._current_hop = new asn1::Integer();
        *t._current_hop->tlv = *o._current_hop->tlv;
    }
    t.children.push_back(t._current_hop);

    // max_hops
    t._max_hops = nullptr;
    if (o._max_hops) {
        t._max_hops = new asn1::Integer();
        *t._max_hops->tlv = *o._max_hops->tlv;
    }
    t.children.push_back(t._max_hops);
}

asn1::HopInfo::HopInfo(const HopInfo &o){
    copy_HopInfo(*this, o);
}

asn1::HopInfo &asn1::HopInfo::operator=(const HopInfo &o){
    if (this == &o) return *this;
    copy_HopInfo(*this, o);
    return *this;
}

asn1::HopInfo::~HopInfo() = default;

//ErrorCode
asn1::ErrorCode::ErrorCode(){
    node_type_name.assign("ErrorCode");

}
asn1::ErrorCode::~ErrorCode() = default;

//GDTMessage
asn1::GDTMessage::GDTMessage(){
    node_type_name.assign("GDTMessage");
    // header
    _header = nullptr;
    _header = new Header();
    children.push_back(_header);

    // body
    _body = nullptr;
    children.push_back(_body);


}

static void copy_GDTMessage(asn1::GDTMessage &t, const asn1::GDTMessage &o){
    t.node_type_name.assign(o.node_type_name);
    // header 
    t._header = nullptr;
    if (o._header) {
        t._header = new asn1::Header();
        *t._header->tlv = *o._header->tlv;
    }
    t.children.push_back(t._header);

    // body
    t._body = nullptr;
    if (o._body) {
        t._body = new asn1::Body();
        *t._body->tlv = *o._body->tlv;
    }
    t.children.push_back(t._body);
}

asn1::GDTMessage::GDTMessage(const GDTMessage &o){
    copy_GDTMessage(*this, o);
}


asn1::GDTMessage &asn1::GDTMessage::operator=(const GDTMessage &o){
    if (this == &o) return *this;
    copy_GDTMessage(*this, o);
    return *this;
}

asn1::GDTMessage::~GDTMessage() = default;

asn1::ASN1Node* asn1::GDTMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _body = new Body();
                children[1] = _body;
                return _body;
            }

        default: return nullptr;
    }
}

void asn1::GDTMessage::set_body(){
    if(_body == nullptr) _body = (Body*)create_node(1);
}

//EncryptionInfo
asn1::EncryptionInfo::EncryptionInfo(){
    node_type_name.assign("EncryptionInfo");
    // enc_type
    _enc_type = nullptr;
    _enc_type = new Octet_string();
    children.push_back(_enc_type);

    // params
    _params = nullptr;
    children.push_back(_params);

}

static void copy_EncryptionInfo(asn1::EncryptionInfo &t, 
                                const asn1::EncryptionInfo &o){

    t.node_type_name.assign(o.node_type_name);
    // enc_type 
    t._enc_type = nullptr;
    if (o._enc_type) {
        t._enc_type = new asn1::Octet_string();
        *t._enc_type->tlv = *o._enc_type->tlv;
    }
    t.children.push_back(t._enc_type);

    // params
    t._params = nullptr;
    if (o._params) {
        t._params = new asn1::Parameters();
        *t._params->tlv = *o._params->tlv;
    }
    t.children.push_back(t._params);
}

asn1::EncryptionInfo::EncryptionInfo(const EncryptionInfo &o){
    copy_EncryptionInfo(*this, o);
}


asn1::EncryptionInfo &asn1::EncryptionInfo::operator=(const EncryptionInfo &o){
    if (this == &o) return *this;
    copy_EncryptionInfo(*this, o);
    return *this;

}

asn1::EncryptionInfo::~EncryptionInfo() = default;

asn1::ASN1Node* asn1::EncryptionInfo::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return nullptr;
    }
}

void asn1::EncryptionInfo::set_params(){
    if(_params == nullptr) _params = (Parameters*)create_node(1);
}

