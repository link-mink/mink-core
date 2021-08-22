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
    strcpy(node_type_name, "Header");
    // version
    _version = NULL;
    _version = new Integer();
    _version->tlv->tag_class = CONTEXT_SPECIFIC;
    _version->tlv->tag_value = 0;
    children.push_back(_version);

    // source
    _source = NULL;
    _source = new EndPointDescriptor();
    _source->tlv->tag_class = CONTEXT_SPECIFIC;
    _source->tlv->tag_value = 1;
    children.push_back(_source);

    // destination
    _destination = NULL;
    _destination = new EndPointDescriptor();
    _destination->tlv->tag_class = CONTEXT_SPECIFIC;
    _destination->tlv->tag_value = 2;
    children.push_back(_destination);

    // uuid
    _uuid = NULL;
    _uuid = new Octet_string();
    _uuid->tlv->tag_class = CONTEXT_SPECIFIC;
    _uuid->tlv->tag_value = 3;
    children.push_back(_uuid);

    // sequence_num
    _sequence_num = NULL;
    _sequence_num = new Integer();
    _sequence_num->tlv->tag_class = CONTEXT_SPECIFIC;
    _sequence_num->tlv->tag_value = 4;
    children.push_back(_sequence_num);

    // sequence_flag
    _sequence_flag = NULL;
    _sequence_flag = new SequenceFlag();
    _sequence_flag->tlv->tag_class = CONTEXT_SPECIFIC;
    _sequence_flag->tlv->tag_value = 5;
    children.push_back(_sequence_flag);

    // enc_info
    _enc_info = NULL;
    children.push_back(_enc_info);

    // hop_info
    _hop_info = NULL;
    children.push_back(_hop_info);

    // status
    _status = NULL;
    children.push_back(_status);


}
asn1::Header::~Header(){

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

        default: return NULL;
    }
}

void asn1::Header::set_enc_info(){
    if(_enc_info == NULL) _enc_info = (EncryptionInfo*)create_node(6);
}

void asn1::Header::set_hop_info(){
    if(_hop_info == NULL) _hop_info = (HopInfo*)create_node(7);
}

void asn1::Header::set_status(){
    if(_status == NULL) _status = (ErrorCode*)create_node(8);
}

//SequenceFlag
asn1::SequenceFlag::SequenceFlag(){
    strcpy(node_type_name, "SequenceFlag");

}
asn1::SequenceFlag::~SequenceFlag(){

}

//EndPointDescriptor
asn1::EndPointDescriptor::EndPointDescriptor(){
    strcpy(node_type_name, "EndPointDescriptor");
    // type
    _type = NULL;
    _type = new IA5String();
    _type->tlv->tag_class = CONTEXT_SPECIFIC;
    _type->tlv->tag_value = 1;
    children.push_back(_type);

    // id
    _id = NULL;
    children.push_back(_id);


}
asn1::EndPointDescriptor::~EndPointDescriptor(){

}

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

        default: return NULL;
    }
}

void asn1::EndPointDescriptor::set_id(){
    if(_id == NULL) _id = (IA5String*)create_node(1);
}

//Body
asn1::Body::Body(){
    strcpy(node_type_name, "Body");
    // encrypted_data
    _encrypted_data = NULL;
    _encrypted_data = new Octet_string();
    _encrypted_data->tlv->tag_class = CONTEXT_SPECIFIC;
    _encrypted_data->tlv->tag_value = 1;
    children.push_back(_encrypted_data);

    // packet_fwd
    _packet_fwd = NULL;
    _packet_fwd = new PacketFwdMessage();
    _packet_fwd->tlv->tag_class = CONTEXT_SPECIFIC;
    _packet_fwd->tlv->tag_value = 2;
    children.push_back(_packet_fwd);

    // filter
    _filter = NULL;
    _filter = new FilterMessage();
    _filter->tlv->tag_class = CONTEXT_SPECIFIC;
    _filter->tlv->tag_value = 3;
    children.push_back(_filter);

    // data_retention
    _data_retention = NULL;
    _data_retention = new DataRetentionMessage();
    _data_retention->tlv->tag_class = CONTEXT_SPECIFIC;
    _data_retention->tlv->tag_value = 4;
    children.push_back(_data_retention);

    // conf
    _conf = NULL;
    _conf = new ConfigMessage();
    _conf->tlv->tag_class = CONTEXT_SPECIFIC;
    _conf->tlv->tag_value = 6;
    children.push_back(_conf);

    // stats
    _stats = NULL;
    _stats = new StatsMessage();
    _stats->tlv->tag_class = CONTEXT_SPECIFIC;
    _stats->tlv->tag_value = 7;
    children.push_back(_stats);

    // auth
    _auth = NULL;
    _auth = new AuthMessage();
    _auth->tlv->tag_class = CONTEXT_SPECIFIC;
    _auth->tlv->tag_value = 8;
    children.push_back(_auth);

    // reg
    _reg = NULL;
    _reg = new RegistrationMessage();
    _reg->tlv->tag_class = CONTEXT_SPECIFIC;
    _reg->tlv->tag_value = 9;
    children.push_back(_reg);

    // ntfy
    _ntfy = NULL;
    _ntfy = new NotifyMessage();
    _ntfy->tlv->tag_class = CONTEXT_SPECIFIC;
    _ntfy->tlv->tag_value = 10;
    children.push_back(_ntfy);

    // data
    _data = NULL;
    _data = new DataMessage();
    _data->tlv->tag_class = CONTEXT_SPECIFIC;
    _data->tlv->tag_value = 11;
    children.push_back(_data);

    // routing
    _routing = NULL;
    _routing = new RoutingMessage();
    _routing->tlv->tag_class = CONTEXT_SPECIFIC;
    _routing->tlv->tag_value = 12;
    children.push_back(_routing);

    // service_msg
    _service_msg = NULL;
    _service_msg = new ServiceMessage();
    _service_msg->tlv->tag_class = CONTEXT_SPECIFIC;
    _service_msg->tlv->tag_value = 13;
    children.push_back(_service_msg);

    // state_msg
    _state_msg = NULL;
    _state_msg = new StateMessage();
    _state_msg->tlv->tag_class = CONTEXT_SPECIFIC;
    _state_msg->tlv->tag_value = 14;
    children.push_back(_state_msg);


}
asn1::Body::~Body(){

}

//StateMessage
asn1::StateMessage::StateMessage(){
    strcpy(node_type_name, "StateMessage");
    // stmch_id
    _stmch_id = NULL;
    _stmch_id = new Octet_string();
    children.push_back(_stmch_id);

    // state_action
    _state_action = NULL;
    _state_action = new StateAction();
    children.push_back(_state_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::StateMessage::~StateMessage(){

}

asn1::ASN1Node* asn1::StateMessage::create_node(unsigned int _index){
    switch(_index){
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::StateMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(2);
}

//StateAction
asn1::StateAction::StateAction(){
    strcpy(node_type_name, "StateAction");

}
asn1::StateAction::~StateAction(){

}

//ServiceMessage
asn1::ServiceMessage::ServiceMessage(){
    strcpy(node_type_name, "ServiceMessage");
    // service_id
    _service_id = NULL;
    _service_id = new ServiceId();
    children.push_back(_service_id);

    // service_action
    _service_action = NULL;
    _service_action = new ServiceAction();
    children.push_back(_service_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::ServiceMessage::~ServiceMessage(){

}

asn1::ASN1Node* asn1::ServiceMessage::create_node(unsigned int _index){
    switch(_index){
        case 2:
            {
                _params = new Parameters();
                children[2] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::ServiceMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(2);
}

//ServiceId
asn1::ServiceId::ServiceId(){
    strcpy(node_type_name, "ServiceId");

}
asn1::ServiceId::~ServiceId(){

}

//ServiceAction
asn1::ServiceAction::ServiceAction(){
    strcpy(node_type_name, "ServiceAction");

}
asn1::ServiceAction::~ServiceAction(){

}

//RoutingMessage
asn1::RoutingMessage::RoutingMessage(){
    strcpy(node_type_name, "RoutingMessage");
    // routing_action
    _routing_action = NULL;
    _routing_action = new RoutingAction();
    children.push_back(_routing_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::RoutingMessage::~RoutingMessage(){

}

asn1::ASN1Node* asn1::RoutingMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::RoutingMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(1);
}

//RoutingAction
asn1::RoutingAction::RoutingAction(){
    strcpy(node_type_name, "RoutingAction");

}
asn1::RoutingAction::~RoutingAction(){

}

//RegistrationMessage
asn1::RegistrationMessage::RegistrationMessage(){
    strcpy(node_type_name, "RegistrationMessage");
    // reg_action
    _reg_action = NULL;
    _reg_action = new RegistrationAction();
    children.push_back(_reg_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::RegistrationMessage::~RegistrationMessage(){

}

asn1::ASN1Node* asn1::RegistrationMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::RegistrationMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(1);
}

//RegistrationAction
asn1::RegistrationAction::RegistrationAction(){
    strcpy(node_type_name, "RegistrationAction");

}
asn1::RegistrationAction::~RegistrationAction(){

}

//StatsMessage
asn1::StatsMessage::StatsMessage(){
    strcpy(node_type_name, "StatsMessage");
    // stats_action
    _stats_action = NULL;
    _stats_action = new StatsAction();
    children.push_back(_stats_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::StatsMessage::~StatsMessage(){

}

asn1::ASN1Node* asn1::StatsMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::StatsMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(1);
}

//StatsAction
asn1::StatsAction::StatsAction(){
    strcpy(node_type_name, "StatsAction");

}
asn1::StatsAction::~StatsAction(){

}

//AuthMessage
asn1::AuthMessage::AuthMessage(){
    strcpy(node_type_name, "AuthMessage");
    // auth_action
    _auth_action = NULL;
    _auth_action = new AuthAction();
    children.push_back(_auth_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::AuthMessage::~AuthMessage(){

}

asn1::ASN1Node* asn1::AuthMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::AuthMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(1);
}

//AuthAction
asn1::AuthAction::AuthAction(){
    strcpy(node_type_name, "AuthAction");

}
asn1::AuthAction::~AuthAction(){

}

//DataRetentionMessage
asn1::DataRetentionMessage::DataRetentionMessage(){
    strcpy(node_type_name, "DataRetentionMessage");
    // payload_type
    _payload_type = NULL;
    children.push_back(_payload_type);

    // payload
    _payload = NULL;
    children.push_back(_payload);

    // dr_action
    _dr_action = NULL;
    _dr_action = new DataRetentionAction();
    children.push_back(_dr_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::DataRetentionMessage::~DataRetentionMessage(){

}

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

        default: return NULL;
    }
}

void asn1::DataRetentionMessage::set_payload_type(){
    if(_payload_type == NULL) _payload_type = (PayloadType*)create_node(0);
}

void asn1::DataRetentionMessage::set_payload(){
    if(_payload == NULL) _payload = (Octet_string*)create_node(1);
}

void asn1::DataRetentionMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(3);
}

//DataRetentionAction
asn1::DataRetentionAction::DataRetentionAction(){
    strcpy(node_type_name, "DataRetentionAction");

}
asn1::DataRetentionAction::~DataRetentionAction(){

}

//FilterMessage
asn1::FilterMessage::FilterMessage(){
    strcpy(node_type_name, "FilterMessage");
    // filter_action
    _filter_action = NULL;
    _filter_action = new FilterAction();
    children.push_back(_filter_action);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::FilterMessage::~FilterMessage(){

}

asn1::ASN1Node* asn1::FilterMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::FilterMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(1);
}

//FilterAction
asn1::FilterAction::FilterAction(){
    strcpy(node_type_name, "FilterAction");

}
asn1::FilterAction::~FilterAction(){

}

//PacketFwdMessage
asn1::PacketFwdMessage::PacketFwdMessage(){
    strcpy(node_type_name, "PacketFwdMessage");
    // payload_type
    _payload_type = NULL;
    _payload_type = new PayloadType();
    children.push_back(_payload_type);

    // payload
    _payload = NULL;
    children.push_back(_payload);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::PacketFwdMessage::~PacketFwdMessage(){

}

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

        default: return NULL;
    }
}

void asn1::PacketFwdMessage::set_payload(){
    if(_payload == NULL) _payload = (Octet_string*)create_node(1);
}

void asn1::PacketFwdMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(2);
}

//NotifyMessage
asn1::NotifyMessage::NotifyMessage(){
    strcpy(node_type_name, "NotifyMessage");
    // message_type
    _message_type = NULL;
    _message_type = new NotifyMessageType();
    children.push_back(_message_type);

    // message
    _message = NULL;
    children.push_back(_message);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::NotifyMessage::~NotifyMessage(){

}

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

        default: return NULL;
    }
}

void asn1::NotifyMessage::set_message(){
    if(_message == NULL) _message = (Octet_string*)create_node(1);
}

void asn1::NotifyMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(2);
}

//NotifyMessageType
asn1::NotifyMessageType::NotifyMessageType(){
    strcpy(node_type_name, "NotifyMessageType");

}
asn1::NotifyMessageType::~NotifyMessageType(){

}

//DataMessage
asn1::DataMessage::DataMessage(){
    strcpy(node_type_name, "DataMessage");
    // payload_type
    _payload_type = NULL;
    _payload_type = new PayloadType();
    children.push_back(_payload_type);

    // payload
    _payload = NULL;
    children.push_back(_payload);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::DataMessage::~DataMessage(){

}

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

        default: return NULL;
    }
}

void asn1::DataMessage::set_payload(){
    if(_payload == NULL) _payload = (Octet_string*)create_node(1);
}

void asn1::DataMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(2);
}

//PayloadType
asn1::PayloadType::PayloadType(){
    strcpy(node_type_name, "PayloadType");

}
asn1::PayloadType::~PayloadType(){

}

//ConfigMessage
asn1::ConfigMessage::ConfigMessage(){
    strcpy(node_type_name, "ConfigMessage");
    // action
    _action = NULL;
    _action = new ConfigAction();
    children.push_back(_action);

    // payload
    _payload = NULL;
    children.push_back(_payload);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::ConfigMessage::~ConfigMessage(){

}

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

        default: return NULL;
    }
}

void asn1::ConfigMessage::set_payload(){
    if(_payload == NULL) _payload = (Octet_string*)create_node(1);
}

void asn1::ConfigMessage::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(2);
}

//ConfigAction
asn1::ConfigAction::ConfigAction(){
    strcpy(node_type_name, "ConfigAction");

}
asn1::ConfigAction::~ConfigAction(){

}

//Parameter
asn1::Parameter::Parameter(){
    strcpy(node_type_name, "Parameter");
    // id
    _id = NULL;
    _id = new ParameterType();
    children.push_back(_id);

    // value
    _value = NULL;
    children.push_back(_value);


}
asn1::Parameter::~Parameter(){

}

asn1::ASN1Node* asn1::Parameter::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _value = new Parameter_value();
                children[1] = _value;
                return _value;
            }

        default: return NULL;
    }
}

void asn1::Parameter::set_value(){
    if(_value == NULL) _value = (Parameter_value*)create_node(1);
}

//Parameter_value
asn1::Parameter_value::Parameter_value(){
    strcpy(node_type_name, "Parameter_value");

}
asn1::Parameter_value::~Parameter_value(){
}

asn1::Octet_string* asn1::Parameter_value::get_child(unsigned int child_index){
    if(child_index < children.size()) return (Octet_string*)children[child_index]; else return NULL;
}

void asn1::Parameter_value::set_child(unsigned int child_index){
    if(child_index < children.size()){
        if(children[child_index] == NULL) children[child_index] = create_node(child_index);
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
    strcpy(node_type_name, "Parameters");

}
asn1::Parameters::~Parameters(){
}

asn1::Parameter* asn1::Parameters::get_child(unsigned int child_index){
    if(child_index < children.size()) return (Parameter*)children[child_index]; else return NULL;
}

void asn1::Parameters::set_child(unsigned int child_index){
    if(child_index < children.size()){
        if(children[child_index] == NULL) children[child_index] = create_node(child_index);
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
    strcpy(node_type_name, "PdCommandId");

}
asn1::PdCommandId::~PdCommandId(){

}

//FilterResultType
asn1::FilterResultType::FilterResultType(){
    strcpy(node_type_name, "FilterResultType");

}
asn1::FilterResultType::~FilterResultType(){

}

//ParameterType
asn1::ParameterType::ParameterType(){
    strcpy(node_type_name, "ParameterType");

}
asn1::ParameterType::~ParameterType(){

}

//GeneralMessage
asn1::GeneralMessage::GeneralMessage(){
    strcpy(node_type_name, "GeneralMessage");

}
asn1::GeneralMessage::~GeneralMessage(){

}

//HopInfo
asn1::HopInfo::HopInfo(){
    strcpy(node_type_name, "HopInfo");
    // current_hop
    _current_hop = NULL;
    _current_hop = new Integer();
    _current_hop->tlv->tag_class = CONTEXT_SPECIFIC;
    _current_hop->tlv->tag_value = 1;
    children.push_back(_current_hop);

    // max_hops
    _max_hops = NULL;
    _max_hops = new Integer();
    _max_hops->tlv->tag_class = CONTEXT_SPECIFIC;
    _max_hops->tlv->tag_value = 2;
    children.push_back(_max_hops);


}
asn1::HopInfo::~HopInfo(){

}

//ErrorCode
asn1::ErrorCode::ErrorCode(){
    strcpy(node_type_name, "ErrorCode");

}
asn1::ErrorCode::~ErrorCode(){

}

//GDTMessage
asn1::GDTMessage::GDTMessage(){
    strcpy(node_type_name, "GDTMessage");
    // header
    _header = NULL;
    _header = new Header();
    children.push_back(_header);

    // body
    _body = NULL;
    children.push_back(_body);


}
asn1::GDTMessage::~GDTMessage(){

}

asn1::ASN1Node* asn1::GDTMessage::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _body = new Body();
                children[1] = _body;
                return _body;
            }

        default: return NULL;
    }
}

void asn1::GDTMessage::set_body(){
    if(_body == NULL) _body = (Body*)create_node(1);
}

//EncryptionInfo
asn1::EncryptionInfo::EncryptionInfo(){
    strcpy(node_type_name, "EncryptionInfo");
    // enc_type
    _enc_type = NULL;
    _enc_type = new Octet_string();
    children.push_back(_enc_type);

    // params
    _params = NULL;
    children.push_back(_params);


}
asn1::EncryptionInfo::~EncryptionInfo(){

}

asn1::ASN1Node* asn1::EncryptionInfo::create_node(unsigned int _index){
    switch(_index){
        case 1:
            {
                _params = new Parameters();
                children[1] = _params;
                return _params;
            }

        default: return NULL;
    }
}

void asn1::EncryptionInfo::set_params(){
    if(_params == NULL) _params = (Parameters*)create_node(1);
}

