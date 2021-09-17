/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef GDT_DEF_H_
#define GDT_DEF_H_

#include <asn1.h>

namespace asn1 {
    // forward declarations
    class Header;
    class SequenceFlag;
    class EndPointDescriptor;
    class Body;
    class StateMessage;
    class StateAction;
    class ServiceMessage;
    class ServiceId;
    class ServiceAction;
    class RoutingMessage;
    class RoutingAction;
    class RegistrationMessage;
    class RegistrationAction;
    class StatsMessage;
    class StatsAction;
    class AuthMessage;
    class AuthAction;
    class DataRetentionMessage;
    class DataRetentionAction;
    class FilterMessage;
    class FilterAction;
    class PacketFwdMessage;
    class NotifyMessage;
    class NotifyMessageType;
    class DataMessage;
    class PayloadType;
    class ConfigMessage;
    class ConfigAction;
    class Parameter;
    class Parameters;
    class PdCommandId;
    class FilterResultType;
    class ParameterType;
    class GeneralMessage;
    class HopInfo;
    class ErrorCode;
    class GDTMessage;
    class EncryptionInfo;
    class Parameter_value;

    // Parameter_value
    class Parameter_value : public Sequence_of {
    public:
        Parameter_value();
        ~Parameter_value() override;
        // nodes
        Octet_string* get_child(unsigned int child_index);
        void set_child(unsigned int child_index);
        ASN1Node* create_node(unsigned int _index) override;
        ASN1Node* get_next_node(unsigned int _index) override;
    };

    // Header
    class Header : public Sequence {
       public:
        Header();
        Header(const Header &o);
        ~Header() override;
        Header &operator=(const Header &o);
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_enc_info();
        void set_hop_info();
        void set_status();
        // nodes
        Integer* _version;
        EndPointDescriptor* _source;
        EndPointDescriptor* _destination;
        Octet_string* _uuid;
        Integer* _sequence_num;
        SequenceFlag* _sequence_flag;
        EncryptionInfo* _enc_info;
        HopInfo* _hop_info;
        ErrorCode* _status;
    };

    // SequenceFlag
    class SequenceFlag : public Integer {
    public:
        SequenceFlag();
        ~SequenceFlag() override;
        static const int _sf_start = 0;
        static const int _sf_continue = 1;
        static const int _sf_end = 2;
        static const int _sf_stateless_no_reply = 3;
        static const int _sf_stateless = 4;
        static const int _sf_stream_complete = 5;
        static const int _sf_continue_wait = 6;
        static const int _sf_heartbeat = 7;
    };

    // EndPointDescriptor
    class EndPointDescriptor : public Sequence {
    public:
        EndPointDescriptor();
        EndPointDescriptor(const EndPointDescriptor &o);
        ~EndPointDescriptor() override;
        EndPointDescriptor &operator=(const EndPointDescriptor &o);
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_id();
        // nodes
        IA5String* _type;
        IA5String* _id;
    };

    // Body
    class Body : public Choice {
    public:
        Body();
        Body(const Body &o);
        ~Body() override;
        Body &operator=(const Body &o);
        // nodes
        Octet_string* _encrypted_data;
        PacketFwdMessage* _packet_fwd;
        FilterMessage* _filter;
        DataRetentionMessage* _data_retention;
        ConfigMessage* _conf;
        StatsMessage* _stats;
        AuthMessage* _auth;
        RegistrationMessage* _reg;
        NotifyMessage* _ntfy;
        DataMessage* _data;
        RoutingMessage* _routing;
        ServiceMessage* _service_msg;
        StateMessage* _state_msg;
    };

    // StateMessage
    class StateMessage : public Sequence {
    public:
        StateMessage();
        StateMessage(const StateMessage &o);
        StateMessage &operator=(const StateMessage &o);
        ~StateMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        Octet_string* _stmch_id;
        StateAction* _state_action;
        Parameters* _params;
    };

    // StateAction
    class StateAction : public Integer {
    public:
        StateAction();
        ~StateAction() override;
        static const int _sta_update = 0;
    };

    // ServiceMessage
    class ServiceMessage : public Sequence {
    public:
        ServiceMessage();
        ServiceMessage(const ServiceMessage &o);
        ServiceMessage &operator=(const ServiceMessage &o);
        ~ServiceMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        ServiceId* _service_id;
        ServiceAction* _service_action;
        Parameters* _params;
    };

    // ServiceId
    class ServiceId : public Integer {
    public:
        ServiceId();
        ~ServiceId() override;
        static const int _sid_stp_routing = 42;
        static const int _sid_sgn_forward = 43;
        static const int _sid_fgn_filtering = 44;
        static const int _sid_security = 45;
        static const int _sid_pdn_filtering = 46;
        static const int _sid_sysagent = 47;
    };

    // ServiceAction
    class ServiceAction : public Integer {
    public:
        ServiceAction();
        ~ServiceAction() override;
        static const int _srvca_request = 0;
        static const int _srvca_result = 1;
        static const int _srvca_default = 2;
        static const int _srvca_na = 3;
    };

    // RoutingMessage
    class RoutingMessage : public Sequence {
    public:
        RoutingMessage();
        RoutingMessage(const RoutingMessage &o);
        RoutingMessage &operator=(const RoutingMessage &o);
        ~RoutingMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        RoutingAction* _routing_action;
        Parameters* _params;
    };

    // RoutingAction
    class RoutingAction : public Integer {
    public:
        RoutingAction();
        ~RoutingAction() override;
        static const int _roua_route_set = 0;
        static const int _roua_route_get = 1;
        static const int _roua_route_result = 2;
    };

    // RegistrationMessage
    class RegistrationMessage : public Sequence {
    public:
        RegistrationMessage();
        RegistrationMessage(const RegistrationMessage &o);
        RegistrationMessage &operator=(const RegistrationMessage &o);
        ~RegistrationMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        RegistrationAction* _reg_action;
        Parameters* _params;
    };

    // RegistrationAction
    class RegistrationAction : public Integer {
    public:
        RegistrationAction();
        ~RegistrationAction() override;
        static const int _ra_reg_request = 0;
        static const int _ra_reg_result = 1;
    };

    // StatsMessage
    class StatsMessage : public Sequence {
    public:
        StatsMessage();
        StatsMessage(const StatsMessage &o);
        StatsMessage &operator=(const StatsMessage &o);
        ~StatsMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        StatsAction* _stats_action;
        Parameters* _params;
    };

    // StatsAction
    class StatsAction : public Integer {
    public:
        StatsAction();
        ~StatsAction() override;
        static const int _sa_request = 0;
        static const int _sa_result = 1;
    };

    // AuthMessage
    class AuthMessage : public Sequence {
    public:
        AuthMessage();
        AuthMessage(const AuthMessage &o);
        AuthMessage &operator=(const AuthMessage &o);
        ~AuthMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        AuthAction* _auth_action;
        Parameters* _params;
    };

    // AuthAction
    class AuthAction : public Integer {
    public:
        AuthAction();
        ~AuthAction() override;
        static const int _aa_auth_request = 0;
        static const int _aa_auth_result = 1;
    };

    // DataRetentionMessage
    class DataRetentionMessage : public Sequence {
    public:
        DataRetentionMessage();
        DataRetentionMessage(const DataRetentionMessage &o);
        DataRetentionMessage &operator=(const DataRetentionMessage &o);
        ~DataRetentionMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_payload_type();
        void set_payload();
        void set_params();
        // nodes
        PayloadType* _payload_type;
        Octet_string* _payload;
        DataRetentionAction* _dr_action;
        Parameters* _params;
    };

    // DataRetentionAction
    class DataRetentionAction : public Integer {
    public:
        DataRetentionAction();
        ~DataRetentionAction() override;
        static const int _ra_store = 0;
        static const int _ra_delete = 1;
        static const int _ra_fetch = 2;
        static const int _ra_result = 3;
    };

    // FilterMessage
    class FilterMessage : public Sequence {
    public:
        FilterMessage();
        FilterMessage(const FilterMessage &o);
        FilterMessage &operator=(const FilterMessage &o);
        ~FilterMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        FilterAction* _filter_action;
        Parameters* _params;
    };

    // FilterAction
    class FilterAction : public Integer {
    public:
        FilterAction();
        ~FilterAction() override;
        static const int _fa_filter_request = 0;
        static const int _fa_filter_result = 1;
    };

    // PacketFwdMessage
    class PacketFwdMessage : public Sequence {
    public:
        PacketFwdMessage();
        PacketFwdMessage(const PacketFwdMessage &o);
        PacketFwdMessage &operator=(const PacketFwdMessage &o);
        ~PacketFwdMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_payload();
        void set_params();
        // nodes
        PayloadType* _payload_type;
        Octet_string* _payload;
        Parameters* _params;
    };

    // NotifyMessage
    class NotifyMessage : public Sequence {
    public:
        NotifyMessage();
        NotifyMessage(const NotifyMessage &o);
        NotifyMessage &operator=(const NotifyMessage &o);
        ~NotifyMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_message();
        void set_params();
        // nodes
        NotifyMessageType* _message_type;
        Octet_string* _message;
        Parameters* _params;
    };

    // NotifyMessageType
    class NotifyMessageType : public Integer {
    public:
        NotifyMessageType();
        ~NotifyMessageType() override;
    };

    // DataMessage
    class DataMessage : public Sequence {
    public:
        DataMessage();
        DataMessage(const DataMessage &o);
        DataMessage &operator=(const DataMessage &o);
        ~DataMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_payload();
        void set_params();
        // nodes
        PayloadType* _payload_type;
        Octet_string* _payload;
        Parameters* _params;
    };

    // PayloadType
    class PayloadType : public Integer {
    public:
        PayloadType();
        ~PayloadType() override;
        static const int _dmt_unknown = 1000;
        static const int _dmt_r14p = 2000;
        static const int _dmt_layer2 = 0;
        static const int _dmt_ip = 1;
        static const int _dmt_sctp = 2;
        static const int _dmt_tcp = 3;
        static const int _dmt_udp = 4;
        static const int _dmt_m3ua = 5;
        static const int _dmt_m2ua = 6;
        static const int _dmt_mtp3 = 7;
        static const int _dmt_isup = 8;
        static const int _dmt_h248 = 9;
        static const int _dmt_sccp = 10;
        static const int _dmt_smstpdu = 11;
        static const int _dmt_smpp = 12;
        static const int _dmt_tcap = 13;
        static const int _dmt_rtp = 14;
        static const int _dmt_sip = 15;
        static const int _dmt_pop3 = 16;
        static const int _dmt_imap = 17;
        static const int _dmt_http = 18;
        static const int _dmt_radius = 19;
        static const int _dmt_dhcp = 20;
        static const int _dmt_smtp = 21;
        static const int _dmt_m2pa = 22;
        static const int _dmt_mtp2 = 23;
    };

    // ConfigMessage
    class ConfigMessage : public Sequence {
    public:
        ConfigMessage();
        ConfigMessage(const ConfigMessage &o);
        ConfigMessage &operator=(const ConfigMessage &o);
        ~ConfigMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_payload();
        void set_params();
        // nodes
        ConfigAction* _action;
        Octet_string* _payload;
        Parameters* _params;
    };

    // ConfigAction
    class ConfigAction : public Integer {
    public:
        ConfigAction();
        ~ConfigAction() override;
        static const int _ca_cfg_get = 0;
        static const int _ca_cfg_set = 1;
        static const int _ca_cfg_replicate = 2;
        static const int _ca_cfg_ac = 3;
        static const int _ca_cfg_result = 4;
        static const int _ca_cfg_user_login = 5;
        static const int _ca_cfg_user_logout = 6;
    };

    // Parameter
    class Parameter : public Sequence {
    public:
        Parameter();
        Parameter(const Parameter &o);
        Parameter &operator=(const Parameter &o);
        ~Parameter() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_value();
        // nodes
        ParameterType* _id;
        Parameter_value* _value;
    };

    // Parameters
    class Parameters : public Sequence_of {
    public:
        Parameters();
        ~Parameters() override;
        // nodes
        Parameter* get_child(unsigned int child_index);
        void set_child(unsigned int child_index);
        ASN1Node* create_node(unsigned int _index) override;
        ASN1Node* get_next_node(unsigned int _index) override;
    };

    // PdCommandId
    class PdCommandId : public Integer {
    public:
        PdCommandId();
        ~PdCommandId() override;
        static const int _pdci_add = 1;
        static const int _pdci_del = 2;
        static const int _pdci_match = 3;
    };

    // FilterResultType
    class FilterResultType : public Integer {
    public:
        FilterResultType();
        ~FilterResultType() override;
        static const int _frt_accept = 1;
        static const int _frt_drop = 2;
    };

    // ParameterType
    class ParameterType : public Integer {
    public:
        ParameterType();
        ~ParameterType() override;
        static const int _pt_mink_daemon_type = 6000;
        static const int _pt_mink_daemon_id = 6001;
        static const int _pt_mink_auth_id = 6002;
        static const int _pt_mink_auth_password = 6003;
        static const int _pt_mink_daemon_ip = 6004;
        static const int _pt_mink_daemon_port = 6005;
        static const int _pt_mink_daemon_description = 6006;
        static const int _pt_mink_action = 6007;
        static const int _pt_mink_dpi = 6008;
        static const int _pt_mink_spi = 6009;
        static const int _pt_mink_timestamp = 6010;
        static const int _pt_mink_timestamp_nsec = 6011;
        static const int _pt_mink_security_phase = 6012;
        static const int _pt_mink_loop_count = 6013;
        static const int _pt_mink_checksum = 6014;
        static const int _pt_mink_routing_destination = 6100;
        static const int _pt_mink_routing_source = 6101;
        static const int _pt_mink_routing_gateway = 6102;
        static const int _pt_mink_routing_interface = 6103;
        static const int _pt_mink_routing_priority = 6104;
        static const int _pt_mink_router_status = 6105;
        static const int _pt_mink_routing_destination_type = 6106;
        static const int _pt_mink_routing_index = 6107;
        static const int _pt_mink_trunk_label = 6108;
        static const int _pt_mink_connection_type = 6109;
        static const int _pt_mink_service_id = 6110;
        static const int _pt_mink_command_id = 6111;
        static const int _pt_mink_routing_sub_destination = 6112;
        static const int _pt_mink_routing_sub_destination_type = 6113;
        static const int _pt_mink_correlation_notification = 6114;
        static const int _pt_mink_guid = 6115;
        static const int _pt_mink_routing_service_id = 6116;
        static const int _pt_mink_event_id = 6200;
        static const int _pt_mink_event_description = 6201;
        static const int _pt_mink_event_callback_id = 6202;
        static const int _pt_mink_event_callback_priority = 6203;
        static const int _pt_mink_enc_public_key = 6300;
        static const int _pt_mink_enc_private_key = 6301;
        static const int _pt_mink_enc_type = 6302;
        static const int _pt_mink_stats_id = 6400;
        static const int _pt_mink_stats_description = 6401;
        static const int _pt_mink_stats_value = 6402;
        static const int _pt_mink_stats_count = 6403;
        static const int _pt_mink_config_param_name = 7400;
        static const int _pt_mink_config_param_value = 7401;
        static const int _pt_mink_config_ac_line = 7402;
        static const int _pt_mink_config_cfg_item_name = 7403;
        static const int _pt_mink_config_cfg_item_desc = 7404;
        static const int _pt_mink_config_cfg_item_ns = 7405;
        static const int _pt_mink_config_cfg_item_value = 7406;
        static const int _pt_mink_config_cfg_item_nvalue = 7407;
        static const int _pt_mink_config_cfg_item_nt = 7408;
        static const int _pt_mink_config_cfg_cm_mode = 7409;
        static const int _pt_mink_config_cfg_ac_err = 7410;
        static const int _pt_mink_config_cli_path = 7411;
        static const int _pt_mink_config_cfg_line = 7412;
        static const int _pt_mink_config_ac_err_count = 7413;
        static const int _pt_mink_config_cfg_line_count = 7414;
        static const int _pt_mink_config_cfg_item_path = 7415;
        static const int _pt_mink_config_cfg_item_notify = 7416;
        static const int _pt_mink_config_cfg_item_count = 7417;
        static const int _pt_mink_config_replication_line = 7418;
        static const int _pt_mink_sms_status = 7500;
        static const int _pt_mink_sms_uuid = 7501;
        static const int _pt_mink_filter_result = 7600;
        static const int _pt_mink_filter_exit = 7601;
        static const int _pt_mink_filter_list_id = 7602;
        static const int _pt_mink_filter_list_label = 7603;
        static const int _pt_mink_filter_data = 7604;
        static const int _pt_mink_filter_data_size = 7605;
        static const int _pt_eth_destination_mac = 600;
        static const int _pt_eth_source_mac = 601;
        static const int _pt_ip_destination_ip = 700;
        static const int _pt_ip_source_ip = 701;
        static const int _pt_tcp_destination_port = 800;
        static const int _pt_tcp_source_port = 801;
        static const int _pt_udp_destination_port = 900;
        static const int _pt_udp_source_port = 901;
        static const int _pt_sctp_destination_port = 1000;
        static const int _pt_sctp_source_port = 1001;
        static const int _pt_gsmmap_scoa_digits = 500;
        static const int _pt_gsmmap_scoa_type_of_number = 501;
        static const int _pt_gsmmap_scoa_numbering_plan = 502;
        static const int _pt_gsmmap_scda_digits = 503;
        static const int _pt_gsmmap_scda_type_of_number = 504;
        static const int _pt_gsmmap_scda_numbering_plan = 505;
        static const int _pt_gsmmap_imsi = 506;
        static const int _pt_gsmmap_msisdn_digits = 507;
        static const int _pt_gsmmap_msisdn_type_of_number = 508;
        static const int _pt_gsmmap_msisdn_numbering_plan = 509;
        static const int _pt_tcap_source_transaction_id = 510;
        static const int _pt_tcap_destination_transaction_id = 511;
        static const int _pt_tcap_opcode = 512;
        static const int _pt_tcap_component_type = 513;
        static const int _pt_tcap_component_invoke_id = 514;
        static const int _pt_tcap_error_type = 515;
        static const int _pt_tcap_error_code = 516;
        static const int _pt_tcap_dialogue_context_oid = 517;
        static const int _pt_tcap_message_type = 518;
        static const int _pt_gsmmap_nnn_digits = 519;
        static const int _pt_gsmmap_nnn_type_of_number = 520;
        static const int _pt_gsmmap_nnn_numbering_plan = 521;
        static const int _pt_gsmmap_an_digits = 522;
        static const int _pt_gsmmap_an_type_of_number = 523;
        static const int _pt_gsmmap_an_numbering_plan = 524;
        static const int _pt_gsmmap_sca_digits = 525;
        static const int _pt_gsmmap_sca_type_of_number = 526;
        static const int _pt_gsmmap_sca_numbering_plan = 527;
        static const int _pt_tcap_component_count = 528;
        static const int _pt_tcap_dialogue_context_supported = 529;
        static const int _pt_tcap_component_index = 530;
        static const int _pt_tcap_source_transaction_id_length = 531;
        static const int _pt_tcap_destination_transaction_id_length = 532;
        static const int _pt_gsmmap_version = 533;
        static const int _pt_smstpdu_tp_udhi = 400;
        static const int _pt_smstpdu_tp_sri = 401;
        static const int _pt_smstpdu_tp_mms = 402;
        static const int _pt_smstpdu_tp_mti = 403;
        static const int _pt_smstpdu_tp_oa_type_of_number = 404;
        static const int _pt_smstpdu_tp_oa_numbering_plan = 405;
        static const int _pt_smstpdu_tp_oa_digits = 406;
        static const int _pt_smstpdu_tp_pid = 407;
        static const int _pt_smstpdu_tp_dcs = 408;
        static const int _pt_smstpdu_tp_scts = 409;
        static const int _pt_smstpdu_tp_udl = 410;
        static const int _pt_smstpdu_tp_ud = 411;
        static const int _pt_smstpdu_tp_rp = 412;
        static const int _pt_smstpdu_tp_srr = 413;
        static const int _pt_smstpdu_tp_vpf = 414;
        static const int _pt_smstpdu_tp_rd = 415;
        static const int _pt_smstpdu_tp_da_type_of_number = 416;
        static const int _pt_smstpdu_tp_da_numbering_plan = 417;
        static const int _pt_smstpdu_tp_da_digits = 418;
        static const int _pt_smstpdu_tp_vp = 419;
        static const int _pt_smstpdu_msg_id = 420;
        static const int _pt_smstpdu_msg_parts = 421;
        static const int _pt_smstpdu_msg_part = 422;
        static const int _pt_smstpdu_tp_mr = 423;
        static const int _pt_smstpdu_message_class = 424;
        static const int _pt_sccp_destination_local_reference = 300;
        static const int _pt_sccp_source_local_reference = 301;
        static const int _pt_sccp_called_party = 301;
        static const int _pt_sccp_calling_party = 302;
        static const int _pt_sccp_protocol_class = 303;
        static const int _pt_sccp_segmenting_reassembling = 304;
        static const int _pt_sccp_receive_sequence_number = 305;
        static const int _pt_sccp_sequencing_segmenting = 306;
        static const int _pt_sccp_credit = 307;
        static const int _pt_sccp_release_cause = 308;
        static const int _pt_sccp_return_cause = 309;
        static const int _pt_sccp_reset_cause = 310;
        static const int _pt_sccp_error_cause = 311;
        static const int _pt_sccp_refusal_cause = 312;
        static const int _pt_sccp_data = 313;
        static const int _pt_sccp_segmentation = 314;
        static const int _pt_sccp_hop_counter = 315;
        static const int _pt_sccp_importance = 316;
        static const int _pt_sccp_long_data = 317;
        static const int _pt_sccp_called_pa_routing_indicator = 318;
        static const int _pt_sccp_called_pa_global_title_indicator = 319;
        static const int _pt_sccp_called_pa_ssn_indicator = 320;
        static const int _pt_sccp_called_pa_point_code_indicator = 321;
        static const int _pt_sccp_called_pa_point_code_number = 322;
        static const int _pt_sccp_called_pa_subsystem_number = 323;
        static const int _pt_sccp_called_pa_gt_numbering_plan = 324;
        static const int _pt_sccp_called_pa_gt_encoding_scheme = 325;
        static const int _pt_sccp_called_pa_gt_nature_of_address = 326;
        static const int _pt_sccp_called_pa_gt_address = 327;
        static const int _pt_sccp_called_pa_gt_translation_type = 328;
        static const int _pt_sccp_calling_pa_routing_indicator = 329;
        static const int _pt_sccp_calling_pa_global_title_indicator = 330;
        static const int _pt_sccp_calling_pa_ssn_indicator = 331;
        static const int _pt_sccp_calling_pa_point_code_indicator = 332;
        static const int _pt_sccp_calling_pa_point_code_number = 333;
        static const int _pt_sccp_calling_pa_subsystem_number = 334;
        static const int _pt_sccp_calling_pa_gt_numbering_plan = 335;
        static const int _pt_sccp_calling_pa_gt_encoding_scheme = 336;
        static const int _pt_sccp_calling_pa_gt_nature_of_address = 337;
        static const int _pt_sccp_calling_pa_gt_address = 338;
        static const int _pt_sccp_calling_pa_gt_translation_type = 339;
        static const int _pt_sccp_message_type = 340;
        static const int _pt_m3ua_info_string = 200;
        static const int _pt_m3ua_routing_context = 201;
        static const int _pt_m3ua_diagnostic_info = 202;
        static const int _pt_m3ua_heartbeat = 203;
        static const int _pt_m3ua_traffic_mode_type = 204;
        static const int _pt_m3ua_error_code = 205;
        static const int _pt_m3ua_status = 206;
        static const int _pt_m3ua_asp_identifier = 207;
        static const int _pt_m3ua_affected_point_code = 208;
        static const int _pt_m3ua_correlation_id = 209;
        static const int _pt_m3ua_network_appearance = 210;
        static const int _pt_m3ua_user_cause = 211;
        static const int _pt_m3ua_congestion_indications = 212;
        static const int _pt_m3ua_concerned_destination = 213;
        static const int _pt_m3ua_routing_key = 214;
        static const int _pt_m3ua_registration_result = 215;
        static const int _pt_m3ua_deregistration_result = 216;
        static const int _pt_m3ua_local_routing_key_identifier = 217;
        static const int _pt_m3ua_destination_point_code = 218;
        static const int _pt_m3ua_service_indicators = 219;
        static const int _pt_m3ua_origination_point_code_list = 220;
        static const int _pt_m3ua_circuit_range = 221;
        static const int _pt_m3ua_protocol_data = 222;
        static const int _pt_m3ua_protocol_data_service_indicator = 223;
        static const int _pt_m3ua_protocol_data_network_indicator = 224;
        static const int _pt_m3ua_protocol_data_message_priority = 225;
        static const int _pt_m3ua_protocol_data_destination_point_code = 226;
        static const int _pt_m3ua_protocol_data_originating_point_code = 227;
        static const int _pt_m3ua_protocol_data_signalling_link_selection_code = 228;
        static const int _pt_m3ua_registration_status = 229;
        static const int _pt_m3ua_deregistration_status = 230;
        static const int _pt_m3ua_header_data = 231;
        static const int _pt_m3ua_as_label = 232;
        static const int _pt_m3ua_asp_label = 233;
    };

    // GeneralMessage
    class GeneralMessage : public Any {
    public:
        GeneralMessage();
        ~GeneralMessage() override;
    };

    // HopInfo
    class HopInfo : public Sequence {
    public:
        HopInfo();
        HopInfo(const HopInfo &o);
        HopInfo &operator=(const HopInfo &o);
        ~HopInfo() override;
        // nodes
        Integer* _current_hop;
        Integer* _max_hops;
    };

    // ErrorCode
    class ErrorCode : public Integer {
    public:
        ErrorCode();
        ~ErrorCode() override;
        static const int _err_ok = 0;
        static const int _err_out_of_sequence = 1;
        static const int _err_unknown_sequence = 2;
        static const int _err_unsupported_version = 3;
        static const int _err_timeout = 4;
        static const int _err_unknown_route = 5;
        static const int _err_routing_not_supported = 6;
        static const int _err_max_hops_exceeded = 7;
        static const int _err_unknown_error = 255;
    };

    // GDTMessage
    class GDTMessage : public Sequence {
    public:
        GDTMessage();
        GDTMessage(const GDTMessage &o);
        GDTMessage &operator=(const GDTMessage &o);
        ~GDTMessage() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_body();
        // nodes
        Header* _header;
        Body* _body;
    };

    // EncryptionInfo
    class EncryptionInfo : public Sequence {
    public:
        EncryptionInfo();
        EncryptionInfo(const EncryptionInfo &o);
        EncryptionInfo &operator=(const EncryptionInfo &o);
        ~EncryptionInfo() override;
        // optional
        ASN1Node* create_node(unsigned int _index) override;
        void set_params();
        // nodes
        Octet_string* _enc_type;
        Parameters* _params;
    };

}  // namespace asn1
#endif
