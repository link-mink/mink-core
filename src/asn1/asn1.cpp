/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <asn1.h>
#include <mink_utils.h>
#include <stdio.h>
#include <endian.h>
#include <iomanip>
#include <iostream>

// Session id
asn1::SessionId::SessionId() { session_id = 0; }

// if session_id is zero, set all elements' session_id to zero and generate next
// session_id zero session_id is encountered when all available sessions have
// been used (highly unlikely) and reset is needed to avoid session data
// overlapping

uint64_t asn1::SessionId::get_next_id(asn1::ASN1Node* _node) {
    ++session_id;
    if (session_id == 0) {
        _node->set_session_id(session_id);
        ++session_id;
    }

    return session_id;
}

uint64_t asn1::SessionId::get_current_id() { return session_id; }

uint64_t asn1::SessionId::get_next_id() {
    ++session_id;
    return session_id;
}

// Pool classes
asn1::ASN1Pool::ASN1Pool() {
    tlv_count = 100;
    asn1_node_count = 100;
    next_free_asn1_node = NULL;
    next_free_tlv = NULL;
    free_tlv_count = tlv_count;
    free_asn1_node_count = asn1_node_count;
}

asn1::ASN1Pool::~ASN1Pool() {
    for (int i = 0; i < asn1_node_count; i++) {
        // children and tlv have to be cleared or double free corruption can
        // occur every asn1node frees its own children but in case of pooling
        // this has to be avoided since all individual child objects are
        // disposed of separately
        ASN1_POOL[i]->children.clear();
        ASN1_POOL[i]->tlv = NULL;
        delete ASN1_POOL[i];
    }
    for (int i = 0; i < tlv_count; i++) delete TLV_POOL[i];

    TLV_POOL.clear();
    ASN1_POOL.clear();
}

void asn1::ASN1Pool::set_pool_size(int _tlv_count, int _asn1_node_count) {
    tlv_count = _tlv_count;
    free_tlv_count = tlv_count;

    asn1_node_count = _asn1_node_count;
    free_asn1_node_count = asn1_node_count;
}

void asn1::ASN1Pool::init_pool() {
    TLVNode* tlv = NULL;
    ASN1Node* asn1_node = NULL;
    // tlv
    for (int i = 0; i < tlv_count; i++) {
        tlv = new TLVNode();
        TLV_POOL.push_back(tlv);
    }
    next_free_tlv = TLV_POOL[free_tlv_count - 1];

    // asn1 node
    for (int i = 0; i < asn1_node_count; i++) {
        asn1_node = new ASN1Node();
        ASN1_POOL.push_back(asn1_node);
    }
    next_free_asn1_node = ASN1_POOL[free_asn1_node_count - 1];
}

int asn1::ASN1Pool::get_free_asn1_node_count() { return free_asn1_node_count; }

int asn1::ASN1Pool::get_free_tlv_count() { return free_tlv_count; }

int asn1::ASN1Pool::get_tlv_count() { return tlv_count; }

asn1::ASN1Node* asn1::ASN1Pool::request_asn1_node() {
    ASN1Node* tmp = next_free_asn1_node;
    --free_asn1_node_count;
    if (free_asn1_node_count <= 0) free_asn1_node_count = asn1_node_count;
    next_free_asn1_node = ASN1_POOL[free_asn1_node_count - 1];
    return tmp;
}

asn1::TLVNode* asn1::ASN1Pool::request_tlv() {
    TLVNode* tmp = next_free_tlv;
    --free_tlv_count;
    if (free_tlv_count <= 0) free_tlv_count = tlv_count;
    next_free_tlv = TLV_POOL[free_tlv_count - 1];
    return tmp;
}

// ASN1Node
asn1::ASN1Node::ASN1Node() {
    tlv = NULL;
    node_type_name = NULL;
    linked_node = NULL;
    parent_node = NULL;
    session_id = 0;
    choice_selection = NULL;
    // marked = false;
    children.reserve(100);
}

asn1::ASN1Node::~ASN1Node() {
    // children
    for (unsigned int i = 0; i < children.size(); i++)
        if (children[i] != NULL) delete children[i];
    children.clear();
    // tlv
    if (tlv != NULL) delete tlv;
}

bool asn1::ASN1Node::has_linked_data(uint64_t _session_id) {
    return (linked_node != NULL && session_id == _session_id);
}

void asn1::ASN1Node::set_linked_data(uint64_t _session_id) {
    linked_node = this;
    session_id = _session_id;

    // update length and session_id in parent nodes
    linked_node->update_parents(_session_id);
}

asn1::ASN1Node* asn1::ASN1Node::create_node(unsigned int _index) {
    return NULL;
}
asn1::ASN1Node* asn1::ASN1Node::get_next_node(unsigned int _index) {
    return NULL;
}

// set parents and linked nodes
void asn1::ASN1Node::prepare() { asn1::prepare(this, NULL); }

// set session_id for current node and its children
void asn1::ASN1Node::set_session_id(uint64_t _session_id) {
    asn1::set_session_id(this, _session_id);
}

void asn1::ASN1Node::update_parents(uint64_t _session_id) {
    // prepare current length
    prepare_length(tlv);
    int delta_len =
        (tlv->value_length + tlv->value_length_size) - tlv->old_value_length;

    // prepare tag if not set
    if (tlv->tag_value_size < 1) {
        prepare_tag(tlv);
        delta_len += tlv->tag_value_size;
    }

    TLVNode* p_tlv = NULL;
    // check for NULL parent
    if (parent_node != NULL) {
        // set session_id
        parent_node->session_id = _session_id;
        // check for linked_node
        if (parent_node->linked_node != NULL) {
            if (parent_node->linked_node->tlv != NULL) {
                // set parent reference
                p_tlv = parent_node->linked_node->tlv;
                // if parent is not CHOICE
                if (p_tlv->uni_tag_class != CHOICE) {
                    // process delta if needed
                    p_tlv->value_length += delta_len;
                    // std::cout << std::dec <<  "update_parents : " <<
                    // parent_node->linked_node->node_type_name << " = " <<
                    // p_tlv->value_length << ", delta = " << delta_len <<
                    // std::endl;
                    // parent is CHOICE
                } else {
                    p_tlv->value_length = tlv->value_length;
                    p_tlv->value_length_size = tlv->value_length_size;
                    parent_node->choice_selection = this;
                    // std::cout << std::dec <<  "CHOICE update_parents : " <<
                    // parent_node->linked_node->node_type_name << " = " <<
                    // p_tlv->value_length << ", delta = " << delta_len<<
                    // std::endl;
                }

                // set old_value_laneth to current values
                tlv->old_value_length =
                    tlv->value_length + tlv->value_length_size;

                // update parents
                if (parent_node != NULL)
                    parent_node->linked_node->update_parents(_session_id);
            }
        }
    }
}

void asn1::ASN1Node::set_linked_data(uint64_t _session_id,
                                     ASN1Node* _linked_node) {
    if (_linked_node != NULL) {
        linked_node = _linked_node;
        session_id = _session_id;

        // update length and session_id in parent nodes
        linked_node->update_parents(_session_id);
    }
}

/*
   void asn1::ASN1Node::change_linked_data(uint64_t _session_id, unsigned char*
_data, unsigned int _data_length, bool _shallow){ if(linked_node != NULL){
   if(linked_node->tlv != NULL){

   linked_node->tlv->set_value(_data, _data_length, _shallow);
   session_id = _session_id;

// update length and session_id in parent nodes
linked_node->update_parents(_session_id);

}
}

}
 */

// used to unlink optional node from current session
// when unlinking CHOICE selection, do not unlink children, unlink the CHOICE
// node itself and then set the new selection
void asn1::ASN1Node::unlink(uint64_t _session_id) {
    // linked_node = this;
    if (linked_node == NULL) return;
    if (linked_node->tlv != NULL) {
        // do not unlink unused node
        // if tag_value_size is less then 0, node has not been included in
        // calculations, already unlinked
        if (linked_node->tlv->tag_value_size > 0) {
            // remember old value length
            int old_vl = linked_node->tlv->value_length;

            // set value_length, extra -1 to compensate for calculated
            // value_length_size in update_parents for negative value_length,
            // calculated value_length_size is 1
            linked_node->tlv->value_length =
                0 - linked_node->tlv->tag_value_size - 1;
            // set session_id (both ans.1 node and linkednode since they can
            // point to different nodes)
            session_id = _session_id;
            linked_node->session_id = _session_id;

            // update length and session_id in parent nodes
            linked_node->update_parents(_session_id);

            // set current node(both asn.1 node and linked node) as
            // inactive/unlinked session_id of ZERO(0) is not used for normal
            // operation, sessions start from ONE(1)
            session_id = 0;
            linked_node->session_id = 0;

            // set value length to previous value
            // important when unlinking and linking back CONTRUCTED nodes
            linked_node->tlv->value_length = old_vl;

            // ******** CHOICE is special ********
            if (linked_node->tlv->uni_tag_class == CHOICE) {
                for (unsigned int i = 0; i < linked_node->children.size();
                     i++) {
                    linked_node->children[i]->session_id = 0;
                    linked_node->children[i]->tlv->old_value_length = 0;
                }
            }
        }
    }
}

void asn1::ASN1Node::set_linked_data(uint64_t _session_id, unsigned char* _data,
                                     unsigned int _data_length) {
    if (linked_node == NULL) linked_node = this;
    if (linked_node->tlv != NULL) {
        linked_node->tlv->value = _data;
        linked_node->tlv->value_length = _data_length;
        session_id = _session_id;

        // update length and session_id in parent nodes
        linked_node->update_parents(_session_id);
    }
}

// ANY
asn1::Any::Any() {
    node_type_name = new char[500];
    strcpy(node_type_name, "ANY");
    tlv = new TLVNode();
    tlv->uni_tag_class = ANY;
    tlv->tag_value = ANY;
}
asn1::Any::~Any() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// CHOICE
asn1::Choice::Choice() {
    node_type_name = new char[500];
    strcpy(node_type_name, "CHOICE");
    tlv = new TLVNode();
    tlv->uni_tag_class = CHOICE;
    choice_selection = NULL;
}
asn1::Choice::~Choice() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// BOOLEAN
asn1::Boolean::Boolean() {
    node_type_name = new char[500];
    strcpy(node_type_name, "BOOLEAN");
    tlv = new TLVNode();
    tlv->uni_tag_class = BOOLEAN;
}
asn1::Boolean::~Boolean() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// INTEGER
asn1::Integer::Integer() {
    node_type_name = new char[500];
    strcpy(node_type_name, "INTEGER");
    tlv = new TLVNode();
    tlv->uni_tag_class = INTEGER;
}
asn1::Integer::~Integer() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// BIT_STRING
asn1::Bit_string::Bit_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "BIT STRING");
    tlv = new TLVNode();
    tlv->uni_tag_class = BIT_STRING;
}
asn1::Bit_string::~Bit_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// OCTET_STRING
asn1::Octet_string::Octet_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "OCTET STRING");
    tlv = new TLVNode();
    tlv->uni_tag_class = OCTET_STRING;
}
asn1::Octet_string::~Octet_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// PRINTABLE_STRING
asn1::PrintableString::PrintableString() {
    node_type_name = new char[500];
    strcpy(node_type_name, "PRINTABLE STRING");
    tlv = new TLVNode();
    tlv->uni_tag_class = PRINTABLE_STRING;
}
asn1::PrintableString::~PrintableString() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// NULL
asn1::Null::Null() {
    node_type_name = new char[500];
    strcpy(node_type_name, "NULL");
    tlv = new TLVNode();
    tlv->uni_tag_class = _NULL_;
}
asn1::Null::~Null() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// OBJECT_IDENTIFIER
asn1::Object_identifier::Object_identifier() {
    node_type_name = new char[500];
    strcpy(node_type_name, "OBJECT IDENTIFIER");
    tlv = new TLVNode();
    tlv->uni_tag_class = OBJECT_IDENTIFIER;
}
asn1::Object_identifier::~Object_identifier() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// OBJECT_DESCRIPTOR
asn1::Object_descriptor::Object_descriptor() {
    node_type_name = new char[500];
    strcpy(node_type_name, "OBJECT DESCRIPTOR");
    tlv = new TLVNode();
    tlv->uni_tag_class = OBJECT_DESCRIPTOR;
}
asn1::Object_descriptor::~Object_descriptor() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// ========== Eternal and related =============

// EXTERNAL_encoding
asn1::EXTERNAL_encoding::EXTERNAL_encoding() {
    strcpy(node_type_name, "EXTERNAL_encoding");
    // single_ASN1_type
    _single_ASN1_type = new Any();
    ASN1Node* _single_ASN1_type_wrapper = new ASN1Node();
    _single_ASN1_type_wrapper->tlv = new TLVNode();
    _single_ASN1_type_wrapper->tlv->is_explicit = true;
    _single_ASN1_type_wrapper->tlv->tag_class = CONTEXT_SPECIFIC;
    _single_ASN1_type_wrapper->tlv->tag_value = 0;
    _single_ASN1_type_wrapper->children.push_back(_single_ASN1_type);
    children.push_back(_single_ASN1_type_wrapper);

    // octet_aligned
    _octet_aligned = new Octet_string();
    _octet_aligned->tlv->tag_class = CONTEXT_SPECIFIC;
    _octet_aligned->tlv->tag_value = 1;
    children.push_back(_octet_aligned);

    // arbitrary
    _arbitrary = new Bit_string();
    _arbitrary->tlv->tag_class = CONTEXT_SPECIFIC;
    _arbitrary->tlv->tag_value = 2;
    children.push_back(_arbitrary);
}

asn1::EXTERNAL_encoding::~EXTERNAL_encoding() {}

// External
asn1::External::External() {
    // node_type_name = new char[500];
    strcpy(node_type_name, "EXTERNAL");
    tlv->tag_class = UNIVERSAL;
    tlv->tag_value = EXTERNAL;

    // tlv = new TLVNode();
    // tlv->uni_tag_class = EXTERNAL;

    _direct_reference = new Object_identifier();
    children.push_back(_direct_reference);

    _indirect_reference = new Integer();
    children.push_back(_indirect_reference);

    _data_value_descriptor = new Object_descriptor();
    children.push_back(_data_value_descriptor);

    _encoding = new EXTERNAL_encoding();
    children.push_back(_encoding);
}
asn1::External::~External() {}
// ========================================

// REAL
asn1::Real::Real() {
    node_type_name = new char[500];
    strcpy(node_type_name, "REAL");
    tlv = new TLVNode();
    tlv->uni_tag_class = REAL;
}
asn1::Real::~Real() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// ENUMERATED
asn1::Enumerated::Enumerated() {
    node_type_name = new char[500];
    strcpy(node_type_name, "ENUMERATED");
    tlv = new TLVNode();
    tlv->uni_tag_class = ENUMERATED;
}
asn1::Enumerated::~Enumerated() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// EMBEDDED_PDV
asn1::Embedded_pdv::Embedded_pdv() {
    node_type_name = new char[500];
    strcpy(node_type_name, "EMBEDDED PDV");
    tlv = new TLVNode();
    tlv->uni_tag_class = EMBEDDED_PDV;
}
asn1::Embedded_pdv::~Embedded_pdv() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// UTF8_STRING
asn1::Utf8_string::Utf8_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "UTF8String");
    tlv = new TLVNode();
    tlv->uni_tag_class = UTF8STRING;
}

asn1::Utf8_string::~Utf8_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// RELATIVE_OID
asn1::Relative_oid::Relative_oid() {
    node_type_name = new char[500];
    strcpy(node_type_name, "RELATIVE-OID");
    tlv = new TLVNode();
    tlv->uni_tag_class = RELATIVE_OID;
}
asn1::Relative_oid::~Relative_oid() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// SEQUENCE
asn1::Sequence::Sequence() {
    node_type_name = new char[500];
    strcpy(node_type_name, "SEQUENCE");
    tlv = new TLVNode();
    tlv->uni_tag_class = SEQUENCE;
    tlv->complexity = CONSTRUCTED;
}
asn1::Sequence::~Sequence() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// SEQUENCE OF
asn1::Sequence_of::Sequence_of() {
    node_type_name = new char[500];
    strcpy(node_type_name, "SEQUENCE OF");
    tlv = new TLVNode();
    tlv->uni_tag_class = SEQUENCE_OF;
    tlv->complexity = CONSTRUCTED;
    tlv->unlimited_size = true;
    _sequence_of_size = 0;
}
asn1::Sequence_of::~Sequence_of() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// SET
asn1::Set::Set() {
    node_type_name = new char[500];
    strcpy(node_type_name, "SET");
    tlv = new TLVNode();
    tlv->uni_tag_class = SET;
}
asn1::Set::~Set() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// SET OF
asn1::Set_of::Set_of() {
    node_type_name = new char[500];
    strcpy(node_type_name, "SET OF");
    tlv = new TLVNode();
    tlv->uni_tag_class = SET_OF;
    tlv->complexity = CONSTRUCTED;
    tlv->unlimited_size = true;
    _set_of_size = 0;
}
asn1::Set_of::~Set_of() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// NUMERIC_STRING
asn1::Numeric_string::Numeric_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "NumericString");
    tlv = new TLVNode();
    tlv->uni_tag_class = NUMERIC_STRING;
}
asn1::Numeric_string::~Numeric_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// PRINTABLE_STRING
asn1::Printable_string::Printable_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "PrintableString");
    tlv = new TLVNode();
    tlv->uni_tag_class = PRINTABLE_STRING;
}
asn1::Printable_string::~Printable_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// T61_STRING
asn1::T61_string::T61_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "T61String");
    tlv = new TLVNode();
    tlv->uni_tag_class = T61STRING;
}
asn1::T61_string::~T61_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// VIDEOTEX_STRING
asn1::Videotex_string::Videotex_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "VideotexString");
    tlv = new TLVNode();
    tlv->uni_tag_class = VIDEOTEX_STRING;
}
asn1::Videotex_string::~Videotex_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// IA5_STRING
asn1::IA5String::IA5String() {
    node_type_name = new char[500];
    strcpy(node_type_name, "IA5String");
    tlv = new TLVNode();
    tlv->uni_tag_class = IA5_STRING;
}
asn1::IA5String::~IA5String() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// UTC_TIME
asn1::Utc_time::Utc_time() {
    node_type_name = new char[500];
    strcpy(node_type_name, "UTCTime");
    tlv = new TLVNode();
    tlv->uni_tag_class = UTC_TIME;
}
asn1::Utc_time::~Utc_time() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}
// GENERALIZED_TIME
asn1::Generalized_time::Generalized_time() {
    node_type_name = new char[500];
    strcpy(node_type_name, "GeneralizedTime");
    tlv = new TLVNode();
    tlv->uni_tag_class = GENERALIZED_TIME;
}
asn1::Generalized_time::~Generalized_time() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// GRAPHIC_STRING
asn1::Graphic_string::Graphic_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "GraphicString");
    tlv = new TLVNode();
    tlv->uni_tag_class = GRAPHIC_STRING;
}
asn1::Graphic_string::~Graphic_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// VISIBLE_STRING
asn1::Visible_string::Visible_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "VisibleString");
    tlv = new TLVNode();
    tlv->uni_tag_class = VISIBLE_STRING;
}
asn1::Visible_string::~Visible_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// GENERAL_STRING
asn1::General_string::General_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "GeneralString");
    tlv = new TLVNode();
    tlv->uni_tag_class = GENERAL_STRING;
}
asn1::General_string::~General_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// UNIVERSAL_STRING
asn1::Universal_string::Universal_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "UniversalString");
    tlv = new TLVNode();
    tlv->uni_tag_class = UNIVERSAL_STRING;
}
asn1::Universal_string::~Universal_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// CHARACTER_STRING
asn1::Character_string::Character_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "CHARACTER STRING");
    tlv = new TLVNode();
    tlv->uni_tag_class = CHARACTER_STRING;
}
asn1::Character_string::~Character_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// BMP_STRING
asn1::Bmp_string::Bmp_string() {
    node_type_name = new char[500];
    strcpy(node_type_name, "BMPString");
    tlv = new TLVNode();
    tlv->uni_tag_class = BMP_STRING;
}
asn1::Bmp_string::~Bmp_string() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// GeneralizedTime
asn1::GeneralizedTime::GeneralizedTime() {
    node_type_name = new char[500];
    strcpy(node_type_name, "GeneralizedTime");
    tlv = new TLVNode();
    tlv->uni_tag_class = GENERALIZED_TIME;
    tlv->tag_value = 24;
}
asn1::GeneralizedTime::~GeneralizedTime() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// UTCTime
asn1::UTCTime::UTCTime() {
    node_type_name = new char[500];
    strcpy(node_type_name, "UTCTime");
    tlv = new TLVNode();
    tlv->uni_tag_class = UTC_TIME;
    tlv->tag_value = 23;
}
asn1::UTCTime::~UTCTime() {
    delete[] node_type_name;
    delete tlv;
    tlv = NULL;
}

// TLVNode
asn1::TLVNode::TLVNode() {
    complexity = COMPLEXITY_UNKNOWN;
    tag_class = CLASS_UNKNOWN;
    length_type = LENGTH_TYPE_UNKNOWN;
    uni_tag_class = UNKNOWN_UNIVERSAL_TAG;
    tag_value_size = 0;
    tag_value = -1;
    value = NULL;
    value_length = 0;
    value_length_size = 0;
    old_value_length = 0;
    is_explicit = false;
    override_auto_complexity = false;
    unlimited_size = false;
    full_tlv = NULL;
    full_tlv_length = 0;
}

asn1::TLVNode::~TLVNode() {}

void asn1::TLVNode::set_value(unsigned char* _data, unsigned int _length,
                              bool _shallow) {
    // set old
    old_value_length = value_length + value_length_size;
    // new
    if (_shallow) {
        value = _data;
        value_length = _length;

    } else {
        if (value != NULL && value_length >= _length) {
            memcpy(value, _data, _length);
            value_length = _length;
        }
    }
}

int asn1::find_eoc(unsigned char* data, unsigned int data_length) {
    if (data != NULL && data_length > 0) {
        unsigned int tmp_pos = 0;
        TLVNode tlv;
        while (tmp_pos < data_length) {
            decode_tag(&data[tmp_pos], data_length, &tlv);
            tmp_pos += tlv.tag_value_size;
            decode_length(&data[tmp_pos], data_length, &tlv);
            tmp_pos += tlv.value_length_size;
            // primitive type, just skip the value part
            if (tlv.complexity == PRIMITIVE) {
                tmp_pos += tlv.value_length;
                // constructed type, if INDEFINITE look for EOC mark, else just
                // skip the value part
            } else if (tlv.complexity == CONSTRUCTED) {
                // if NDEF, look for EOC, also add those extra 2 bytes 0x00
                // 0x00(EOC)
                if (tlv.length_type == INDEFINITE)
                    tmp_pos +=
                        (find_eoc(&data[tmp_pos], data_length - tmp_pos) + 2);
                else
                    tmp_pos += tlv.value_length;
            }
            // check for EOC = two 0x00 bytes
            if (tmp_pos < data_length - 1)
                if (data[tmp_pos] == 0x00 && data[tmp_pos + 1] == 0x00)
                    return tmp_pos;
        }
    }
    return 0;
}

int asn1::decode_length(unsigned char* data, unsigned int data_length,
                        TLVNode* tlv) {
    if (data != NULL && data_length > 0 && tlv != NULL) {
        if ((*data & 0xFF) > 0x80) {
            tlv->length_type = DEFINITE_LONG;
            // number of octets for the length value
            int l = *data & 0x7F;
            // sanity check
            if (l == 0x7f) return 2;
            if (l >= data_length) return 2;
            tlv->value_length_size = l + 1;
            tlv->value_length = 0;
            ++data;
            // process octets
            for (int i = 0; i < l; i++)
                tlv->value_length += ((data[i] & 0xFF) << (8 * (l - i - 1)));
            //--data;
            // std::cout << "DEFINITE LONG: " << std::dec << tlv->tag_value <<
            // ":" <<  tlv->value_length_size << ":" << tlv->value_length <<
            // std::endl;

            // indefinite form
        } else if ((*data & 0xFF) == 0x80) {
            tlv->length_type = INDEFINITE;
            tlv->value_length_size = 1;
            // find EOC and calculate length
            tlv->value_length =
                find_eoc(&data[tlv->value_length_size], data_length - 1);
            // std::cout << "INDEFINITE: " << std::dec << tlv->tag_value << ":"
            // <<  tlv->value_length << std::endl;

            // definite form, single octet
        } else {
            tlv->length_type = DEFINITE_SHORT;
            tlv->value_length_size = 1;
            tlv->value_length = *data;
            // std::cout << "DEFINITE SHORT: " << std::dec << tlv->tag_value <<
            // ":" <<  tlv->value_length << std::endl;
        }

        // ok
        return 0;
    }
    // err
    return 1;
}

void asn1::decode_tag(unsigned char* data, unsigned int data_length,
                      TLVNode* tlv) {
    if (data != NULL && data_length > 0 && tlv != NULL) {
        // get class
        tlv->tag_class = (TagClass)(*data & 0xc0);
        // get complexity
        tlv->complexity = (Complexity)(*data & 0x20);
        // get tag
        // multiple bytes tag
        if ((*data & 0x1f) == 0x1f) {
            // std::cout << "multiple bytes tag" << std::endl;
            tlv->tag_value = 0;
            tlv->tag_value_size = 1;
            ++data;

            // tlv->tag_length = number of octets for tag value
            while ((*data & 0x80) == 0x80) {
                tlv->tag_value_size++;
                ++data;
            }
            // move back
            data -= (tlv->tag_value_size - 1);
            // calculate tag
            for (int i = 0; i < tlv->tag_value_size; i++)
                tlv->tag_value |=
                    ((data[i] & 0x7f) << (7 * (tlv->tag_value_size - i - 1)));
            // first byte is 0x1f, also included in total tag size
            tlv->tag_value_size++;
            // single byte tag
        } else {
            tlv->tag_value = *data & 0x1f;
            tlv->tag_value_size = 1;
        }
    }
}

// main decode method WITH asn1 definition (public)
int asn1::decode(unsigned char* data, unsigned int data_length,
                 asn1::ASN1Node* root_node, asn1::ASN1Node* root_defintion_node,
                 asn1::ASN1Pool* _asn1_pool, uint64_t* _session_id) {
    // used node count
    unsigned int used_nc = 0;
    // non CHOICE root node, make root_defintion_node a child of temporary
    // parent node, process children of temporary parent node
    if (root_defintion_node->tlv->uni_tag_class != asn1::CHOICE) {
        asn1::ASN1Node root_asn1_node;
        asn1::TLVNode tlv;
        root_asn1_node.tlv = &tlv;
        root_asn1_node.children.push_back(root_defintion_node);
        int res = asn1::_decode(data, data_length, root_node, &root_asn1_node,
                                _asn1_pool, _session_id, &used_nc);
        root_asn1_node.children.clear();
        root_asn1_node.tlv = NULL;
        return res;

        // CHOICE root node, process children of root_defintion_node
    } else {
        return asn1::_decode(data, data_length, root_node, root_defintion_node,
                             _asn1_pool, _session_id, &used_nc);
    }

    return 0;
}

// main decode method WITH asn1 definition (private)
int asn1::_decode(unsigned char* data, unsigned int data_length,
                  ASN1Node* root_node, ASN1Node* root_defintion_node,
                  ASN1Pool* _asn1_pool, uint64_t* _session_id,
                  unsigned int* used_nc) {
    // sanity checks
    if (data == NULL) return 100;
    if (root_node == NULL) return 101;
    // **** ALLOW ZERO LENGH NODES ****
    // if(data_length == 0) return 102;

    unsigned int tmp_pos = 0;
    TLVNode* tlv = NULL;
    ASN1Node* new_node = NULL;
    unsigned int next_src_index = 0;
    ASN1Node* tmp_node_src = NULL;
    ASN1Node* tmp_node_matched = NULL;
    int tmp_tag_value = UNKNOWN_UNIVERSAL_TAG;
    TagClass tmp_tag_class = CLASS_UNKNOWN;
    int res = 0;
    bool unlimited = false;

    while (tmp_pos < data_length) {
        // get tlv
        tlv = _asn1_pool->request_tlv();
        tlv->value_length = 0;

        // inc node counter, check for buffer full error
        ++(*used_nc);
        if (*used_nc > _asn1_pool->get_tlv_count()) return 400;

        // get start of tlv node
        tlv->full_tlv = &data[tmp_pos];

        // get tag
        decode_tag(&data[tmp_pos], data_length, tlv);

        // skip tag part
        tmp_pos += tlv->tag_value_size;

        // get length
        if (decode_length(&data[tmp_pos], data_length - tmp_pos, tlv) != 0)
            return 300;

        // set old value (important for re-encoding)
        tlv->old_value_length = tlv->value_length_size + tlv->value_length;

        // get full tlv node length
        tlv->full_tlv_length = tlv->old_value_length + tlv->tag_value_size +
                               (tlv->length_type == INDEFINITE ? 2 : 0);

        // skip length part
        tmp_pos += tlv->value_length_size;

        // sanity check
        if (tlv->value_length > (data_length - tmp_pos)) return 200;

        // get value
        tlv->value = &data[tmp_pos];

        // add to current node
        new_node = _asn1_pool->request_asn1_node();
        new_node->children.clear();
        new_node->node_type_name = NULL;
        new_node->tlv = tlv;
        // set linked node to current node
        new_node->linked_node = new_node;
        // set current session id
        new_node->session_id = *_session_id;
        // set parrent node
        new_node->parent_node = root_node;
        // push to list
        root_node->children.push_back(new_node);

        // search asn1 definition
        if (root_defintion_node != NULL) {
            // get unlimited flag (SET OF and SEQUENCE OF)
            unlimited = root_defintion_node->tlv->unlimited_size;
            // unlimited size structure; SEQUENCE OF and SET OF
            if (unlimited) root_defintion_node->get_next_node(next_src_index);

            // check definition node for match
            for (unsigned int j = next_src_index;
                 j < root_defintion_node->children.size(); j++) {
                // create if necessary
                if (root_defintion_node->children[j] == NULL)
                    root_defintion_node->create_node(j);
                tmp_node_src = root_defintion_node->children[j];
                // if NULL, skip
                if (tmp_node_src == NULL) continue;

                // special tag cases
                switch (tmp_node_src->tlv->tag_value) {
                    // UNI tag
                    case UNKNOWN_UNIVERSAL_TAG:
                        tmp_tag_value = tmp_node_src->tlv->uni_tag_class;
                        tmp_tag_class = UNIVERSAL;
                        break;
                        // ANY
                    case ANY:
                        tmp_tag_value = new_node->tlv->tag_value;
                        tmp_tag_class = new_node->tlv->tag_class;
                        break;
                        // other
                    default:
                        tmp_tag_value = tmp_node_src->tlv->tag_value;
                        tmp_tag_class = tmp_node_src->tlv->tag_class;
                        break;
                }

                // CHOICE
                if (tmp_tag_value == CHOICE) {
                    // find CHOICE selection
                    tmp_node_matched = resolve_CHOICE(new_node, tmp_node_src);
                    // set CHOICE selection
                    if (tmp_node_matched != NULL) {
                        // set choice node values
                        tmp_node_src->choice_selection = tmp_node_matched;
                        tmp_node_src->session_id = *_session_id;
                        tmp_node_src->linked_node = tmp_node_src;
                        // set relevant tlv values
                        tmp_node_src->tlv->tag_value_size = tlv->tag_value_size;
                        tmp_node_src->tlv->length_type = tlv->length_type;
                        tmp_node_src->tlv->old_value_length =
                            tlv->old_value_length;
                        tmp_node_src->tlv->value_length = tlv->value_length;
                        tmp_node_src->tlv->value_length_size =
                            tlv->value_length_size;
                        // change ber node linked node
                        new_node->linked_node = tmp_node_src;
                    }

                    // other
                } else {
                    if (new_node->tlv->tag_class == tmp_tag_class &&
                        new_node->tlv->tag_value == tmp_tag_value)
                        tmp_node_matched = tmp_node_src;
                    else
                        tmp_node_matched = NULL;
                }

                // check if matched
                if (tmp_node_matched != NULL) {
                    // - SET is not ordered, start from first element every time
                    // (not in case of SET OF when unlimited_size is set)
                    // - all other elements are ordered
                    if (root_defintion_node->tlv->uni_tag_class == SET &&
                        !unlimited)
                        next_src_index = 0;
                    else
                        next_src_index = j + 1;
                    // update dest node name
                    new_node->node_type_name = tmp_node_matched->node_type_name;
                    // set CHOICE selection and session id for CHOICE node
                    if (root_defintion_node->tlv->uni_tag_class == CHOICE) {
                        // set choice node values
                        root_defintion_node->choice_selection =
                            tmp_node_matched;
                        root_defintion_node->session_id = *_session_id;
                        root_defintion_node->linked_node = root_defintion_node;
                        // set relevant tlv values
                        root_defintion_node->tlv->tag_value_size =
                            tlv->tag_value_size;
                        root_defintion_node->tlv->length_type =
                            tlv->length_type;
                        root_defintion_node->tlv->old_value_length =
                            tlv->old_value_length;
                        root_defintion_node->tlv->value_length =
                            tlv->value_length;
                        root_defintion_node->tlv->value_length_size =
                            tlv->value_length_size;
                        // change ber node linked node
                        new_node->linked_node = root_defintion_node;
                    }
                    // link with current plain BER node
                    tmp_node_matched->linked_node = new_node;
                    // update session id
                    tmp_node_matched->session_id = *_session_id;
                    break;
                }
            }
        }

        // if constructed, process more
        if (tlv->complexity == CONSTRUCTED)
            res = _decode(tlv->value, tlv->value_length, new_node,
                          tmp_node_matched, _asn1_pool, _session_id, used_nc);
        // error check
        if (res != 0) return res;

        // next TLV on this level
        tmp_pos +=
            (tlv->value_length + (tlv->length_type == INDEFINITE ? 2 : 0));
    }

    return 0;
}

// main decode method WITHOUT asn1 definition (public)
int asn1::decode(unsigned char* data, unsigned int data_length,
                 ASN1Node* root_node, ASN1Pool* _asn1_pool) {
    unsigned int used_nc = 0;
    return _decode(data, data_length, root_node, _asn1_pool, &used_nc);
}

// main decode method WITHOUT asn1 definition (private)
int asn1::_decode(unsigned char* data, unsigned int data_length,
                  ASN1Node* root_node, ASN1Pool* _asn1_pool,
                  unsigned int* used_nc) {
    // sanity checks
    if (data == NULL) return 100;
    if (root_node == NULL) return 101;
    // **** ALLOW ZERO LENGH NODES ****
    // if(data_length == 0) return 102;

    unsigned int tmp_pos = 0;
    TLVNode* tlv = NULL;
    ASN1Node* new_node = NULL;
    int res = 0;
    while (tmp_pos < data_length) {
        tlv = _asn1_pool->request_tlv();
        tlv->value_length = 0;

        // inc node counter, check for buffer full error
        ++(*used_nc);
        if (*used_nc > _asn1_pool->get_tlv_count()) return 400;

        // get start of tlv node
        tlv->full_tlv = &data[tmp_pos];

        // get tag
        decode_tag(&data[tmp_pos], data_length, tlv);

        // skip tag part
        tmp_pos += tlv->tag_value_size;

        // get length
        if (decode_length(&data[tmp_pos], data_length - tmp_pos, tlv) != 0)
            return 300;

        // get full tlv node length
        tlv->full_tlv_length = tlv->value_length_size + tlv->value_length +
                               tlv->tag_value_size +
                               (tlv->length_type == INDEFINITE ? 2 : 0);

        // skip length part
        tmp_pos += tlv->value_length_size;

        // sanity check
        if (tlv->value_length > (data_length - tmp_pos)) return 200;

        // get value
        tlv->value = &data[tmp_pos];
        // add to current node
        new_node = _asn1_pool->request_asn1_node();
        new_node->children.clear();
        new_node->node_type_name = NULL;
        new_node->tlv = tlv;
        root_node->children.push_back(new_node);

        // if constructed, process more
        if (tlv->complexity == CONSTRUCTED)
            res = decode(tlv->value, tlv->value_length, new_node, _asn1_pool);
        // error check
        if (res != 0) return res;

        // next TLV on this level
        tmp_pos +=
            (tlv->value_length + (tlv->length_type == INDEFINITE ? 2 : 0));
    }

    return 0;
}

// encode methods
/*
// get class
tlv->tag_class = (TagClass)(*data & 0xc0);
// get complexity
tlv->complexity = (Complexity)(*data & 0x20);
// get tag
// multiple bytes tag
if((*data & 0x1f) == 0x1f){
//std::cout << "multiple bytes tag" << std::endl;
tlv->tag_value = 0;
tlv->tag_value_size = 1;
++data;

// tlv->tag_value_size = number of octets for tag value
while((*data & 0x80) == 0x80){
tlv->tag_value_size++;
++data;
}
// move back
data -= (tlv->tag_value_size - 1);
// calculate tag
for(int i = 0; i<tlv->tag_value_size; i++) tlv->tag_value |= ((data[i] & 0x7f)
<< (7 * (tlv->tag_value_size - i - 1)));
// first byte is 0x1f, also included in total tag size
tlv->tag_value_size++;
// single byte tag
}else{
tlv->tag_value = *data & 0x1f;
tlv->tag_value_size = 1;

} */

void asn1::prepare_tag(TLVNode* tlv) {
    if (tlv != NULL) {
        // multi byte tag
        if (tlv->tag_value > 30) {
            unsigned int req_bits = ceil(log2(tlv->tag_value + 1));
            unsigned int req_septet_bytes = ceil((double)req_bits / 7);
            tlv->tag_value_size = req_septet_bytes + 1;
            // single byte tag
        } else {
            tlv->tag_value_size = 1;
        }
    }
}

void asn1::encode_tag(unsigned char* data, unsigned int data_length,
                      TLVNode* tlv) {
    if (data != NULL && data_length > 0 && tlv != NULL) {
        // multi byte tag
        if (tlv->tag_value > 30) {
            unsigned int req_bits = ceil(log2(tlv->tag_value + 1));
            unsigned int req_septet_bytes = ceil((double)req_bits / 7);
            unsigned int i = 0;
            // set multi byte tag
            *(data++) = 0x1f | tlv->tag_class | tlv->complexity;
            // set tag bytes
            while (i < req_septet_bytes) {
                // more bytes
                data[i] = 0x80;
                // actual tag
                data[i] |= tlv->tag_value >> (8 * (req_septet_bytes - i - 1));
                // inc
                i++;
            }
            // no more bytes flag
            data[i - 1] &= 0x7f;
            tlv->tag_value_size = req_septet_bytes + 1;
            // single byte tag
        } else {
            *data = tlv->tag_value | tlv->tag_class | tlv->complexity;
            tlv->tag_value_size = 1;
        }
    }
}

void asn1::encode_prepared_tag(unsigned char* data, unsigned int data_length,
                               TLVNode* tlv) {
    if (data != NULL && data_length > 0 && tlv != NULL) {
        // multi byte tag
        if (tlv->tag_value_size > 1) {
            unsigned int req_septet_bytes = tlv->tag_value_size - 1;
            unsigned int i = 0;
            // set multi byte tag
            *(data++) = 0x1f | tlv->tag_class | tlv->complexity;
            // set tag bytes
            while (i < req_septet_bytes) {
                // more bytes
                data[i] = 0x80;
                // actual tag
                data[i] |= tlv->tag_value >> (8 * (req_septet_bytes - i - 1));
                // inc
                i++;
            }
            // no more bytes flag
            data[i - 1] &= 0x7f;
            // single byte tag
        } else {
            *data = tlv->tag_value | tlv->tag_class | tlv->complexity;
        }
    }
}

void asn1::prepare_length(TLVNode* tlv) {
    if (tlv != NULL) {
        // definite long
        if (tlv->value_length > 127) {
            unsigned int req_bits = ceil(log2(tlv->value_length + 1));
            unsigned int req_bytes = ceil((double)req_bits / 8);
            tlv->value_length_size = req_bytes + 1;
            tlv->length_type = DEFINITE_LONG;

            // definite short
        } else {
            tlv->value_length_size = 1;
            tlv->length_type = DEFINITE_SHORT;
            ;
        }
        // ** NOT USING INDEFINITE FORM **
    }
}

void asn1::encode_prepared_length(unsigned char* data, unsigned int data_length,
                                  TLVNode* tlv) {
    if (data != NULL && data_length > 0 && tlv != NULL) {
        // definite long
        if (tlv->value_length > 127) {
            unsigned int req_bytes = tlv->value_length_size - 1;
            // set number of bytes for length
            *(data++) = 0x80 | req_bytes;
            // set length bytes
            for (unsigned int i = 0; i < req_bytes; i++)
                data[i] = tlv->value_length >> (8 * (req_bytes - i - 1));

            // definite short
        } else {
            *data = tlv->value_length;
        }
        // ** NOT USING INDEFINITE FORM **
    }
}

void asn1::encode_length(unsigned char* data, unsigned int data_length,
                         TLVNode* tlv) {
    if (data != NULL && data_length > 0 && tlv != NULL) {
        // definite long
        if (tlv->value_length > 127) {
            unsigned int req_bits = ceil(log2(tlv->value_length + 1));
            unsigned int req_bytes = ceil((double)req_bits / 8);
            // set number of bytes for length
            *(data++) = 0x80 | req_bytes;
            // set length bytes
            for (unsigned int i = 0; i < req_bytes; i++)
                data[i] = tlv->value_length >> (8 * (req_bytes - i - 1));
            tlv->value_length_size = req_bytes + 1;

            // definite short
        } else {
            *data = tlv->value_length;
            tlv->value_length_size = 1;
        }
        // ** NOT USING INDEFINITE FORM **
    }
}

void asn1::set_session_id(ASN1Node* root_node, uint64_t _session_id) {
    if (root_node != NULL) {
        // set session
        root_node->session_id = _session_id;
        // children
        for (unsigned int i = 0; i < root_node->children.size(); i++) {
            set_session_id(root_node->children[i], _session_id);
        }
    }
}

void asn1::mem_transfer_deep(ASN1Node* root_node, unsigned char* dest_buffer,
                             int dest_buffer_pos) {
    if (root_node != NULL) {
        if (root_node->linked_node != NULL) {
            if (root_node->linked_node->tlv != NULL) {
                TLVNode* tmp_tlv = root_node->linked_node->tlv;

                if (tmp_tlv->value_length > 0 && tmp_tlv->value != NULL) {
                    memcpy(&dest_buffer[dest_buffer_pos], tmp_tlv->value,
                           tmp_tlv->value_length);
                    tmp_tlv->value = &dest_buffer[dest_buffer_pos];
                    dest_buffer_pos += tmp_tlv->value_length;
                }

                for (unsigned int i = 0;
                     i < root_node->linked_node->children.size(); i++) {
                    mem_transfer_deep(root_node->linked_node->children[i],
                                      dest_buffer, dest_buffer_pos);
                }
            }
        }
    }
}

void asn1::reset(ASN1Node* root_node) {
    if (root_node != NULL) {
        if (root_node->linked_node != NULL) {
            if (root_node->linked_node->tlv != NULL) {
                TLVNode* tmp_tlv = root_node->linked_node->tlv;
                tmp_tlv->tag_value_size = 0;
                tmp_tlv->value_length = 0;
                tmp_tlv->value = NULL;
                tmp_tlv->value_length_size = 0;
                tmp_tlv->old_value_length = 0;

                for (unsigned int i = 0;
                     i < root_node->linked_node->children.size(); i++) {
                    reset(root_node->linked_node->children[i]);
                }
            }
        }
    }
}

void asn1::prepare(ASN1Node* root_node, ASN1Node* parent) {
    if (root_node != NULL) {
        // set parent
        root_node->parent_node = parent;
        // set linked node ref to itself
        root_node->linked_node = root_node;
        // pepare tag
        // prepare_tag(root_node->tlv);
        for (unsigned int i = 0; i < root_node->children.size(); i++) {
            prepare(root_node->children[i], root_node);
        }
    }
}

uint64_t asn1::generate_session_id() {
    timespec ts;
    clock_gettime(0, &ts);
    return (ts.tv_sec + ts.tv_nsec);
}

void asn1::print_structure(ASN1Node* root_node, int depth) {
    if (root_node != NULL) {
        for (int i = 0; i < depth; i++) std::cout << "  ";

        if (root_node->tlv != NULL) {
            switch (root_node->tlv->tag_class) {
                case asn1::APPLICATION:
                    std::cout << "[APP(";
                    break;
                case asn1::UNIVERSAL:
                    std::cout << "[UNI(";
                    break;
                case asn1::CONTEXT_SPECIFIC:
                    std::cout << "[CTX(";
                    break;
                case asn1::PRIVATE:
                    std::cout << "[PVT(";
                    break;
                default:
                    break;
            }
            std::cout << (root_node->tlv->complexity == asn1::CONSTRUCTED
                              ? "C)"
                              : "P)");
            if (root_node->tlv->tag_value_size == 1) {
                std::cout << std::dec << " T(SHORT ";
            } else if (root_node->tlv->tag_value_size > 1) {
                std::cout << std::dec << " T(LONG["
                          << root_node->tlv->tag_value_size << "] ";

            } else
                std::cout << std::dec << " T(? ";

            std::cout << root_node->tlv->tag_value << ") L(";
            switch (root_node->tlv->length_type) {
                case asn1::INDEFINITE:
                    std::cout << "NDEF ";
                    break;
                case asn1::DEFINITE_SHORT:
                    std::cout << "SHORT ";
                    break;
                case asn1::DEFINITE_LONG:
                    std::cout << "LONG[" << root_node->tlv->value_length_size
                              << "] ";
                    break;
                default:
                    std::cout << "? ";
                    break;
                    break;
            }
            std::cout << root_node->tlv->value_length << ")]";

            if (root_node->node_type_name != NULL)
                std::cout << " " << root_node->node_type_name;

            if (root_node->tlv->complexity == asn1::PRIMITIVE) {
                if (root_node->tlv->value_length <= 16) {
                    std::cout << " -> ";
                    for (int k = 0; k < root_node->tlv->value_length; k++) {
                        std::cout
                            << std::setfill('0') << std::setw(2) << std::hex
                            << (int)(root_node->tlv->value[k] & 0xff) << " ";
                    }
                    // cout << "}";
                    std::cout << std::endl;

                } else {
                    std::cout << " -> ";
                    std::cout << std::endl;
                    for (int i = 0; i < depth + 1; i++) std::cout << "  ";
                    int lc = 0;
                    for (int k = 0; k < root_node->tlv->value_length; k++) {
                        std::cout
                            << std::setfill('0') << std::setw(2) << std::hex
                            << (int)(root_node->tlv->value[k] & 0xff) << " ";
                        lc++;
                        if (lc >= 16) {
                            std::cout << std::endl;
                            lc = 0;
                            for (int i = 0; i < depth + 1; i++)
                                std::cout << "  ";
                        }
                    }
                    // cout << "}";
                    std::cout << std::endl;
                }

            } else
                std::cout << " {" << std::endl;

        } else {
            std::cout << "[ROOT/NO TLV] {" << std::endl;
        }

        for (unsigned int i = 0; i < root_node->children.size(); i++) {
            print_structure(root_node->children[i], depth + 1);
        }

        if (root_node->tlv == NULL) {
            for (int i = 0; i < depth; i++) std::cout << "  ";
            std::cout << "}" << std::endl;

        } else if (root_node->tlv->complexity == asn1::CONSTRUCTED) {
            for (int i = 0; i < depth; i++) std::cout << "  ";
            std::cout << "}" << std::endl;
        }
    }
    std::cout << std::dec;
}

int asn1::encode(unsigned char* buffer, int buffer_length, ASN1Node* root_node,
                 uint64_t _session_id, bool mem_switch) {
    if (buffer != NULL && buffer_length > 0 && root_node != NULL) {
        if (root_node->linked_node != NULL &&
            root_node->session_id == _session_id) {
            ASN1Node* linked_node = root_node->linked_node;
            if (linked_node->tlv != NULL) {
                unsigned int total_length = 0;

                // all except CHOICE
                if (linked_node->tlv->uni_tag_class != CHOICE) {
                    // check complexity and universal tagging and encode tag
                    if (linked_node->tlv->tag_value == UNKNOWN_UNIVERSAL_TAG) {
                        linked_node->tlv->tag_value =
                            linked_node->tlv->uni_tag_class;
                        linked_node->tlv->tag_class = UNIVERSAL;
                    }

                    if (linked_node->tlv->complexity == COMPLEXITY_UNKNOWN)
                        linked_node->tlv->complexity =
                            (linked_node->children.size() == 0 ? PRIMITIVE
                                                               : CONSTRUCTED);
                    encode_prepared_tag(buffer, buffer_length,
                                        linked_node->tlv);
                    buffer += linked_node->tlv->tag_value_size;
                    total_length += linked_node->tlv->tag_value_size;

                    // encode length
                    encode_prepared_length(buffer, buffer_length - total_length,
                                           linked_node->tlv);
                    buffer += linked_node->tlv->value_length_size;
                    total_length += linked_node->tlv->value_length_size;

                    // primitive
                    if (linked_node->tlv->complexity == PRIMITIVE ||
                        linked_node->tlv->override_auto_complexity) {
                        memcpy(buffer, linked_node->tlv->value,
                               linked_node->tlv->value_length);
                        // switch pointers if mem_switch is ON
                        if (mem_switch) linked_node->tlv->value = buffer;
                        // inc buffer
                        buffer += linked_node->tlv->value_length;
                        total_length += linked_node->tlv->value_length;

                        // constructed
                    } else if (linked_node->tlv->complexity == CONSTRUCTED) {
                        // children
                        unsigned int tmp_length = 0;
                        for (unsigned int i = 0;
                             i < linked_node->children.size(); i++) {
                            tmp_length =
                                encode(buffer, buffer_length - total_length,
                                       linked_node->children[i], _session_id,
                                       mem_switch);
                            buffer += tmp_length;
                            total_length += tmp_length;
                        }
                    }

                    // CHOICE
                } else {
                    unsigned int tmp_length = 0;
                    if (linked_node->choice_selection != NULL) {
                        tmp_length =
                            encode(buffer, buffer_length - total_length,
                                   linked_node->choice_selection, _session_id,
                                   mem_switch);
                        total_length += tmp_length;
                        buffer += tmp_length;
                    }
                    /*
                    // children
                    for(unsigned int i = 0; i<linked_node->children.size(); i++)
                    { tmp_length = encode(buffer, buffer_length - total_length,
                    linked_node->children[i], _session_id, mem_switch);
                    // CHOICE has only one active child
                    if(tmp_length > 0){
                    total_length += tmp_length;
                    buffer += tmp_length;
                    break;
                    }
                    }
                     */
                }

                // return total bytes encoded
                return total_length;
            }

        }  // else std::cout << "!!!!!!ERR!!!!!!!!!: " <<
           // root_node->node_type_name << " - " << root_node->linked_node <<
           // std::endl;
    }
    return 0;
}

int asn1::encode(unsigned char* buffer, int buffer_length, ASN1Node* root_node,
                 uint64_t _session_id) {
    if (buffer != NULL && buffer_length > 0 && root_node != NULL) {
        if (root_node->linked_node != NULL &&
            root_node->session_id == _session_id) {
            ASN1Node* linked_node = root_node->linked_node;
            if (linked_node->tlv != NULL) {
                unsigned int total_length = 0;

                // all except CHOICE
                if (linked_node->tlv->uni_tag_class != CHOICE) {
                    // check complexity and universal tagging and encode tag
                    if (linked_node->tlv->tag_value == UNKNOWN_UNIVERSAL_TAG) {
                        linked_node->tlv->tag_value =
                            linked_node->tlv->uni_tag_class;
                        linked_node->tlv->tag_class = UNIVERSAL;
                    }

                    if (linked_node->tlv->complexity == COMPLEXITY_UNKNOWN)
                        linked_node->tlv->complexity =
                            (linked_node->children.size() == 0 ? PRIMITIVE
                                                               : CONSTRUCTED);
                    encode_prepared_tag(buffer, buffer_length,
                                        linked_node->tlv);
                    buffer += linked_node->tlv->tag_value_size;
                    total_length += linked_node->tlv->tag_value_size;

                    // encode length
                    encode_prepared_length(buffer, buffer_length - total_length,
                                           linked_node->tlv);
                    buffer += linked_node->tlv->value_length_size;
                    total_length += linked_node->tlv->value_length_size;

                    // primitive
                    if (linked_node->tlv->complexity == PRIMITIVE ||
                        linked_node->tlv->override_auto_complexity) {
                        memcpy(buffer, linked_node->tlv->value,
                               linked_node->tlv->value_length);
                        buffer += linked_node->tlv->value_length;
                        total_length += linked_node->tlv->value_length;

                        // constructed
                    } else if (linked_node->tlv->complexity == CONSTRUCTED) {
                        // children
                        unsigned int tmp_length = 0;
                        for (unsigned int i = 0;
                             i < linked_node->children.size(); i++) {
                            tmp_length =
                                encode(buffer, buffer_length - total_length,
                                       linked_node->children[i], _session_id);
                            buffer += tmp_length;
                            total_length += tmp_length;
                        }
                    }

                    // CHOICE
                } else {
                    unsigned int tmp_length = 0;
                    // children
                    if (linked_node->choice_selection != NULL) {
                        tmp_length =
                            encode(buffer, buffer_length - total_length,
                                   linked_node->choice_selection, _session_id);
                        total_length += tmp_length;
                        buffer += tmp_length;
                    }
                    /*
                       for(unsigned int i = 0; i<linked_node->children.size();
                    i++) { tmp_length = encode(buffer, buffer_length -
                    total_length, linked_node->children[i], _session_id);
                    // CHOICE has only one active child
                    if(tmp_length > 0){
                    total_length += tmp_length;
                    buffer += tmp_length;
                    break;
                    }
                    }
                     */
                }

                // return total bytes encoded
                return total_length;
            }

        }  // else std::cout << "!!!!!!ERR!!!!!!!!!: " <<
           // root_node->node_type_name << " - " << root_node->linked_node <<
           // std::endl;
    }
    return 0;
}

asn1::ASN1Node* asn1::resolve_CHOICE(asn1::ASN1Node* needle,
                                     asn1::ASN1Node* stack) {
    if (needle != NULL && stack != NULL) {
        ASN1Node* tmp_node_stack = NULL;
        int tmp_tag_value;
        TagClass tmp_tag_class;
        // std::cout << stack->children.size() << "################" <<
        // needle->children.size() << std::endl;
        for (unsigned int i = 0; i < stack->children.size(); i++) {
            tmp_node_stack = stack->children[i];
            // reset
            // tmp_node_stack->tlv->value_length = 0;
            // tmp_node_stack->tlv->value = NULL;
            // tmp_node_stack->linked_node = NULL;

            // special tag cases
            switch (tmp_node_stack->tlv->tag_value) {
                // UNI
                case UNKNOWN_UNIVERSAL_TAG:
                    tmp_tag_value = tmp_node_stack->tlv->uni_tag_class;
                    tmp_tag_class = UNIVERSAL;
                    // std::cout << std::dec << "@@@@@@@UNI   " <<
                    // tmp_node_stack->tlv->tag_value << ":" <<
                    // tmp_node_stack->tlv->tag_class<< std::endl;
                    break;
                    // ANY
                case ANY:
                    tmp_tag_value = needle->tlv->tag_value;
                    tmp_tag_class = needle->tlv->tag_class;
                    break;
                    // other
                default:
                    tmp_tag_value = tmp_node_stack->tlv->tag_value;
                    tmp_tag_class = tmp_node_stack->tlv->tag_class;
                    break;
            }

            // CHOICE
            if (tmp_tag_value == CHOICE) {
                tmp_node_stack = resolve_CHOICE(needle, tmp_node_stack);
                if (tmp_node_stack != NULL) {
                    tmp_tag_value = tmp_node_stack->tlv->tag_value;
                    tmp_tag_class = tmp_node_stack->tlv->tag_class;
                }
            }

            // std::cout << std::dec << "@@@@@@@UNI2222    " <<
            // needle->tlv->tag_value << ":" << needle->tlv->tag_class <<
            // std::endl;

            if (tmp_node_stack != NULL) {
                if (needle->tlv->tag_class == tmp_tag_class &&
                    needle->tlv->tag_value == tmp_tag_value) {
                    return tmp_node_stack;
                }
            }
        }
    }
    return NULL;
}

// check if node exists in current session
bool asn1::node_exists(ASN1Node* node, uint64_t _session_id) {
    // if node is null, second condition will not be evaluated
    // (short-curcuit logical expressions evaluation)
    return (node != NULL && node->has_linked_data(_session_id));
}

// combine
// dest = BER decoded
// source = ASN1 structure
void asn1::combine(ASN1Node* dest, ASN1Node* src) {
    if (dest != NULL && src != NULL) {
        ASN1Node* tmp_node_dest = NULL;
        ASN1Node* tmp_node_src = NULL;
        ASN1Node* tmp_node_matched = NULL;
        int tmp_tag_value = UNKNOWN_UNIVERSAL_TAG;
        TagClass tmp_tag_class = CLASS_UNKNOWN;
        unsigned int next_src_index = 0;

        if (src->children.size() >= dest->children.size()) {
            for (unsigned int i = 0; i < dest->children.size(); i++) {
                // ber decoded node
                tmp_node_dest = dest->children[i];
                // find a match in asn1 structure
                for (unsigned int j = next_src_index; j < src->children.size();
                     j++) {
                    tmp_node_src = src->children[j];
                    // reset
                    // tmp_node_src->tlv->value_length = 0;
                    // tmp_node_src->tlv->value = NULL;
                    tmp_node_src->linked_node = NULL;
                    // special tag cases
                    switch (tmp_node_src->tlv->tag_value) {
                        // UNI tag
                        case UNKNOWN_UNIVERSAL_TAG:
                            tmp_tag_value = tmp_node_src->tlv->uni_tag_class;
                            tmp_tag_class = UNIVERSAL;
                            break;
                            // ANY
                        case ANY:
                            tmp_tag_value = tmp_node_dest->tlv->tag_value;
                            tmp_tag_class = tmp_node_dest->tlv->tag_class;
                            break;
                            // other
                        default:
                            tmp_tag_value = tmp_node_src->tlv->tag_value;
                            tmp_tag_class = tmp_node_src->tlv->tag_class;
                            break;
                    }

                    // CHOICE
                    if (tmp_tag_value == CHOICE) {
                        tmp_node_matched =
                            resolve_CHOICE(tmp_node_dest, tmp_node_src);
                        // other
                    } else {
                        if (tmp_node_dest->tlv->tag_class == tmp_tag_class &&
                            tmp_node_dest->tlv->tag_value == tmp_tag_value)
                            tmp_node_matched = tmp_node_src;
                        else
                            tmp_node_matched = NULL;
                    }

                    // check if matched
                    if (tmp_node_matched != NULL) {
                        // - SET is not ordered, start from first element every
                        // time
                        // - all other elements are ordered
                        if (src->tlv->uni_tag_class == SET)
                            next_src_index = 0;
                        else
                            next_src_index = j + 1;
                        // update dest node name
                        tmp_node_dest->node_type_name =
                            tmp_node_matched->node_type_name;
                        // update tlv values in src
                        // tmp_node_matched->tlv->value =
                        // tmp_node_dest->tlv->value;
                        // tmp_node_matched->tlv->value_length =
                        // tmp_node_dest->tlv->value_length;
                        // link node
                        tmp_node_matched->linked_node = tmp_node_dest;
                        // continue processing
                        combine(tmp_node_dest, tmp_node_matched);
                        break;
                    }
                }
            }
        }
    }
}

uint32_t asn1::prepare_int(uint32_t val, unsigned int* req_bytes,
                           int req_b_override) {
    if (req_b_override == -1)
        *req_bytes = mink_utils::size_bytes(val);
    else
        *req_bytes = req_b_override;
    val <<= (sizeof(val) - *req_bytes) * 8;
    // zero should have length of 1
    if (*req_bytes == 0) *req_bytes = 1;
    return htobe32(val);
}

uint64_t asn1::decode_int(unsigned char* data, unsigned int data_length) {
    if (data_length > sizeof(uint64_t)) return 0;
    uint64_t res = 0;
    memcpy(&res, data, data_length);
    res <<= (sizeof(uint64_t) - data_length) * 8;
    return be64toh(res);
}

time_t asn1::unix_timestamp(const char* gen_time) {
    // YYYYMMDDHHMMSS.fff
    if (gen_time == NULL) return 0;
    if (strlen(gen_time) < 14) return 0;

    tm tm_ts;
    bzero(&tm_ts, sizeof(tm_ts));
    int values[6];
    // YYYY
    int res = sscanf(gen_time, "%4u%2u%2u%2u%2u%2u", &values[0], &values[1],
                     &values[2], &values[3], &values[4], &values[5]);
    if (res == 6) {
        tm_ts.tm_year = values[0] - 1900;
        tm_ts.tm_mon = values[1] - 1;
        tm_ts.tm_mday = values[2];
        tm_ts.tm_hour = values[3];
        tm_ts.tm_min = values[4];
        tm_ts.tm_sec = values[5];
        tm_ts.tm_isdst = -1;
        return mktime(&tm_ts);
    }

    return 0;
}

int asn1::generalized_time(time_t ts, unsigned int msec, unsigned char* output,
                           bool local_time) {
    if (output == NULL) return -1;
    // fix extra msec is needed
    if (msec > 999) msec = 0;

    // YYYYMMDDHHMMSS.fff
    tm tm_ts;
    localtime_r(&ts, &tm_ts);
    int bc = 0;

    // YYYY
    int c = sprintf((char*)output, "%.4d", tm_ts.tm_year + 1900);
    output += c;
    bc += c;
    // MM
    c = sprintf((char*)output, "%.2d", tm_ts.tm_mon + 1);
    output += c;
    bc += c;
    // DD
    c = sprintf((char*)output, "%.2d", tm_ts.tm_mday);
    output += c;
    bc += c;
    // HH
    c = sprintf((char*)output, "%.2d", tm_ts.tm_hour);
    output += c;
    bc += c;
    // MM
    c = sprintf((char*)output, "%.2d", tm_ts.tm_min);
    output += c;
    bc += c;
    // SS
    c = sprintf((char*)output, "%.2d", tm_ts.tm_sec);
    output += c;
    bc += c;
    // .FFF
    if (msec > 0) {
        c = sprintf((char*)--output, "%g",
                    (tm_ts.tm_sec % 10) + ((double)msec / 1000));
        output += c;
        --bc += c;
    }
    // local or utc
    if (!local_time) {
        *output = 'Z';
        ++bc;
    }

    // byte count
    return bc;
}

