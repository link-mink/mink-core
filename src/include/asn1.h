/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef ASN1_H_
#define ASN1_H_

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <cmath>
#include <vector>
#include <string>
#include <mink_pkg_config.h>

namespace asn1 {
enum UniversalClassTag {
    EOC                     = 0x00,
    BOOLEAN                 = 0x01,
    INTEGER                 = 0x02,
    BIT_STRING              = 0x03,
    OCTET_STRING            = 0x04,
    _NULL_                  = 0x05,
    OBJECT_IDENTIFIER       = 0x06,
    OBJECT_DESCRIPTOR       = 0x07,
    EXTERNAL                = 0x08,
    REAL                    = 0x09,
    ENUMERATED              = 0x0a,
    EMBEDDED_PDV            = 0x0b,
    UTF8STRING              = 0x0c,
    RELATIVE_OID            = 0x0d,
    SEQUENCE                = 0x10,
    SEQUENCE_OF             = 0x10,
    SET                     = 0x11,
    SET_OF                  = 0x11,
    NUMERIC_STRING          = 0x12,
    PRINTABLE_STRING        = 0x13,
    T61STRING               = 0x14,
    VIDEOTEX_STRING         = 0x15,
    IA5_STRING              = 0x16,
    UTC_TIME                = 0x17,
    GENERALIZED_TIME        = 0x18,
    GRAPHIC_STRING          = 0x19,
    VISIBLE_STRING          = 0x1a,
    GENERAL_STRING          = 0x1b,
    UNIVERSAL_STRING        = 0x1c,
    CHARACTER_STRING        = 0x1d,
    BMP_STRING              = 0x1e,
    USE_LONG_FORM           = 0x1f,
    // extra
    CHOICE                  = 0xff,
    UNKNOWN_UNIVERSAL_TAG   = -1,
    ANY                     = -2

};

enum TagClass {
    UNIVERSAL               = 0x00,
    APPLICATION             = 0x40,
    CONTEXT_SPECIFIC        = 0x80,
    PRIVATE                 = 0xc0,
    CLASS_UNKNOWN           = -1

};

enum Complexity {
    PRIMITIVE               = 0x00,
    CONSTRUCTED             = 0x20,
    COMPLEXITY_UNKNOWN      = -1
};

enum LengthType {
    DEFINITE_SHORT          = 100,
    DEFINITE_LONG           = 200,
    INDEFINITE              = 300,
    LENGTH_TYPE_UNKNOWN     = -1,

};

class TLVNode {
public:
    TLVNode() = default;
    TLVNode(const TLVNode &o) = default;
    ~TLVNode();

    bool is_explicit = false;
    TagClass tag_class = CLASS_UNKNOWN;
    Complexity complexity = COMPLEXITY_UNKNOWN;
    bool override_auto_complexity = false;
    bool unlimited_size = false;
    LengthType length_type = LENGTH_TYPE_UNKNOWN;
    UniversalClassTag uni_tag_class = UNKNOWN_UNIVERSAL_TAG;
    int tag_value = -1;
    int tag_value_size = 0;
    unsigned char* value = nullptr;
    unsigned char* full_tlv = nullptr;
    int full_tlv_length = 0;
    int value_length = 0;
    unsigned int value_length_size = 0;
    // used when calculating parent lengths in update_parents
    unsigned int old_value_length = 0;

    void set_value(unsigned char* _data, unsigned int _length, bool _shallow);
};

class ASN1Node {
public:
    ASN1Node();
    ASN1Node(const ASN1Node &o) = delete;
    ASN1Node &operator=(const ASN1Node &o) = delete;
    virtual ~ASN1Node();

    TLVNode* tlv = nullptr;
    uint64_t session_id = 0;
#ifdef ENABLE_MDEBUG
    std::string node_type_name;
#endif
    std::vector<ASN1Node*> children;
    ASN1Node* linked_node = nullptr;
    ASN1Node* parent_node = nullptr;
    ASN1Node* choice_selection = nullptr;

    bool has_linked_data(uint64_t _session_id) const;
    void set_linked_data(uint64_t _session_id, unsigned char* _data,
                         unsigned int _data_length);
    void unlink(uint64_t _session_id);
    void set_linked_data(uint64_t _session_id, ASN1Node* _linked_node);
    void set_linked_data(uint64_t _session_id);
    void update_parents(uint64_t _session_id);
    void prepare();
    void set_session_id(uint64_t _session_id);
    // optional and sequence of
    virtual ASN1Node* create_node(unsigned int _index);
    virtual ASN1Node* get_next_node(unsigned int _index);
};

// standard asn1 classes
class Any : public ASN1Node {
public:
    Any();
    Any(const Any &o) = delete;
    Any &operator=(const Any &o) = delete;
    ~Any() override;
};

class Choice : public ASN1Node {
public:
    Choice();
    Choice(const Choice &o) = delete;
    Choice &operator=(const Choice &o) = delete;
    ~Choice() override;
};

class Boolean : public ASN1Node {
public:
    Boolean();
    Boolean(const Boolean &o) = delete;
    Boolean &operator=(const Boolean &o) = delete;
    ~Boolean() override;
};

class Integer : public ASN1Node {
public:
    Integer();
    Integer(const Integer &o) = delete;
    Integer &operator=(const Integer &o) = delete;
    ~Integer() override;
};

class Bit_string : public ASN1Node {
public:
    Bit_string();
    Bit_string(const Bit_string &o) = delete;
    Bit_string &operator=(const Bit_string &o) = delete;
    ~Bit_string() override;
};

class Octet_string : public ASN1Node {
public:
    Octet_string();
    Octet_string(const Octet_string &o) = delete;
    Octet_string &operator=(const Octet_string &o) = delete;
    ~Octet_string() override;
};

class PrintableString : public ASN1Node {
public:
    PrintableString();
    PrintableString(const PrintableString &o) = delete;
    PrintableString &operator=(const PrintableString &o) = delete;
    ~PrintableString() override;
};

class Null : public ASN1Node {
public:
    Null();
    Null(const Null &o) = delete;
    Null &operator=(const Null &o) = delete;
    ~Null() override;
};

class Object_identifier : public ASN1Node {
public:
    Object_identifier();
    Object_identifier(const Object_identifier &o) = delete;
    Object_identifier &operator=(const Object_identifier &o) = delete;
    ~Object_identifier() override;
};

class Object_descriptor : public ASN1Node {
public:
    Object_descriptor();
    Object_descriptor(const Object_descriptor &o) = delete;
    Object_descriptor &operator=(const Object_descriptor &o) = delete;
    ~Object_descriptor() override;
};

class Real : public ASN1Node {
public:
    Real();
    Real(const Real &o) = delete;
    Real &operator=(const Real &o) = delete;
    ~Real() override;
};

class Enumerated : public ASN1Node {
public:
    Enumerated();
    Enumerated(const Enumerated &o) = delete;
    Enumerated &operator=(const Enumerated &o) = delete;
    ~Enumerated() override;
};

class Embedded_pdv : public ASN1Node {
public:
    Embedded_pdv();
    Embedded_pdv(const Embedded_pdv &o) = delete;
    Embedded_pdv &operator=(const Embedded_pdv &o) = delete;
    ~Embedded_pdv() override;
};

class Utf8_string : public ASN1Node {
public:
    Utf8_string();
    Utf8_string(const Utf8_string &o) = delete;
    Utf8_string &operator=(const Utf8_string &o) = delete;
    ~Utf8_string() override;
};

class Relative_oid : public ASN1Node {
public:
    Relative_oid();
    Relative_oid(const Relative_oid &o) = delete;
    Relative_oid &operator=(const Relative_oid &o) = delete;
    ~Relative_oid() override;
};

class Sequence : public ASN1Node {
public:
    Sequence();
    Sequence(const Sequence &o) = delete;
    Sequence &operator=(const Sequence &o) = delete;
    ~Sequence() override;
};

class Sequence_of : public ASN1Node {
public:
    Sequence_of();
    Sequence_of(const Sequence_of &o) = delete;
    Sequence_of &operator=(const Sequence_of &o) = delete;
    ~Sequence_of() override;
    int _sequence_of_size;
};

class Set : public ASN1Node {
public:
    Set();
    Set(const Set &o) = delete;
    Set &operator=(const Set &o) = delete;
    ~Set() override;
};

class Set_of : public ASN1Node {
public:
    Set_of();
    Set_of(const Set_of &o) = delete;
    Set_of &operator=(const Set_of &o) = delete;
    ~Set_of() override;
    int _set_of_size;
};

class Numeric_string : public ASN1Node {
public:
    Numeric_string();
    Numeric_string(const Numeric_string &o) = delete;
    Numeric_string &operator=(const Numeric_string &o) = delete;
    ~Numeric_string() override;
};

class Printable_string : public ASN1Node {
public:
    Printable_string();
    Printable_string(const Printable_string &o) = delete;
    Printable_string &operator=(const Printable_string &o) = delete;
    ~Printable_string() override;
};

class T61_string : public ASN1Node {
public:
    T61_string();
    T61_string(const T61_string &o) = delete;
    T61_string &operator=(const T61_string &o) = delete;
    ~T61_string() override;
};

class Videotex_string : public ASN1Node {
public:
    Videotex_string();
    Videotex_string(const Videotex_string &o) = delete;
    Videotex_string &operator=(const Videotex_string &o) = delete;
    ~Videotex_string() override;
};

class IA5String : public ASN1Node {
public:
    IA5String();
    ~IA5String() override;
};

class Utc_time : public ASN1Node {
public:
    Utc_time();
    Utc_time(const Utc_time &o) = delete;
    Utc_time &operator=(const Utc_time &o) = delete;
    ~Utc_time() override;
};

class Generalized_time : public ASN1Node {
public:
    Generalized_time();
    Generalized_time(const Generalized_time &o) = delete;
    Generalized_time &operator=(const Generalized_time &o) = delete;
    ~Generalized_time() override;
};

class Graphic_string : public ASN1Node {
public:
    Graphic_string();
    Graphic_string(const Graphic_string &o) = delete;
    Graphic_string &operator=(const Graphic_string &o) = delete;
    ~Graphic_string() override;
};

class Visible_string : public ASN1Node {
public:
    Visible_string();
    Visible_string(const Visible_string &o) = delete;
    Visible_string &operator=(const Visible_string &o) = delete;
    ~Visible_string() override;
};

class General_string : public ASN1Node {
public:
    General_string();
    General_string(const General_string &o) = delete;
    General_string &operator=(const General_string &o) = delete;
    ~General_string() override;
};

class Universal_string : public ASN1Node {
public:
    Universal_string();
    Universal_string(const Universal_string &o) = delete;
    Universal_string &operator=(const Universal_string &o) = delete;
    ~Universal_string() override;
};

class Character_string : public ASN1Node {
public:
    Character_string();
    Character_string(const Character_string &o) = delete;
    Character_string &operator=(const Character_string &o) = delete;
    ~Character_string() override;
};

class Bmp_string : public ASN1Node {
public:
    Bmp_string();
    Bmp_string(const Bmp_string &o) = delete;
    Bmp_string &operator=(const Bmp_string &o) = delete;
    ~Bmp_string() override;
};

class GeneralizedTime : public ASN1Node {
public:
    GeneralizedTime();
    GeneralizedTime(const GeneralizedTime &o) = delete;
    GeneralizedTime &operator=(const GeneralizedTime &o) = delete;
    ~GeneralizedTime() override;
};

class UTCTime : public ASN1Node {
public:
    UTCTime();
    UTCTime(const UTCTime &o) = delete;
    UTCTime &operator=(const UTCTime &o) = delete;
    ~UTCTime() override;
};

// ========== Eternal and related =============
// EXTERNAL_encoding
class EXTERNAL_encoding : public Choice {
public:
    EXTERNAL_encoding();
    EXTERNAL_encoding(const EXTERNAL_encoding &o);
    EXTERNAL_encoding &operator=(const EXTERNAL_encoding &o);
    ~EXTERNAL_encoding() override;
    // nodes
    Any* _single_ASN1_type;
    Octet_string* _octet_aligned;
    Bit_string* _arbitrary;
};

class External : public Sequence {
public:
    External();
    External(const External &o);
    External &operator=(const External &o);
    ~External() override;
    // nodes
    Object_identifier* _direct_reference;
    Integer* _indirect_reference;
    Object_descriptor* _data_value_descriptor;
    EXTERNAL_encoding* _encoding;
};
// ========================================

// ASN1 pool classes
class ASN1Pool {
private:
    std::vector<TLVNode*> TLV_POOL;
    std::vector<ASN1Node*> ASN1_POOL;
    int tlv_count = 100;
    int asn1_node_count = 100;
    int free_tlv_count = 100;
    int free_asn1_node_count = 100;
    TLVNode* next_free_tlv = nullptr;
    ASN1Node* next_free_asn1_node = nullptr;

public:
    ASN1Pool() = default;
    ASN1Pool(const ASN1Pool &o) = delete;
    ASN1Pool &operator=(const ASN1Pool &o) = delete;
    ~ASN1Pool();

    void set_pool_size(int _tlv_count, int _asn1_node_count);
    void init_pool();
    TLVNode* request_tlv();
    ASN1Node* request_asn1_node();
    int get_free_tlv_count() const;
    int get_free_asn1_node_count() const;
    int get_tlv_count() const;
};

class SessionId {
private:
    uint64_t session_id = 0;

public:
    SessionId() = default;
    uint64_t get_next_id();
    uint64_t get_next_id(ASN1Node* _node);
    uint64_t get_current_id() const;
};

// helper methods
int decode_length(unsigned char* data, unsigned int data_length, TLVNode* tlv);
void decode_tag(const unsigned char* data, unsigned int data_length, TLVNode* tlv);
void encode_length(unsigned char* data, unsigned int data_length, TLVNode* tlv);
void encode_prepared_length(unsigned char* data, unsigned int data_length,
                            const TLVNode* tlv);
void prepare_length(TLVNode* tlv);
void encode_prepared_tag(unsigned char* data, unsigned int data_length,
                         const TLVNode* tlv);
void encode_tag(unsigned char* data, unsigned int data_length, TLVNode* tlv);
void prepare_tag(TLVNode* tlv);
int find_eoc(unsigned char* data, unsigned int data_length);
ASN1Node* resolve_CHOICE(ASN1Node* needle, ASN1Node* stack);
void prepare(ASN1Node* root_node, ASN1Node* parent);
void reset(ASN1Node* root_node);
void set_session_id(ASN1Node* root_node, uint64_t _session_id);
uint64_t generate_session_id();
void print_structure(const ASN1Node* root_node, int depth);

void mem_transfer_deep(ASN1Node* root_node, unsigned char* dest_buffer,
                       int dest_buffer_pos);

// check if node exists in current session
bool node_exists(const ASN1Node* node, uint64_t _session_id);

// main decode method WITHOUT asn1 definition
int decode(unsigned char* data, unsigned int data_length, ASN1Node* root_node,
           ASN1Pool* _asn1_pool);
int _decode(unsigned char* data, unsigned int data_length, ASN1Node* root_node,
            ASN1Pool* _asn1_pool, unsigned int* used_nc);

// helper decode method, used ONLY internally
int _decode(unsigned char* data, unsigned int data_length, ASN1Node* root_node,
            ASN1Node* root_defintion_node, ASN1Pool* _asn1_pool,
            uint64_t* _session_id, unsigned int* used_nc);
// main decode method WITH asn1 definition
int decode(unsigned char* data, unsigned int data_length, ASN1Node* root_node,
           ASN1Node* root_defintion_node, ASN1Pool* _asn1_pool,
           uint64_t* _session_id);

// encode method
int encode(unsigned char* buffer, int buffer_length, ASN1Node* root_node,
           uint64_t _session_id);
int encode(unsigned char* buffer, int buffer_length, ASN1Node* root_node,
           uint64_t _session_id, bool mem_switch);

// combine dest(without asn1 definition) and source(with asn1 definition)
void combine(ASN1Node* dest, ASN1Node* src);

// convert unix timestamp to generalized time
int generalized_time(time_t ts, 
                     unsigned int msec, 
                     unsigned char* output,
                     size_t out_sz,
                     bool local_time = true);
// convert generalized time to unix timestamp
time_t unix_timestamp(const char* gen_time);

// prepare int for asn.1 ber encoded integer
uint32_t prepare_int(uint32_t val, unsigned int* req_bytes,
                     int req_b_override = -1);

// decode asn.1 int
uint64_t decode_int(const unsigned char* data, unsigned int data_length);

}  // namespace asn1

#endif /* ASN1_H_ */
