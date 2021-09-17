/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_UTILS_H_
#define MINK_UTILS_H_

#include <ext/mt_allocator.h>
#include <iomanip>
#include <time.h>
#include <string>
#include <dirent.h>
#include <curses.h>
#include <inttypes.h>
#include <map>
#include <atomic.h>
#include <vector>
#include <sstream>
#include <spscq.h>
#include <pool.h>
#include <ext/mt_allocator.h>
#include <string.h>
#include <new>
#include <iomanip>
#include <unordered_map>
#include <limits>
#include <mutex>
#include <random>

namespace mink_utils {
    /**
     * Variant data type
     */
    enum VariantParamType{
        DPT_INT     = 1,
        DPT_STRING  = 2,
        DPT_DOUBLE  = 3,
        DPT_CHAR    = 4,
        DPT_BOOL    = 5,
        DPT_OCTETS  = 6,
        DPT_POINTER = 7
    };

    /**
     * Variant param union
     */
    union UVariantParam{
        int64_t i64;
        double d;
        char c;
        bool b;
        void* p;
        char* str;
    };

    /**
     * Get number of bits required for int
     * @param[in]   input   Integer value
     * @return      Number of bits required for input
     */
    int size_bits(unsigned int input);

    /**
     * Get number of bytes required for int
     * @param[in]   input   Integer value
     * @return      Number of bytes required for input
     */
    int size_bytes(unsigned int input);

    /**
     * Variant param
     */
    class VariantParam {
    public:
        /**
         * Types
         */
        using param_alloc_t = __gnu_cxx::__mt_alloc<char>;

        /**
         * Constructor
         * @param   _type   Variant data type
         */
        VariantParam(VariantParamType _type, 
                     param_alloc_t* _palloc, 
                     unsigned int _max): max(_max),
                                         type(_type),
                                         data_size(0),
                                         palloc(_palloc),
                                         palloc_p(nullptr){

        }

        /**
         * Destructor
         */
        ~VariantParam(){
            if(palloc_p != nullptr) {
                palloc->deallocate(palloc_p, data_size);
                palloc_p = nullptr;
            }

        }

        /**
         * Equality operator
         */
        bool operator==(const VariantParam& other) const {
            if(this->type != other.type) return false;
            if(this->data_size != other.data_size) return false;
            switch(this->type){
                case DPT_INT:
                    return this->data.i64 == other.data.i64;

                case DPT_STRING:
                    return (strcmp(this->data.str, other.data.str) == 0);

                case DPT_DOUBLE:
                    return this->data.d == other.data.d;

                case DPT_CHAR:
                    return this->data.c == other.data.c;

                case DPT_BOOL:
                    return this->data.b == other.data.b;

                case DPT_OCTETS:
                    return (memcmp(this->data.str, other.data.str, this->data_size) == 0);

                case DPT_POINTER:
                    return this->data.p == other.data.p;

                default: break;
            }
            return false;
        }

        /**
         * Inequality operator
         */
        bool operator!=(const VariantParam& other) const {
            return !(*this == other);
        }

        /**
         * Int variant cast
         */
        explicit operator int() const {
            if(type == DPT_INT) return data.i64;
            return 0;
        }

        /**
         * Unsigned 64bit int variant vast
         */
        explicit operator uint64_t() const {
            if(type == DPT_INT) return data.i64;
            return 0;
        }

        /**
         * Unsigned 32bit int variant vast
         */
        explicit operator uint32_t() const {
            if(type == DPT_INT) return data.i64;
            return 0;
        }

        /**
         * Bool variant cast
         */
        explicit operator bool() const {
            if(type == DPT_BOOL) return data.b;
            return false;
        }

        /**
         * C style string variant cast
         */
        explicit operator char*() const {
            if(type == DPT_STRING) return data.str;
            return nullptr;
        }

        /**
         * Octets variant cast
         */
        explicit operator unsigned char*() const {
            if(type == DPT_OCTETS) return (unsigned char*)data.str;
            return nullptr;
        }

        /**
         * Double variant cast
         */
        explicit operator double() const {
            if(type == DPT_DOUBLE) return data.d;
            return 0;
        }

        /**
         * Char variant cast
         */
        explicit operator char() const {
            if(type == DPT_CHAR) return data.c;
            return 0;
        }

        /**
         * Pointer variant cast
         */
        explicit operator void*() const {
            if(type == DPT_POINTER) return data.p;
            return nullptr;
        }

        /**
         * Set Int variant data
         * @param[in]   _data   Int data
         */
        void set_int(int64_t _data){
            if(type == DPT_INT){
                data.i64 = _data;
                data_size = sizeof(data.i64);
            }
        }

        /**
         * Set bool variant data
         * @param[in]   _data   bool data
         */
        void set_bool(bool _data){
            if(type == DPT_BOOL){
                data.b = _data;
                data_size = sizeof(data.b);
            }
        }

        /**
         * Set C style string variant data
         * @param[in]   _data   C string data
         */
        void set_str(const char* _data){
            if(type == DPT_STRING){
                // get string length
                size_t slen = strnlen(_data, max);
                // check for buffer overflow
                unsigned int csize = (slen >= max ? (max - 1) : slen);
                // allocate
                if(palloc_p != nullptr) palloc->deallocate(palloc_p, data_size);
                palloc_p = palloc->allocate(csize + 1);
                data.str = new(palloc_p) char[csize + 1];
                // copy data
                memcpy(data.str, _data, csize);
                // set null termination
                data.str[csize] = 0;
                // set size
                data_size = csize + 1;
            }
        }

        /**
         * Set char variant data
         * @param[in]   _data   char data
         */
        void set_char(char _data){
            if(type == DPT_CHAR){
                data.c = _data;
                data_size = sizeof(data.c);

            }
        }

        /**
         * Set double variant data
         * @param[in]   _data   double data
         */
        void set_double(double _data){
            if(type == DPT_DOUBLE){
                data.d = _data;
                data_size = sizeof(data.d);
            }
        }

        /**
         * Set octets variant data
         * @param[in]   _data       octets data
         * @param[in]   _data_size  data size
         */
        void set_octets(const unsigned char* _data, unsigned int _data_size){
            if(type == DPT_OCTETS){
                // check for buffer overflow
                unsigned int csize = (_data_size > max ? max : _data_size);
                // allocate
                if(palloc_p != nullptr) palloc->deallocate(palloc_p, data_size);
                palloc_p = palloc->allocate(csize);
                data.str = new(palloc_p) char[csize];
                // copy data
                memcpy(data.str, _data, csize);
                // set size
                data_size = csize;
            }
        }

        /**
         * Set pointer variant data
         * @param[in]   _data   double data
         */
        void set_pointer(void* _data){
            if(type == DPT_POINTER){
                data.p = _data;
                data_size = sizeof(void*);
            }
        }

        /**
         * Get current data size in bytes
         * @return      Data size in bytes
         */
        unsigned int get_size() const {
            return data_size;
        } 

        /**
         * Get parameter type
         * @return      Parameter type
         */
        VariantParamType get_type() const {
            return type;
        }

        /**
         * Set parameter type
         */
        void set_type(VariantParamType _type){
            type = _type;
        }

        /**
         * Get variant data pointer
         */
        UVariantParam* get_data(){
            return &data;
        }

        /**
         * Output operator<< for VariantParam
         *
         */
        friend std::ostream& operator<< (std::ostream& out, const VariantParam& param){
            switch(param.type){
                case DPT_INT:
                    out << "(I) " << (int)param;
                    break;

                case DPT_OCTETS:
                    {
                        out << "(O) ";

                        auto cdata = (unsigned char*)param;
                        for(unsigned int k = 0; k<param.data_size; k++){
                            out << std::setfill('0') << std::setw(2) << std::hex << (int)(cdata[k] & 0xff)<< " ";
                        }
                        out << std::dec;

                        break;
                    }

                case DPT_STRING:
                    out << "(S) " << (char*)param;
                    break;

                case DPT_BOOL:
                    out << "(B) " << ((bool)param ? "true" : "false");
                    break;

                case DPT_CHAR:
                    out << "(C)" << "'" << (char)param << "'";
                    break;

                case DPT_DOUBLE:
                    out << "(D) " << (double)param;
                    break;

                case DPT_POINTER:
                    out << "(P) " << (void*)param;
                    break;

                default:
                    break;

            }
            return out;
        }

        /**
         * Get maxium number of storage bytes for STRING
         * and OCTETS types
         */
        unsigned int get_max() const {
            return max;
        }

    private:
        unsigned int max;
        UVariantParam data;
        VariantParamType type;
        unsigned int data_size;
        param_alloc_t* palloc;
        param_alloc_t::pointer palloc_p;

    };

    template<typename TID = uint32_t>
    class ParamTuple {
    public:
        explicit ParamTuple(TID _key, 
                            uint32_t _index = 0, 
                            uint32_t _fragment = 0, 
                            uint32_t _context = 0): key(_key),
                            index(_index),
                            fragment(_fragment),
                            context(_context){}
        TID key;
        uint32_t index;
        uint32_t fragment;
        uint32_t context;

        bool operator != (const ParamTuple& right) const {
            if(this->key == right.key) return false;
            if(this->index == right.index) return false;
            if(this->fragment == right.fragment) return false;
            if(this->context == right.context) return false;
            return true;

        }
        bool operator == (const ParamTuple& right) const {
            if(this->key != right.key) return false;
            if(this->index != right.index) return false;
            if(this->fragment != right.fragment) return false;
            if(this->context != right.context) return false;
            return true;
        }

        /**
         * Standard output operator
         */
        friend std::ostream& operator<<(std::ostream& out, const ParamTuple& pt){
            out << "[" << pt.context << "] " << pt.key << "." << pt.index << "." << pt.fragment;
            return out;

        }

    };


    template<typename TID>
    class ParamTupleCompare{
    public:
        bool operator ()(const ParamTuple<TID>& x, const ParamTuple<TID>& y) const {
            if(x.key < y.key) return true;
            else if(x.key == y.key){
                if(x.index < y.index) return true;
                else if(x.index == y.index){
                    if(x.fragment < y.fragment) return true;
                    else if(x.fragment == y.fragment){
                        if(x.context < y.context) return true;
                    }
                }

            }

            return false;
        }
    };

    /**
     * Variant param map
     * @param[in]       TID     key type
     * @param[in]       _Alloc  param map allocator
     */
    template<typename TID, typename _Alloc = std::allocator<std::pair<const ParamTuple<TID>, VariantParam > > >
    class VariantParamMap {
    public:
        /**
         * Types
         */
        using pmap_t = std::map<ParamTuple<TID>, VariantParam, ParamTupleCompare<TID>, _Alloc>;
        using pmap_value_t = typename pmap_t::value_type;
        using it_t = typename pmap_t::iterator;
        using cit_t = typename pmap_t::const_iterator;
        using insert_res_t = std::pair<it_t, bool>;
        using tune_t = __gnu_cxx::__pool_base::_Tune;
        using param_alloc_t = __gnu_cxx::__mt_alloc<char>;

        /**
         * Constructor
         */
        VariantParamMap(unsigned int MAX_STR_SIZE = 256, 
                        const _Alloc& alloc = _Alloc()): max(MAX_STR_SIZE),
                                                         params(ParamTupleCompare<TID>(), alloc){
            // set param allocator
            tune_t t_opt(16, 2048, 32, 10240, 4096, 10, false);
            param_alloc._M_set_options(t_opt);
            labels_p = &labels;

        }
        
        /**
         * Destructor
         */
        ~VariantParamMap() = default;

        /**
         * Copy constructor
         */
        VariantParamMap(const VariantParamMap& other){
            // set max
            max = other.max;
            // set param allocator
            tune_t t_opt(16, 2048, 32, 10240, 4096, 10, false);
            param_alloc._M_set_options(t_opt);
            // copy labels
            labels = other.labels;
            labels_p = &labels;
            // loop other params
            for(it_t it = other.params.begin(); it != other.params.end(); ++it){
                // other param
                VariantParam& vparam = it->second;
                // create param with data from other param
                switch(vparam.get_type()){
                    case DPT_INT:
                        set_int(it->first.key, vparam.get_data()->i64, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_STRING:
                        set_cstr(it->first.key, vparam.get_data()->str, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_DOUBLE:
                        set_double(it->first.key, vparam.get_data()->d, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_CHAR:
                        set_char(it->first.key, vparam.get_data()->c, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_BOOL:
                        set_bool(it->first.key, vparam.get_data()->b, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_OCTETS:
                        set_octets(it->first.key, (unsigned char*)vparam.get_data()->str, vparam.get_size(), it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_POINTER:
                        set_pointer(it->first.key, vparam.get_data()->p, it->first.index, it->first.fragment, it->first.context);
                        break;

                    default:
                        break;

                }

            }

        }

        /**
         * Equality operator
         */
        bool operator==(const VariantParamMap<TID, _Alloc>& other) const {
            return (this->params == other.params);
        }

        /**
         * Inequality operator
         */
        bool operator!=(const VariantParamMap<TID, _Alloc>& other) const {
            return (this->params != other.params);
        }



        /**
         * Assignment operator
         */
        VariantParamMap<TID, _Alloc>& operator=(VariantParamMap<TID, _Alloc>& other) {
            // self assignment check
            if(this == &other) return *this;
            params.clear();
            // copy labels
            labels = other.labels;
            // loop other params
            for(it_t it = other.params.begin(); it != other.params.end(); ++it){
                // other param
                VariantParam& vparam = it->second;
                // create param with data from other param
                switch(vparam.get_type()){
                    case DPT_INT:
                        set_int(it->first.key, vparam.get_data()->i64, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_STRING:
                        set_cstr(it->first.key, vparam.get_data()->str, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_DOUBLE:
                        set_double(it->first.key, vparam.get_data()->d, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_CHAR:
                        set_char(it->first.key, vparam.get_data()->c, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_BOOL:
                        set_bool(it->first.key, vparam.get_data()->b, it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_OCTETS:
                        set_octets(it->first.key, (unsigned char*)vparam.get_data()->str, vparam.get_size(), it->first.index, it->first.fragment, it->first.context);
                        break;

                    case DPT_POINTER:
                        set_pointer(it->first.key, vparam.get_data()->p, it->first.index, it->first.fragment, it->first.context);
                        break;

                    default:
                        break;

                }

            }
            return *this;
        }

        /**
         * Add int param
         * @param[in]   id      key
         * @param[in]   data    param data
         */
        VariantParam* set_int(TID id, int64_t data, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_INT, &param_alloc, max)));
            rt.first->second.set_int(data);
            return &rt.first->second;
        }

        /**
         * Increment int param
         * @param[in]   id      key
         * @param[in]   data    param data
         */
        VariantParam* inc_int(TID id, int64_t data, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_INT, &param_alloc, max)));


            if(!rt.second) rt.first->second.get_data()->i64 += data;

            return &rt.first->second;
        }


        /**
         * Add bool param
         * @param[in]   id      key
         * @param[in]   data    param data
         */
        VariantParam* set_bool(TID id, bool data, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_BOOL, &param_alloc, max)));
            rt.first->second.set_bool(data);
            return &rt.first->second;
        }


        /**
         * Add C string param
         * @param[in]   id      key
         * @param[in]   data    param data
         */
        VariantParam* set_cstr(TID id, const char* data, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_STRING, &param_alloc, max)));
            rt.first->second.set_str(data);
            return &rt.first->second;
        }

        /**
         * Add char param
         * @param[in]   id      key
         * @param[in]   data    param data
         */
        VariantParam* set_char(TID id, char data, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_CHAR, &param_alloc, max)));
            rt.first->second.set_char(data);
            return &rt.first->second;
        }

        /**
         * Add double param
         * @param[in]   id      key
         * @param[in]   data    param data
         */
        VariantParam* set_double(TID id, double data, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_DOUBLE, &param_alloc, max)));
            rt.first->second.set_double(data);
            return &rt.first->second;
        }

        /**
         * Add octets param
         * @param[in]   id          key
         * @param[in]   data        param data
         * @param[in]   data_size   param data size
         */
        VariantParam* set_octets(TID id, const unsigned char* data, unsigned int data_size, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_OCTETS, &param_alloc, max)));
            rt.first->second.set_octets(data, data_size);
            return &rt.first->second;
        }

        /**
         * Add pointer param
         * @param[in]   id      key
         * @param[in]   data    param data
         */
        VariantParam* set_pointer(TID id, void* data, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            insert_res_t rt = params.insert(pmap_value_t(ParamTuple<TID>(id, index, fragment, context),
                        VariantParam(DPT_POINTER, &param_alloc, max)));
            rt.first->second.set_pointer(data);
            return &rt.first->second;
        }

        VariantParam* set(VariantParam* vp, TID id, uint32_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            switch(vp->get_type()){
                case DPT_INT:
                    return set_int(id, vp->get_data()->i64, index, fragment, context);

                case DPT_STRING:
                    return set_cstr(id, vp->get_data()->str, index, fragment, context);

                case DPT_DOUBLE:
                    return set_double(id, vp->get_data()->d, index, fragment, context);

                case DPT_CHAR:
                    return set_char(id, vp->get_data()->c, index, fragment, context);

                case DPT_BOOL:
                    return set_bool(id, vp->get_data()->b, index, fragment, context);

                case DPT_OCTETS:
                    return set_octets(id, (unsigned char*)vp->get_data()->str, vp->get_size(), index, fragment, context);

                case DPT_POINTER:
                    return set_pointer(id, vp->get_data()->p, index, fragment, context);

                default:
                    break;

            }

            return nullptr;

        }

        bool set(VariantParamMap& other_map, ParamTuple<TID> other_id, ParamTuple<TID> id){
            // get from other map
            VariantParam* other_vp = other_map.get_param(other_id.key, other_id.index, other_id.fragment, other_id.context);
            // cehck if found
            if(other_vp == nullptr) return false;
            // set
            if(set(other_vp, id.key, id.index, id.fragment, id.context) == nullptr) return false;
            // ok
            return true;
        }




        /**
         * Defragment parameter
         * @param[in]   id      key
         * @param[in]   index   param index
         * @return      Pointer to defragmented parameter
         */
        VariantParam* defragment(TID id, uint32_t index = 0, uint32_t context = 0){
            // find first fragment
            it_t it = params.find(ParamTuple<TID>(id, index, 0, context));
            // sanity check
            if(it == params.end()) return nullptr;
            // tmp buffer
            unsigned char tmp_buff[max];
            // counter
            unsigned int c = 0;
            // loop fragments
            for(it_t it_next = it; it != params.end() && it->first.key == id && it->first.index == index && it->first.context == context; it = it_next){
                // next
                ++it_next;
                // copy data
                memcpy(&tmp_buff[c], it->second.get_data()->str, it->second.get_size());
                // next fragment
                c += it->second.get_size();
                // sanity check
                if(c >= max) {
                    c = max;
                    break;
                }

                // erase fragment
                params.erase(it);

            }

            // create and return new param
            return set_octets(id, tmp_buff, c, index, 0, context);


        }



        /**
         * Get param
         * @param[in]   id      key
         * @return      Pointer to variant param or nullptr if not found
         */
        VariantParam *get_param(TID id, 
                                uint32_t index = 0,
                                uint32_t fragment = 0, 
                                uint32_t context = 0) {
            it_t it = params.find(ParamTuple<TID>(id, 
                                                  index, 
                                                  fragment, 
                                                  context));
            if (it != params.end())
                return &it->second;
            return nullptr;
        }

        /**
         * Get param
         * @param[in]   id      key
         * @return      Pointer to variant param's value or nullptr if not found
         */
        template <typename T>
        T get_pval(TID id, 
                    uint32_t index = 0, 
                    uint32_t fragment = 0,
                    uint32_t context = 0) {
            it_t it = params.find(ParamTuple<TID>(id, 
                                                  index, 
                                                  fragment, 
                                                  context));
            if (it != params.end()) {
                return static_cast<T>(it->second);
            }
            throw(std::runtime_error("Param not found"));
        }

        /**
         * Check if context exists
         * @param[in]   context context
         * @return      true if found or false otherwise
         */
        bool context_exists(uint32_t context){
            for(it_t it = params.begin(); it != params.end(); ++it){
                if(it->first.context == context) return true;
            }
            return false;
        }

        bool swap(ParamTuple<TID> id1, ParamTuple<TID> id2){
            // find
            it_t it1 = params.find(id1);
            it_t it2 = params.find(id2);
            // sanity
            if(it1 == params.end() || it2 == params.end()) return false;
            if(it1 == it2) return false;
            // param refs
            const VariantParam& vp1 = it1->second;
            VariantParam& vp2 = it2->second;
            // check if types are the same
            if(vp1.get_type() != vp2.get_type()) return false;
            // check type
            switch(vp1.get_type()){
                case DPT_INT:
                    {
                        int64_t tmp = (int)vp1;
                        set_int(id1.key, vp2.get_data()->i64, id1.index, id1.fragment, id1.context);
                        set_int(id2.key, tmp, id2.index, id2.fragment, id2.context);
                        break;
                    }
                case DPT_STRING:
                    {
                        char tmp[max];
                        memcpy(tmp, (char*)vp1, vp1.get_size());
                        set_cstr(id1.key, vp2.get_data()->str, id1.index, id1.fragment, id1.context);
                        set_cstr(id2.key, tmp, id2.index, id2.fragment, id2.context);
                        break;
                    }

                case DPT_DOUBLE:
                    {
                        double tmp = (double)vp1;
                        set_double(id1.key, vp2.get_data()->d, id1.index, id1.fragment, id1.context);
                        set_double(id2.key, tmp, id2.index, id2.fragment, id2.context);
                        break;
                    }

                case DPT_CHAR:
                    {
                        char tmp = (char)vp1;
                        set_char(id1.key, vp2.get_data()->c, id1.index, id1.fragment, id1.context);
                        set_char(id2.key, tmp, id2.index, id2.fragment, id2.context);
                        break;
                    }

                case DPT_BOOL:
                    {
                        bool tmp = (bool)vp1;
                        set_bool(id1.key, vp2.get_data()->b, id1.index, id1.fragment, id1.context);
                        set_bool(id2.key, tmp, id2.index, id2.fragment, id2.context);
                        break;
                    }
                case DPT_OCTETS:
                    {
                        unsigned char tmp[max];
                        memcpy(tmp, (unsigned char*)vp1, vp1.get_size());
                        int tmp_s = vp1.get_size();
                        set_octets(id1.key, (unsigned char*)vp2.get_data()->str, vp2.get_size(), id1.index, id1.fragment, id1.context);
                        set_octets(id2.key, tmp, tmp_s, id2.index, id2.fragment, id2.context);
                        break;
                    }

                case DPT_POINTER:
                    {
                        void* tmp = (void*)vp1;
                        set_pointer(id1.key, vp2.get_data()->p, id1.index, id1.fragment, id1.context);
                        set_pointer(id2.key, tmp, id2.index, id2.fragment, id2.context);
                        break;
                    }

                default:
                    break;
            }

            // ok
            return true;
        }


        /**
         * Remove param from list
         * @param[in]   id      key
         * @return      Number of removed params
         */
        size_t erase_param(TID id, int64_t index = 0, uint32_t fragment = 0, uint32_t context = 0){
            if(index == -1){
                int c = 0;
                for(it_t it = params.begin(), it_next = it; it != params.end(); it = it_next){
                    // next
                    ++it_next;
                    // check key
                    if(it->first.key == id && it->first.context == context) {
                        params.erase(it);
                        ++c;
                    }
                }
                // return
                return c;

            }else return params.erase(ParamTuple<TID>(id, index, fragment, context));
        }

        /**
         * Remove all params
         */
        void clear_params(){
            params.clear();
        }

        /**
         * Get iterator to beginning of params
         */
        it_t get_begin(){
            return params.begin();
        }

        /**
         * Get iterator to end of params
         */
        it_t get_end(){
            return params.end();
        }

        /**
         * Standard output operator
         */
        friend std::ostream& operator<<(std::ostream& out, const VariantParamMap& pmap){
            for(cit_t it = pmap.params.begin(); it != pmap.params.end(); ++it){
                // key
                out << std::dec << it->first;
                // find label
                typename std::map<TID, std::string>::iterator itl = pmap.labels_p->find(it->first.key);
                if(itl != pmap.labels_p->end()) out << " (" << itl->second << ")";
                // value
                out << " = " << it->second;
                // endl
                out << std::endl;
            }
            return out;

        }

        /**
         * Set param id label
         */
        void set_label(TID id, const char* label){
            labels[id] = label;
        }

        /**
         * Set label map pointer
         */
        void set_label_p(std::map<TID, std::string>* labels){
            labels_p = labels;
        }

        /**
         * Get param map size
         */
        size_t size() const {
            return params.size();
        }

        /**
         * Get maxium number of storage bytes for STRING
         * and OCTETS types
         */
        unsigned int get_max() const {
            return max;
        }

    private:
        unsigned int max;
        param_alloc_t param_alloc;
        std::map<TID, std::string> labels;
        std::map<TID, std::string>* labels_p;
        std::map<ParamTuple<TID>, VariantParam, ParamTupleCompare<TID>, _Alloc> params;
    };

    /**
     * Pooled Variant param map (GCC mt_allocator)
     * @param[in]       TID     key type
     */
    template<typename TID>
    class PooledVPMap: public VariantParamMap<TID,
        __gnu_cxx::__mt_alloc<std::pair<const ParamTuple<TID>, VariantParam > > >{
    public:
        /**
         * types
         */
        using tune_t = __gnu_cxx::__pool_base::_Tune;
        using mt_alloc_t = __gnu_cxx::__mt_alloc<std::pair<const ParamTuple<TID>, mink_utils::VariantParam > >;

        /**
         * Constructor
         */
        explicit PooledVPMap(unsigned int MAX_STR_SIZE = 1024)
            : VariantParamMap<TID, mt_alloc_t>(MAX_STR_SIZE, mt_alloc_t()) {}
    };

    /**
     * General parameter map
     * @tparam  TID     Parameter id typename
     * @tparam  T       Parameter typename
     * @tparam  THSAFE  Thread safe flag
     */
    template <typename TID, typename T, bool THSAFE = false>
    class ParameterMap {
    public:
        /**
         * Constructor
         */
        ParameterMap() {
            if (THSAFE)
                pthread_rwlock_init(&_lock, nullptr);
        }

        ParameterMap(const ParameterMap &o) = delete;
        ParameterMap &operator=(const ParameterMap &o) = delete;

        /**
         * Destructor
         */
        ~ParameterMap() {
            if (THSAFE)
                pthread_rwlock_destroy(&_lock);
        }

        /**
         * Get parameter
         * @param[in]   param_id        Parameter id
         * @return      Parameter or nullptr if not found
         */
        T get_param(TID param_id) {
            lock_rd();
            typename std::map<TID, T>::iterator it = params.find(param_id);
            T res = (it != params.end() ? it->second : nullptr);
            unlock();
            return res;
        }

        /**
         * Check if parameter exists
         * @param[in]   param_id        Parameter id
         * @return      true if parameter exists or false otherwise
         */
        bool exists(TID param_id) {
            lock_rd();
            typename std::map<TID, T>::iterator it = params.find(param_id);
            bool res = (it != params.end() ? true : false);
            unlock();
            return res;
        }

        /**
         * Get paramter map
         * @param[in]   Pointer to parameter map
         */
        std::map<TID, T> *get_param_map() { return &params; }

        /**
         * Set parameter
         * @param[in]   param_id        Parameter id
         * @param[in]   param           Parameter
         */
        void set_param(TID param_id, T param) {
            lock_wr();
            params[param_id] = param;
            unlock();
        }

        /**
         * Remove parameter
         * @param[in]   param_id        Parameter id
         * @return      Number of erased parameters
         */
        int remove_param(TID param_id) {
            lock_wr();
            int res = params.erase(param_id);
            unlock();
            return res;
        }

        /**
         * Clear parameter map
         */
        void clear_params() {
            lock_wr();
            params.clear();
            unlock();
        }

    private:
        /**
         * Read Lock
         */
        void lock_rd() {
            if (THSAFE)
                pthread_rwlock_rdlock(&_lock);
        }

        /**
         * Write Lock
         */
        void lock_wr() {
            if (THSAFE)
                pthread_rwlock_wrlock(&_lock);
        }

        /**
         * Unlock mutex
         */
        void unlock() {
            if (THSAFE)
                pthread_rwlock_unlock(&_lock);
        }

        /** Parameter map */
        std::map<TID, T> params;
        /** RW lock */
        pthread_rwlock_t _lock;
    };

    // fwd
    uint64_t hash_fnv1a_64bit(const void *key, int len);

    class Randomizer {
    public:
        Randomizer();

        /**
         * generate rando sequence of characters
         *
         * @param[out] out  Pointer to output buffer
         * @param[in]   nr  Size of output buffer
         */
        void generate(uint8_t *out, const size_t nr);
        
    private:
        std::uniform_int_distribution<> dis;
        std::random_device rd;
        std::mt19937 gen;

    };    

    class Guid {
    public:
        const uint8_t* data() const{
            return guid.data();
        }
        void set(const uint8_t *data){
            for (int i = 0; i < 16; i++)
                guid[i] = data[i];
        }

        bool operator==(const Guid &o) const { 
            return (guid == o.guid); 
        }

    private:
        std::array<uint8_t, 16> guid;
    
    };

    template <typename DATA_TYPE> 
    class CorrelationMap {
    public:

        class DataWrapper {
        public:
            DataWrapper() : ts(time(nullptr)), 
                            data_timeout(0) {}
            DataWrapper(const DATA_TYPE &_data, uint32_t _timeout)
                : ts(time(nullptr)), 
                  data_timeout(_timeout), 
                  data(_data) {}
            time_t ts;
            uint32_t data_timeout;
            DATA_TYPE data;
        };

        // hashing functor
        struct fnv1a_guid_hash {
            size_t operator()(const Guid &x) const {
                return hash_fnv1a_64bit(x.data(), 16);
            }
        };

        // types
        using cmap_pair_t = std::pair<const Guid, DataWrapper>;
        using cmap_type = std::unordered_map<Guid, 
                                             DataWrapper, 
                                             fnv1a_guid_hash,
                                             std::equal_to<Guid>>;

        using cmap_it_type = typename cmap_type::iterator;
        using cmap_value_type = typename cmap_type::value_type;
        using cmap_insert_type = std::pair<cmap_it_type, bool>;

        CorrelationMap() : data_timeout(10), 
                           max(std::numeric_limits<uint32_t>::max()) {}
        explicit CorrelationMap(uint32_t _max, uint32_t _data_timeout = 10)
            : data_timeout(_data_timeout), max(_max) {}

        void set_max_size(uint32_t _max) { max = _max; }

        DATA_TYPE *get(const Guid &id) {
            // find
            cmap_it_type it = data_map.find(id);
            // check result, return
            if (it == data_map.end())
                return nullptr;
            return &it->second.data;
        }

        cmap_it_type get_it(const Guid &id) { 
            return data_map.find(id); 
        }

        cmap_it_type set(const Guid &id, 
                         const DATA_TYPE &data,
                         uint32_t _timeout = 0) {
            // check max
            if (data_map.size() >= max)
                return data_map.end();
            // insert
            cmap_insert_type it = data_map.insert(cmap_value_type(
                id,
                DataWrapper(data, (_timeout == 0 ? data_timeout : _timeout))));
            // return iterator
            return it.first;
        }

        void set_timeout(uint32_t _timeout) { 
            data_timeout = _timeout; 
        }

        uint32_t get_timeout() const { 
            return data_timeout; 
        }

        bool remove(const Guid &id) {
            if (data_map.erase(id) > 0)
                return true;
            return false;
        }

        void remove(cmap_it_type it) { 
            data_map.erase(it); 
        }

        static bool update_ts(cmap_it_type it) {
            // update ts
            it->second.ts = time(nullptr);
            // ok
            return true;
        }

        time_t get_ts(const Guid &id) {
            // find
            cmap_it_type it = data_map.find(id);
            // check result, return
            if (it == data_map.end())
                return 0;
            return it->second.ts;
        }

       static  bool update_timeout(cmap_it_type it, uint32_t timeout) {
            // update ts
            it->second.data_timeout = timeout;
            // ok
            return true;
        }

        bool update_ts(const Guid &id) {
            // find
            cmap_it_type it = data_map.find(id);
            // check result, return
            if (it == data_map.end())
                return false;
            // update ts
            it->second.ts = time(nullptr);
            // return ok
            return true;
        }

        bool update_timeout(const Guid &id, uint32_t timeout) {
            // find
            cmap_it_type it = data_map.find(id);
            // check result, return
            if (it == data_map.end())
                return false;
            // update timeout
            it->second.data_timeout = timeout;
            // return ok
            return true;
        }

        void expire(std::vector<DATA_TYPE> &out) {
            // res clear
            out.clear();
            // get ts
            time_t ts = time(nullptr);
            // iterate
            for (cmap_it_type it = data_map.begin(), it_next = it;
                 it != data_map.end(); it = it_next) {
                // next
                ++it_next;
                // check if expired
                if (ts - it->second.ts > it->second.data_timeout) {
                    // copy data part
                    out.push_back(DATA_TYPE(it->second.data));
                    // remove from map
                    data_map.erase(it);
                }
            }
        }

        void expire() {
            // get ts
            time_t ts = time(nullptr);
            // iterate
            for (cmap_it_type it = data_map.begin(), it_next = it;
                 it != data_map.end(); it = it_next) {
                // next
                ++it_next;
                // check if expired
                if (ts - it->second.ts > it->second.data_timeout) {
                    // remove from map
                    data_map.erase(it);
                }
            }
        }

        cmap_it_type begin() { 
            return data_map.begin(); 
        }

        cmap_it_type end() { 
            return data_map.end(); 
        }

        size_t size() const { 
            return data_map.size(); 
        }

        void lock() { 
            mtx.lock(); 
        }

        void unlock() { 
            mtx.unlock(); 
        }

    private:
        uint32_t data_timeout;
        cmap_type data_map;
        std::mutex mtx;
        uint32_t max;
    };

    template<typename DTYPE>
    class WRRItem{
    public:
        WRRItem(DTYPE _item, const char* _id, uint32_t _w): item(_item), weight(_w), old_weight(_w){
            strncpy(id, _id, 65);
            id[64] = 0;
        }

        char id[65];
        DTYPE item;
        uint32_t weight;
        uint32_t old_weight;
    };

    template<typename DTYPE>
    class WRR{
    public:
        using items_map_t = std::vector<WRRItem<DTYPE> >;
        using items_map_it_t = typename items_map_t::iterator;
        using items_map_rit_t = typename items_map_t::reverse_iterator;
        using items_map_val_t = typename items_map_t::value_type;

        /*
         * http://kb.linuxvirtualserver.org/wiki/Weighted_Round-Robin_Scheduling
         *
         */
        WRR(): w_gcd(0), w_max(0), index(-1), cw(0){}

        items_map_val_t* add_item(DTYPE item, const char* id, uint32_t weight){
            items_map_it_t it = items.insert(items.end(), WRRItem<DTYPE>(item, id, weight));
            recalc();
            // return
            return &(*it);
        }

        void recalc(){
            // empty check
            if(items.size() == 0) {
                w_gcd = 0;
                w_max = 0;
                return;
            }

            // calculate gcd
            w_gcd = items[0].weight;
            for(unsigned int i = 1; i<items.size(); i++) w_gcd = gcd(w_gcd, items[i].weight);

            // find max weight
            w_max = 0;
            for(unsigned int i = 0; i<items.size(); i++) if(items[i].weight > w_max) w_max = items[i].weight;

        }

        items_map_val_t* run(){
            /*
               Supposing that there is a server set S = {S0, S1, …, Sn-1};
               W(Si) indicates the weight of Si;
               i indicates the server selected last time, and i is initialized with -1;
               cw is the current weight in scheduling, and cw is initialized with zero;
               max(S) is the maximum weight of all the servers in S;
               gcd(S) is the greatest common divisor of all server weights in S;

               while (true) {
               i = (i + 1) mod n;
               if (i == 0) {
               cw = cw - gcd(S);
               if (cw <= 0) {
               cw = max(S);
               if (cw == 0)
               return nullptr;
               }
               }
               if (W(Si) >= cw)
               return Si;
               }
             */
            // empty check
            if(items.size() == 0) return nullptr;
            // size
            int sz = items.size();
            // counter
            int c = 0;
            // run
            while(true){
                index = (index + 1) % items.size();
                if(index == 0){
                    cw = cw - w_gcd;
                    if(cw <= 0){
                        cw = w_max;
                        // err
                        if(cw == 0) return nullptr;
                    }
                }
                // get item
                WRRItem<DTYPE>& item = items[index];
                // return item (we don't want zero weight items returned)
                if(item.weight > 0 && item.weight >= cw) return &item;
                // inc counter
                ++c;
                // stop if no items match
                if(c >= sz) return nullptr;
            }
            // err
            return nullptr;
        }

        int enable(items_map_val_t* item){
            if(item == nullptr) return 1;
            // skip id already enabled
            if(item->weight > 0) return 2;
            item->weight = item->old_weight;
            recalc();
            return 0;
        }

        int enable(const char* id){
            if(id == nullptr) return 1;
            items_map_it_t it = items.begin();
            int dc = 0;
            while(it != items.end()){
                if(strcmp((*it).id, id) == 0){
                    WRRItem<DTYPE>& item = *it;
                    // skip if already enabled
                    if(item.weight == 0){
                        item.weight = item.old_weight;

                    }
                    ++dc;
                }
                ++it;
            }
            recalc();
            if(dc > 0) return 0;
            return 2;

        }

        int disable(items_map_val_t* item){
            if(item == nullptr) return 1;
            // skip id already disabled
            if(item->weight == 0) return 2;
            item->old_weight = item->weight;
            item->weight = 0;
            recalc();
            return 0;
        }

        int disable(const char* id){
            if(id == nullptr) return 1;
            items_map_it_t it = items.begin();
            int dc = 0;
            while(it != items.end()){
                if(strcmp((*it).id, id) == 0){
                    WRRItem<DTYPE>& item = *it;
                    // skip if already disabled
                    if(item.weight > 0){
                        item.old_weight = item.weight;
                        item.weight = 0;

                    }
                    ++dc;
                }
                ++it;
            }
            recalc();
            if(dc > 0) return 0;
            return 2;

        }

        void clear(){
            items.clear();
        }

        int remove(uint32_t index){
            if(index >= items.size()) return 1;
            items.erase(items.begin() + index);
            recalc();
            return 0;
        }

        int remove(const char* id){
            if(id == nullptr) return 1;
            items_map_it_t it = items.begin();
            int dc = 0;
            while(it != items.end()){
                if(strcmp((*it).id, id) == 0){
                    it = items.erase(it);
                    ++dc;
                }else ++it;
            }
            recalc();
            if(dc > 0) return 0;
            return 2;
            /*
               for(unsigned int i = 0; i<items.size(); i++){
               if(strcmp(items[i].id, id) == 0){
               items.erase(items.begin() + i);
               recalc();
               return 0;

               }
               }
               return 2;
             */
        }

        items_map_val_t* get(const char* id){
            if(id == nullptr) return nullptr;
            // loop
            for(items_map_it_t it = items.begin(); it != items.end(); ++it){
                // compare id
                if(strcmp((*it).id, id) == 0) return &(*it);
            }
            // err
            return nullptr;
        }

        items_map_it_t remove(items_map_it_t it){
            items_map_it_t it_res = items.remove(it);
            recalc();
            return it_res;
        }

        items_map_it_t begin(){
            return items.begin();
        }

        items_map_it_t end(){
            return items.end();
        }
        size_t size() const {
            return items.size();
        }

    private:
        uint32_t gcd(uint32_t m, uint32_t n){
            if(n == 0) return m;
            return gcd(n, m % n);
        }

        items_map_t items;
        uint32_t w_gcd;
        uint32_t w_max;
        int index;
        int cw;

    };

    class StatsManager {
    public:
        using it_t = std::map<uint32_t, mink::Atomic<uint64_t>>::iterator;

        StatsManager() = default;
        virtual ~StatsManager() = default;

        void register_item(uint32_t id) {
            stats_map[id] = mink::Atomic<uint64_t>();
        }

        void inc(uint32_t id, uint64_t val) {
            it_t it = stats_map.find(id);
            if (it != stats_map.end())
                it->second.fetch_add(val);
        }

        void dec(uint32_t id, uint64_t val) {
            it_t it = stats_map.find(id);
            if (it != stats_map.end())
                it->second.fetch_sub(val);
        }

        uint64_t get(uint32_t id) {
            it_t it = stats_map.find(id);
            if (it != stats_map.end())
                return it->second.fetch_add(0);
            return 0;
        }

        uint64_t set(uint32_t id, uint64_t val) {
            it_t it = stats_map.find(id);
            if (it != stats_map.end())
                return it->second.set(val);
            return 0;
        }

    private:
        std::map<uint32_t, mink::Atomic<uint64_t>> stats_map;
    };

    /**
     * FNV 32bit hash (http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx)
     * @param[in]   key Pointer to source data
     * @param[in]   len Length of source data
     * @return      32bit FNV hash
     */
    uint32_t hash_fnv(const void* key, int len);

    /**
     * FNV 32bit hash (http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx)
     * @param[in]   key Pointer to source data
     * @param[in]   len Length of source data
     * @return      32bit FNV hash
     */
    uint32_t hash_fnv1a(const void* key, int len);

    /**
     * FNV-1a 64bit hash (http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx)
     * @param[in]   key Pointer to source data
     * @param[in]   len Length of source data
     * @return      64bit FNV hash
     */
    uint64_t hash_fnv1a_64bit(const void* key, int len);

    /**
     * FNV 32bit hash (http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx)
     * @param[in]   str Pointer to source string data
     * @return      32bit FNV hash
     */
    uint32_t hash_fnv1a_str(const char* key);

    /**
     * FNV 64bit hash (http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx)
     * @param[in]   str Pointer to source string data
     * @return      64bit FNV hash
     */
    uint64_t hash_fnv1a_str_64bit(const char* key);

    /**
     * Auto complete rollback revision sort, used by scandir
     * @param[in]   a   Item one from scandir
     * @param[in]   b   Item two from scandir
     * @return      -1 if a > b, 1 if a < b, or 0
     */
    int _ac_rollback_revision_sort(const struct dirent ** a, const struct dirent ** b);

    /**
     * Auto complete rollback file filtr
     * @param[in]   a   Item provided by scandir
     * @return      1 if valid or 0 otherwise
     */
    int _ac_rollback_revision_filter(const struct dirent* a);

    /**
     * Tokenize string
     * @param[in]       data            Pointer to string
     * @param[out]      result          Pointer to output string list
     * @param[in]       result_max_size Maximum size of output list
     * @param[out]      result_size     Pointer to int which will contain number of tokens in output list
     * @param[in]       keep_quotes     If set, keep quotes if needed
     */
    void tokenize(const std::string* data,
                  std::string* result,
                  int result_max_size,
                  int* result_size,
                  bool keep_quotes);
    /**
     * Run external script
     * @param[in]       script          Pointer to script path
     * @param[out]      result          Pointer to output buffer
     * @param[in]       result_size     Maximum size of output buffer
     * @return          0 for success or error code if error occurred
     */
    int run_external(const char* script, char* result, int result_size);

    /**
     * Run extarnal script and print output
     * @param[in]       script          Pointer to script path
     * @param[in]       ncurses         Ncurses flag (if false, use std::cout)
     *
     */
    void run_external_print(const char* script, bool ncurses);

    /**
     * Run external plugin command handler
     * @param[in]       _module         Pointer to module path
     * @param[in]       arg_names       Pointer to list of name arguments
     * @param[in]       arg_values      Pointer to list of value arguments
     * @param[in]       arg_count       Number of arguments
     * @param[in]       ncurses         Ncurses flag (if false, use std::cout)
     * @return          nullptr, reserved for future use
     */
    void* run_external_method_handler(const char* _module,
                                      const char** arg_names,
                                      const char** arg_values,
                                      int arg_count,
                                      bool ncurses);

    /**
     * Run external plugin method
     * @param[in]       handle          Pointer to module handle
     * @param[in]       method          Pointer to method name
     * @param[in]       args            Pointer to list of arguments
     * @param[in]       argc            Number of arguments
     * @param[in]       ncurses         Ncurses flag (if false, use std::cout)
     * @return          Module dependent
     *
     */
    void* run_external_method(void* handle, const char* method, void** args, int argc, bool ncurses);

    /**
     * Run external plugin command handler
     * @param[in]       _module         Pointer to module path
     * @param[in]       method          Pointer to method name
     * @param[in]       args            Pointer to list of arguments
     * @param[in]       argc            Number of arguments
     * @param[in]       ncurses         Ncurses flag (if false, use std::cout)
     * @return          nullptr, reserved for future use
     */
    void* run_external_method(const char* _module, const char* method, void** args, int argc, bool ncurses);

    /**
     * Load plugin
     * @param[in]       _module         Pointer to module path
     * @return          Plugin handle
     */
    void* load_plugin(const char* _module);

    /**
     * Unload plugin
     * @param[in]       handle          Plugin handle
     */
    void unload_plugin(void* handle);

    /**
     * Implementations of "more"
     * @param[in]       line_c          Number of lines present in data window buffer
     * @param[out]      data_win        Pointer to data window buffer
     * @param[in]       interrupt       Pointer to interrupt flag, if True stop line output
     * @return          interrupted characted or -1
     *
     */
    int cli_more(int line_c, const WINDOW* data_win, const bool* interrupt);

    /**
     * Get file size
     * @param[in]       filename        Filename
     * @return  File size
     */
    int get_file_size(const char *filename);

    /**
     * Load raw file contents
     * @param[in]       filename        Filename
     * @param[out]      result          Pointer to output buffer
     * @param[out]      result_size     Pointer to int which will contain file size
     * @return  0 for success or error code if error occurred
     *
     */
    int load_file(const char *filename, char *result, int *result_size);
}


#endif /* ifndef MINK_UTILS_H_ */
