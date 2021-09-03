/*
 *            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * Copyright (C) 2021  Damir Franusic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GDT_UTILS_H_
#define GDT_UTILS_H_

#include <gdt.h>
#include <map>
#include <pool.h>
#include <mink_utils.h>

// types
typedef mink_utils::PooledVPMap<uint32_t> gdt_vpmap_t;

namespace gdt {

    // fwd declarations
    class ServiceStreamHandlerNew;
    class ServiceMsgManager;
    class ServiceMessage;
    class ServiceMsgManager;
    class ServiceParamFactory;
    class ServiceMessageNext;
    class ServiceMessageDone;

    /**
     * Service parameter data type
     */
    enum ServiceParamType {
        /** Unknown */
        SPT_UNKNOWN     = 0,
        /** General octet stream */
        SPT_OCTETS      = 1,
        /** Unsigned 32bit integer */
        SPT_UINT32      = 2,
        /** Unsigned 64bit integer */
        SPT_UINT64      = 3,
        /** Float */
        SPT_FLOAT       = 4,
        /** Double */
        SPT_DOUBLE      = 5,
        /** C style string */
        SPT_CSTRING     = 6,
        /** Boolean */
        SPT_BOOL        = 7,
        /** Pmink variant */
        SPT_VARIANT     = 8

    };

    /**
     * Service parameter class
     */
    class ServiceParam {
    public:
        /**
         * Default constructor
         */
        ServiceParam();

        /**
         * Destructor
         */
        virtual ~ServiceParam();

        /**
         * Extract parameter data
         * @param[out]  _out    Pointer to output buffer
         * @returnI     0 for success or error code
         */
        virtual int extract(void *_out) = 0;

        /**
         * Print parameter data to standard output
         */
        virtual void std_out();

        /**
         * Set service param data from Variant param
         */
        void set(mink_utils::VariantParam *vparam);

        /**
         * Set parameter data
         * @param[in]       _data       Pointer to parameter data
         * @param[in]       _data_size  Data size
         * @return          0 for success or error code
         */
        virtual int set_data(const void *_data, unsigned int _data_size);

        /**
         * Set parameter data
         * @param[in]       _data       Pointer to file
         * @param[in]       _file_size  File size
         * @retur           0 for success or error code
         */
        virtual int set_data(FILE *_data, unsigned int _file_size);

        /**
         * Get pointer to parameter data
         * @return  Pointer to parameter data
         */
        unsigned char *get_data();

        /**
         * Get data pointer
         */
        unsigned char *get_data_p();

        /**
         * Set data pointer
         */
        void set_data_p(unsigned char *_data_p);

        /**
         * Set data pointer to internal buffer
         */
        void reset_data_p();

        /**
         * Get size of parameter data
         * @return  Parameter data size
         */
        int get_data_size();

        /**
         * Increment total data size
         * @param[in]       _inc    Increment
         */
        void inc_total_data_size(unsigned int _inc);

        /**
         * Get total data size
         * @return  Total data size including all fragments
         */
        int get_total_data_size() const;

        /**
         * Get service parameter data type
         * @return  Service parameter data type
         */
        ServiceParamType get_type() const;

        /**
         * Set parameter id
         * @param[in]   _id     Parameter id
         */
        void set_id(uint32_t _id);

        /**
         * Set parameter index
         * @param[in]    idx     Parameter index
         */
        void set_index(uint32_t idx);

        /**
         * Get parameter id
         * @return  Parameter id
         */
        uint32_t get_id();

        /**
         * Get pointer to parameter id
         * @return  Pointer to parameter id
         */
        uint32_t *get_idp();

        /**
         * Reset parameter values
         */
        void reset();

        /**
         * Set thread safety
         * @param[in]   Thread safety flag
         */
        void set_thread_safety(bool _thread_safe);

        /**
         * Set service message manager
         * @param[in]   Pointer to service massage manager
         */
        void set_param_factory(ServiceParamFactory *_pfact);

        /**
         * Get fragmentation flag
         */
        bool is_fragmented() const;

        /**
         * Get pointer to fragmentation flag
         */
        bool *get_fragmentation_p();

        /**
         * Set fragmentation flag
         */
        void set_fragmented(bool _fragmented);

        /**
         * Get param id index
         */
        uint32_t get_index() const;

        /**
         * Get variant param type
         */
        int get_extra_type() const;

        /**
         * Set variant param type
         */
        void set_extra_type(int type);

        /**
         * Get fragment index
         */
        int get_fragment_index() const;

        void set_callback(GDTEventType type, GDTCallbackMethod *cback);
        bool process_callback(GDTEventType type, GDTCallbackArgs *args);
        void clear_callbacks();

        // friend with ServiceMsgManager
        friend class ServiceMsgManager;
        friend class ServiceMessageNext;
        friend class ServiceMessage;
        friend class ServiceStreamHandlerNext;
        friend class ServiceStreamHandlerDone;
        friend class ServiceStreamHandlerNew;

    protected:
        /** Lock mutex */
        void lock();
        /** Unlock mutex */
        void unlock();
        void fragment(const void *_data, unsigned int _data_size);
        /** Parameter data buffer */
        unsigned char data[256];
        /** Parameter data pointer */
        unsigned char *data_p;
        /** Input data pointer */
        const void *in_data_p;
        /** Parameter data size */
        unsigned int data_size;
        /** Total data size including all fragments */
        unsigned int total_data_size;
        /** Parameter type */
        ServiceParamType type;
        /** Parameter id */
        uint32_t id;
        /** Parameter index */
        uint32_t index;
        /** Extra parameter type */
        int extra_type;
        /** Mutex */
        pthread_mutex_t mtx;
        /** Thread safe flag */
        bool thread_safe;
        /** Fragmentation flag */
        bool fragmented;
        /** Linked params/fragments */
        std::vector<ServiceParam *> linked;
        unsigned int linked_index;
        /** Pointer to service param factory */
        ServiceParamFactory *param_fctry;
        GDTCallbackHandler cb_handler;
        int fragments;
        int fragment_index;
        /** Fragmentation finished, last fragment */
        static bool FRAGMENTATION_DONE;
        /** Fragmentation in progress, more fragments coming */
        static bool FRAGMENTATION_NEXT;

        // data read callback
        typedef int (*param_data_cb_type)(ServiceParam *sc_param, const void *in,
                                          int in_size);
        param_data_cb_type param_data_cb;

        static int param_data_file(ServiceParam *sc_param, const void *in,
                                   int in_size);
        static int param_data_default(ServiceParam *sc_param, const void *in,
                                      int in_size);
    };

    /**
     * Unknown service parameter class
     */
    class ServiceParamVARIANT : public ServiceParam {
    public:
        ServiceParamVARIANT();  /**< Default constructor */
        ~ServiceParamVARIANT(); /**< Destructor */

        /**
         * Extract parameter data
         * @param[out]  _out    Pointer to output buffer
         * @return      0 for success or error code
         */
        int extract(void *_out) override;

        /**
         * Set parameter data
         * @param[in]   _data       Pointer to parameter data
         * @param[in]   _data_size  Data ssize
         * @return      0 for success or error code
         */

        int set_data(void *_data, unsigned int _data_size);

        /**
         * Print parameter data to standard output
         */
        void std_out() override;
    };

    /**
     * Unknown service parameter class
     */
    class ServiceParamUNKNOWN : public ServiceParam {
    public:
        ServiceParamUNKNOWN();  /**< Default constructor */
        ~ServiceParamUNKNOWN(); /**< Destructor */

        /**
         * Extract parameter data
         * @param[out]  _out    Pointer to output buffer
         * @return      0 for success or error code
         */
        int extract(void *_out) override;

        /**
         * Set parameter data
         * @param[in]   _data       Pointer to parameter data
         * @param[in]   _data_size  Data ssize
         * @return      0 for success or error code
         */

        int set_data(void *_data, unsigned int _data_size);

        /**
         * Print parameter data to standard output
         */
        void std_out() override;
    };

    /**
     * Boolean service parameter class
     */
    class ServiceParamBOOL : public ServiceParam {
    public:
        ServiceParamBOOL();  /**< Default constructor */
        ~ServiceParamBOOL(); /**< Destructor */

        /**
         * Extract parameter data
         * @param[out]  _out    Pointer to output buffer
         * @return      0 for success or error code
         */
        int extract(void *_out) override;

        /**
         * Set bool value
         * @param[in]   _data   Parameter data
         * @return      0 for success or error code
         */
        int set_bool(bool _data);

        /**
         * Print parameter data to standard output
         */
        void std_out() override;
    };

    /**
     * Unsigned 32bit integer service parameter class
     */
    class ServiceParamUINT32 : public ServiceParam {
    public:
        ServiceParamUINT32();  /**< Default constructor */
        ~ServiceParamUINT32(); /**< Destructor */

        /**
         * Extract parameter data
         * @param[out]  _out    Pointer to output buffer
         * @return      0 for success or error code
         */
        int extract(void *_out) override;

        /**
         * Set unsigned 32bit integer value
         * @param[in]   _data   Parameter data
         * @return      0 for success or error code
         */
        int set_uint32(uint32_t _data);

        /**
         * Print parameter data to standard output
         */
        void std_out() override;
    };

    /**
     * Unsigned 64bit integer service parameter class
     */
    class ServiceParamUINT64 : public ServiceParam {
    public:
        ServiceParamUINT64();  /**< Default constructor */
        ~ServiceParamUINT64(); /**< Destructor */

        /**
         * Extract parameter data
         * @param[out]  _out    Pointer to output buffer
         * @return      0 for success or error code
         */
        int extract(void *_out) override;

        /**
         * Set unsigned 64bit integer value
         * @param[in]   _data   Parameter data
         * @return      0 for success or error code
         */
        int set_uint64(uint64_t _data);

        /**
         * Print parameter data to standard output
         */
        void std_out() override;
    };

    /**
     * C style string service parameter class
     */
    class ServiceParamCString : public ServiceParam {
    public:
        ServiceParamCString();  /**< Default constructor */
        ~ServiceParamCString(); /**< Destructor */

        /**
         * Extract parameter data
         * @param[out]  _out    Pointer to output buffer
         * @return      0 for success or error code
         */
        int extract(void *_out) override;

        /**
         * Set C style string value
         * @param[in]   cstring     Pointer to C style string
         */
        void set_cstring(char *cstring);
    };

    /**
     * General octet stream service parameter class
     */
    class ServiceParamOctets : public ServiceParam {
    public:
        ServiceParamOctets();  /**< Default constructor */
        ~ServiceParamOctets(); /**< Destructor */

        /**
         * Extract parameter data
         * @param[out]  _iout   Pointer to output buffer
         * @return      0 for success or error code
         */
        int extract(void *_out) override;

        /**
         * Print parameter data to standard output
         */
        void std_out() override;
    };

    /**
     * Service parameter factory class
     */
    class ServiceParamFactory {
    public:
        /**
         * Constructor
         * @param[in]   _pooled     Parameter pooling flag
         * @param[in]   pool_size   Pool size
         */
        ServiceParamFactory(bool _pooled = true, bool _th_safe = false,
                            unsigned int pool_size = 100);

        /**
         * Destructor
         */
        ~ServiceParamFactory();

        /**
         * Create new service parameter
         * @param[in]   param_type  Service parameter type
         * @return      Pointer to service parameter
         */
        ServiceParam *new_param(ServiceParamType param_type = gdt::SPT_UNKNOWN);

        /**
         * Free service parameter
         * @param[in]   param   Pointer to service parameter
         * @return      0 for success or error code
         */
        int free_param(ServiceParam *param);

    private:
        /** Pooling flag */
        bool pooled;
        /** SPT_CSTRING memory pool */
        memory::Pool<ServiceParamCString, true>
            cstr_pool;
        /** SPT_OCTETS memory pool */
        memory::Pool<ServiceParamOctets, true>
            oct_pool;
        /** SPT_UINT32 memory pool */
        memory::Pool<ServiceParamUINT32, true>
            uint32_pool;
        /** SPT_UINT64 memory pool */
        memory::Pool<ServiceParamUINT64, true>
            uint64_pool;
        /** SPT_UNKNOWN memory pool */
        memory::Pool<ServiceParamUNKNOWN, true>
            unknown_pool;
        /** SPT_BOOL memory pool */
        memory::Pool<ServiceParamBOOL, true>
            bool_pool;
        /** SPT_VARIANT memory pool */
        memory::Pool<ServiceParamVARIANT, true>
            var_pool;
    };

    /**
     * Service parameter ID <--> TYPE mapping class
     */
    class ParamIdTypeMap {
    public:
        ParamIdTypeMap();  /**< Default constructor */
        ~ParamIdTypeMap(); /**< Destructor */

        /**
         * Add new mapping
         * @param[in]   _id     Service parameter id
         * @param[in]   _type   Service parameter type
         * @return      0 for success or error code
         */
        int add(uint32_t _id, ServiceParamType _type);

        /**
         * Remove mapping
         * @param[in]   id      Service parameter id
         * @return      0 for success or error code
         */
        int remove(uint32_t id);

        /**
         * Get mapping
         * @param[in]   id      Service parameter id
         * @return      Service parameter type
         */
        ServiceParamType get(uint32_t id);

        /**
         * Clear all mappings
         */
        int clear();

    private:
        /** ID <--> TYPE map */
        std::map<uint32_t, ServiceParamType> idtmap;
    };

    class ServiceStreamHandlerNext : public gdt::GDTCallbackMethod {
    public:
        ServiceStreamHandlerNext();
        // handler method for ServiceMessage streams
        void run(gdt::GDTCallbackArgs *args);
        ServiceStreamHandlerNew *ssh_new;
    };

    class ServiceStreamHandlerDone : public gdt::GDTCallbackMethod {
    public:
        ServiceStreamHandlerDone();
        // handler method for ServiceMessage streams
        void run(gdt::GDTCallbackArgs *args);
        ServiceStreamHandlerNew *ssh_new;
    };

    class ServiceStreamHandlerNew : public gdt::GDTCallbackMethod {
    public:
        ServiceStreamHandlerNew();
        // handler method for ServiceMessage streams
        void run(gdt::GDTCallbackArgs *args);
        ServiceStreamHandlerNext ssh_next;
        ServiceStreamHandlerDone ssh_done;
        ServiceMsgManager *smsg_m;
        GDTCallbackMethod *usr_stream_hndlr;
    };

    class ServiceStreamNewClient : public gdt::GDTCallbackMethod {
    public:
        ServiceStreamNewClient();
        // handler method
        void run(gdt::GDTCallbackArgs *args);
        // service message manager
        gdt::ServiceMsgManager *smsg_m;
        // user stream nc handler
        GDTCallbackMethod *usr_stream_nc_hndlr;
        // user stream handler
        GDTCallbackMethod *usr_stream_hndlr;
    };

    class ServiceMessageDone : public gdt::GDTCallbackMethod {
    public:
        ServiceMessageDone();
        void run(gdt::GDTCallbackArgs *args);
        ServiceMessage *smsg;
        GDTCallbackMethod *usr_method;
        int status;
    };

    class ServiceMessageNext : public gdt::GDTCallbackMethod {
    public:
        void run(gdt::GDTCallbackArgs *args);
        ServiceMessage *smsg;
        unsigned int pc;
        unsigned int pos;
        unsigned int pindex;
    };

    class ServiceMessageAsyncDone : public gdt::GDTCallbackMethod {
    public:
        void run(gdt::GDTCallbackArgs *args);
    };

    /**
     * Service message class
     */
    class ServiceMessage {
    public:
        ServiceMessage();  /**< Default constructor */
        ~ServiceMessage(); /**< Destructor */

        /**
         * Add service parameter
         * @param[in]   id              Service parameter id
         * @param[in]   param           Pointer to service parameter
         * @param[in]   index           Parameter id index
         * @return      0 for success or error code
         */
        int add_param(uint32_t id, ServiceParam *param, uint32_t index = 0);

        /**
         * Remove service parameter
         * @param[in]   id              Service parameter id
         * @return      0 for success or error code
         */
        int remove_param(uint32_t id);

        /**
         * Get service parameter(s) by id
         * @param[in]   id              Service parameter id
         * @param[out]  out             Pointer to output vector
         * @return      0 for success or error code
         *
         */
        int get_param(uint32_t id, std::vector<ServiceParam *> *out);

        /**
         * Reset service message values
         * @return      0 for success or error code
         */
        int reset();

        /**
         * Set ID <--> TYPE mapping
         * @param[in]   idtm            Pointer to IDT mapping
         *
         */
        void set_idt_map(ParamIdTypeMap *idtm);

        /**
         * Get service id
         * @return      Service id
         */
        uint32_t get_service_id();

        /**
         * Get pointer to service id
         * @return      Pointer to service id
         */
        uint32_t *get_service_idp();

        /**
         * Get service action
         * @return      Service action
         */
        uint32_t get_service_action();

        /**
         * Get pointer to service action
         * @return      Pointer to service action
         */
        uint32_t *get_service_actionp();

        /**
         * Set service id
         * @param[in]   _service_id             Service id
         *
         */
        void set_service_id(uint32_t _service_id);

        /**
         * Set service action
         * @param[in]   _service_action         Service action
         *
         */
        void set_service_action(uint32_t _service_action);

        /**
         * Get service message param
         * @param[in]   id                      Parameter id
         * @param[in]   index                   Parameter index
         * @param[in]   fragment                Parameter fragment
         * @param[in]   context                 Parameter context
         *
         * @return      Parameter pointer or NULL if not found
         */
        mink_utils::VariantParam *vpget(uint32_t id, 
                                        uint32_t index = 0,
                                        uint32_t fragment = 0,
                                        uint32_t context = 0);

        /**
         * Set string service message param
         * @param[in]   id                      Parameter id
         * @param[in]   s                       Parameter value
         * @param[in]   index                   Parameter index
         * @param[in]   fragment                Parameter fragment
         * @param[in]   context                 Parameter context
         *
         * @return      Parameter pointer or NULL if not found
         */
        mink_utils::VariantParam *vpset(uint32_t id, 
                                        const std::string &s,
                                        uint32_t index = 0,
                                        uint32_t fragment = 0,
                                        uint32_t context = 0);

        /**
         * Get all service message parameters
         * @return      Pointer to parameter vector
         *
         */
        std::vector<ServiceParam *> *get_param_map();

        /**
         * Get service message stream done handler
         * @return      Pointer to stream handler
         */
        ServiceMessageDone *get_sdone_hndlr();

        /**
         * Get service message stream next handler
         * @eturn       Pointer to stream handler
         */
        ServiceMessageNext *get_snext_hndlr();

        /**
         * Wait for stream finished semaphore
         * @return      0 for success or error code
         */
        int signal_wait();

        /**
         * Signal stream finished semaphore
         * @return      0 for success or error code
         *
         */
        int signal_post();

        /**
         * Set service message manager
         * @param[in]   _smsg_m         Pointer to service message manager
         */
        void set_smsg_manager(ServiceMsgManager *_smsg_m);

        /**
         * Get service message manager
         * @return      Pointer to service mesage manager
         */
        ServiceMsgManager *get_smsg_manager();

        /**
         * Get current fragmented param
         * @return      Pointer to current fragmented param
         */
        ServiceParam *get_frag_param();

        /**
         * Set current fragmented param
         * @param[in]   _frag_param     Pointer to new fragmented param
         */
        void set_frag_param(ServiceParam *_frag_param);

        /**
         * Get complete flag
         */
        bool is_complete();

        /**
         * Set complete flag
         */
        bool set_complete(bool _is_complete);
        bool set_auto_free(bool _auto_free);
        bool get_auto_free() const;
        void set_callback(GDTEventType type, GDTCallbackMethod *cback);
        bool process_callback(GDTEventType type, GDTCallbackArgs *args);
        void clear_callbacks();
        /** General param list */
        mink_utils::ParameterMap<uint32_t, void *> params;
        mink_utils::PooledVPMap<uint32_t> vpmap;
        bool missing_params;

    private:
        /** IDT mapping */
        ParamIdTypeMap *idt_map;
        /** Service parameter list */
        std::vector<ServiceParam *> tlvs; /**< Service parameter list */
        /** Service id */
        uint32_t service_id;
        /** Service action */
        uint32_t service_action;
        /** Stream done handler */
        ServiceMessageDone msg_done;
        /** Stream next handler */
        ServiceMessageNext msg_next;
        /** Service message manager */
        ServiceMsgManager *smsg_m;
        /** Stream done semaphore */
        sem_t smsg_sem;
        /** New param received semaphore */
        sem_t new_param_sem;
        /** Current fragmented param */
        ServiceParam *frag_param;
        /** Complete flag */
        mink::Atomic<uint8_t> complete;
        /** Received param count */
        mink::Atomic<uint32_t> recv_param_count;
        GDTCallbackHandler cb_handler;
        bool auto_free;
    };

    /**
     * Stats
     */
    enum SrvcSatsType{
        SST_RX_SMSG_POOL_EMPTY          = 1,
        SST_RX_SPARAM_POOL_EMPTY        = 2
    };

    /**
     * Smsg related GDT stream params
     */
    enum SmsgParamType{
        SMSG_PT_SMSG                    = 0,
        SMSG_PT_PASS                    = 1
    };

    /**
     * Service message manager
     */
    class ServiceMsgManager {
    public:
        /**
         * Constructor
         * @param[in]   _idt_map                        Pointer to IDT mapping
         * @param[in]   _new_msg_hndlr                  Handler for SERVICE MESSAGE STARTING
         *                                              event
         * @param[in]   _nonsrvc_stream_hndlr           Handler for NON SERVICE
         * MESSAGE
         * @param[in]   pool_size                       Service message faatory pool size
         * @param[in]   param_pool_size                 Param factory pool size (per
         * type)
         */
        ServiceMsgManager(ParamIdTypeMap *_idt_map,
                          GDTCallbackMethod *_new_msg_hndlr,
                          GDTCallbackMethod *_nonsrvc_stream_hndlr = NULL,
                          unsigned int pool_size = 100,
                          unsigned int param_pool_size = 1000);

        /** no copy constructor */
        ServiceMsgManager(const ServiceMsgManager &o) = delete;
        /** no assignment operator */
        ServiceMsgManager &operator=(const ServiceMsgManager &o) = delete;

        /**
         * Destructor
         */
        ~ServiceMsgManager();

        /**
         * Setup service message event handlers for GDT client
         * @param[in]   gdtc                    Pointer to GDT client
         *
         */
        void setup_client(GDTClient *gdtc);

        /**
         * Setup service message event handlers for GDT server
         * @param[in]   gdts                    Pointer to GDT session
         * @param[in]   _usr_stream_nc_hndlr    Pointer to user handler for NEW
         *                                      CLIENT event
         * @param[in]   _usr_stream_hndlr       Pointer to user handler for NEW STREAM
         * event
         *
         */
        void setup_server(GDTSession *gdts,
                          gdt::GDTCallbackMethod *_usr_stream_nc_hndlr,
                          gdt::GDTCallbackMethod *_usr_stream_hndlr);

        /**
         * Send service message
         * @param[in]   msg                     Pointer to service message
         * @param[in]   gdtc                    Pointer to GDT client
         * @param[in]   dtype                   Pointer to destination daemon type C string
         * @param[in]   did                     Pointer to destination daemon id C string
         * @param[in]   async                   Async flag
         * @param[in]   on_sent                 Pointer to message sent event handler used only
         *                                      in async mode only
         * @return      0 for success or error code
         */
        int send(ServiceMessage *msg, GDTClient *gdtc, const char *dtype,
                 const char *did, bool async = false,
                 gdt::GDTCallbackMethod *on_sent = &cb_async_done);

        /**
         * Sync sparam map to reflect vpmap
         * @param[in]   msg                     Pointer to service message
         * @param[in]   pmap                    List of extra service params to
                                                include along with vpmap params
         * @return      0 for success of error code
         */
        int vpmap_sparam_sync(ServiceMessage *msg,
                              const std::vector<ServiceParam *> *pmap = NULL);

        /**
         * Create new service message
         * @return      Pointer to service message
         */
        ServiceMessage *new_smsg();

        /**
         * Free service message
         * @param[in]   msg             Service message pointer
         * @param[in]   params_only     Free only params flag
         * @param[in]   clear_vpmap     Clear vpmap flag
         * @return      0 for success or error code
         */
        int free_smsg(ServiceMessage *msg, bool params_only = false,
                      bool clear_vpmap = true);

        /**
         * Get service parameter factory
         * @return      Pointer to service parameter factory
         */
        ServiceParamFactory *get_param_factory();

        /**
         * Get IDT mapping
         * @return      Pointer to IDT mapping
         */
        ParamIdTypeMap *get_idt_map();

        /**
         * Make service message available
         * @param[in]   msg     Pointer to service message
         * @return      0 for success or error code
         */
        // int publish_active_msg(ServiceMessage* msg);

        /**
         * Generate new random UUID
         */
        void generate_uuid(unsigned char *out);

        /**
         * Get ServiceMessage NEW STREAM handler
         */
        gdt::GDTCallbackMethod *get_srvcs_hndlr();

        /**
         * Get ServiceMessage NEW CLIENT handler
         */
        gdt::GDTCallbackMethod *get_srvcs_nc_hndlr();

        void set_new_msg_handler(GDTCallbackMethod *hndlr);
        void set_msg_err_handler(GDTCallbackMethod *hndlr);
        bool process_callback(GDTEventType type, GDTCallbackArgs *args);

        /** MAX parameter size constant */
        static const int MAX_PARAMS_SIZE = 768;
        mink_utils::StatsManager stats;

    private:
        /** Random number generator */
        mink_utils::Randomizer random_gen;
        /** Service message semaphore */
        sem_t q_sem;
        /** IDT mapping */
        ParamIdTypeMap *idt_map;
        /** Service message memory pool */
        memory::Pool<ServiceMessage, true> msg_pool;
        /** Service parameter factory */
        ServiceParamFactory *param_factory;
        /** Service message new stream handler */
        ServiceStreamHandlerNew srvcs_hndlr;
        /** New client stream handler (GDT server) */
        ServiceStreamNewClient srvcs_nc;
        GDTCallbackHandler cb_handler;
        static ServiceMessageAsyncDone cb_async_done;
    };
}


#endif /* GDT_UTILS_H_ */
