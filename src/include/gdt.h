/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef GDT_H_
#define GDT_H_

#include <vector>
#include <map>
#include <deque>
#include <pthread.h>
#include <semaphore.h>
#include <endian.h>
#include <gdt_def.h>
#include <pool.h>
#include <atomic.h>
#include <ring.h>
#include <mink_utils.h>
#include <poll.h>
#include <sctp.h>

namespace gdt {
    /**
     * current GDT version
     */
    const int _GDT_VERSION_ = 1;

    /**
     * GDT Stream type
     */
    enum GDTStreamType {
        /** Unknown stream */
        GDT_ST_UNKNOWN              = -1,
        /** Stateful stream */
        GDT_ST_STATEFUL             = 0x00,
        /** Stateless stream (single packet, no stream) */
        GDT_ST_STATELESS            = 0x01,
        /** Stateless stream without ACK (single packet) */
        GDT_ST_STATELESS_NO_REPLY   = 0x02,
    };

    /**
     * GDT Stream initiator type
     */
    enum GDTStreamInitiatorType{
        /** Stream started locally */
        GDT_SIT_LOCAL   = 0,
        /** Stream started remotely */
        GDT_SIT_REMOTE  = 1
    };

    /**
     * GDT Event type
     */
    enum GDTEventType {
        /** New client connection */
        GDT_ET_CLIENT_NEW               = 0,
        /** Client terminated */
        GDT_ET_CLIENT_TERMINATED        = 1,
        /** New stream starting */
        GDT_ET_STREAM_NEW               = 2,
        /** Next packet in stream (GDT_ST_STATEFUL and GDT_ST_STATELESS) */
        GDT_ET_STREAM_NEXT              = 3,
        /** Stream ending */
        GDT_ET_STREAM_END               = 4,
        /** Stream ending */
        GDT_ET_STREAM_TIMEOUT           = 5,
        /** New datagram */
        GDT_ET_DATAGRAM                 = 6,
        /** Payload sent */
        GDT_ET_PAYLOAD_SENT             = 7,
        /** Client idle */
        GDT_ET_CLIENT_IDLE              = 8,
        /** Client terminating */
        GDT_ET_CLIENT_TERMINATING       = 9,
        /** Client re-connecting */
        GDT_ET_CLIENT_RECONNECTING      = 10,
        /** Client re-connected */
        GDT_ET_CLIENT_RECONNECTED       = 11,
        /** Heartbeat missed */
        GDT_ET_HEARTBEAT_MISSED         = 12,
        /** Heartbeat received */
        GDT_ET_HEARTBEAT_RECEIVED       = 13,
        /** Client object created */
        GDT_ET_CLIENT_CREATED           = 100,
        /** Client object destroyed */
        GDT_ET_CLIENT_DESTROYED         = 101,
        /** New ServiceMessage starting */
        GDT_ET_SRVC_MSG_NEW             = 14,
        /** New ServiceMessage short parameter */
        GDT_ET_SRVC_SHORT_PARAM_NEW     = 15,
        /** New ServiceMessage fragmented parameter stream starting */
        GDT_ET_SRVC_PARAM_STREAM_NEW    = 16,
        /** Next ServiceMessage parameter fragment */
        GDT_ET_SRVC_PARAM_STREAM_NEXT   = 17,
        /** Last ServiceMessage parameter fragment */
        GDT_ET_SRVC_PARAM_STREAM_END    = 18,
        /** ServiceMessage ending, all data received */
        GDT_ET_SRVC_MSG_COMPLETE        = 19,
        /** ServiceMessage error, missing or similar */
        GDT_ET_SRVC_MSG_ERROR           = 20
    };

    /**
     * Connection direction
     */
    enum GDTConnectionDirection {
        /** Unknown/ERR */
        GDT_CD_UNKNOWN  = -1,
        /** INBOUND */
        GDT_CD_INBOUND  = 0x00,
        /** OUTBOUND */
        GDT_CD_OUTBOUND = 0x01
    };

    /**
     * Sequence type
     */
    enum GDTSequenceFlag {
        /** Unknown/ERR */
        GDT_SF_UNKNOWN          = -1,
        /** Sequence starting */
        GDT_SF_START            = 0,
        /** Sequence continuing */
        GDT_SF_CONTINUE         = 1,
        /** Sequence ending */
        GDT_SF_END              = 2,
        /** Single packet sequence */
        GDT_SF_STATELESS        = 4,
        /** Sequence continuing and waiting for peer or timeout */
        GDT_SF_CONTINUE_WAIT    = 6,
        /** Heartbeat */
        GDT_SF_HEARTBEAT        = 7,
    };

    /**
     * Callback Arguments type
     */
    enum GDTCBArgsType {
        /** Input arguments */
        GDT_CB_INPUT_ARGS   = 0,
        /** Output arguments */
        GDT_CB_OUTPUT_ARGS  = 1

    };

    /**
     * Callback Argument type
     */
    enum GDTCBArgType {
        /** INBOUND GDT message */
        GDT_CB_ARG_IN_MSG       = 0,
        /** INBOUND GDT message session id */
        GDT_CB_ARG_IN_MSG_ID    = 1,
        /** Client connection */
        GDT_CB_ARG_CLIENT       = 2,
        /** Stream connection */
        GDT_CB_ARG_STREAM       = 3,
        /** OUTBOUND GDT message */
        GDT_CB_ARG_OUT_MSG      = 4,
        /** OUTBOUND SCTP payload */
        GDT_CB_ARG_PAYLOAD      = 5,
        /** GDT Body indicator */
        GDT_CB_ARG_BODY         = 6,
        /** INBOUND raw packet bytes */
        GDT_CB_ARG_IN_RAW       = 7,
        /** INBOUND raw packet length */
        GDT_CB_ARG_IN_RAW_LEN   = 8,
        /** Switch OUTPUT data pointers from INPUT to PAYLOAD  */
        GDT_CB_ARG_MEM_SWITCH   = 9,
        /** Heartbeat info object */
        GDT_CB_ARG_HBEAT_INFO   = 10,
        /** ServiceMessage parameter */
        GDT_CB_ARGS_SRVC_PARAM  = 11,
        /** ServiceMessage */
        GDT_CB_ARGS_SRVC_MSG    = 12
    };

    /**
     * GDT Statistics type
     */
    enum GDTStatsType {
        /** INBOUND statistics */
        GDT_INBOUND_STATS   = 0,
        /** OUTBOUND statistics */
        GDT_OUTBOUND_STATS  = 1
    };

    /*
     * GDT Routing algorithm
     */
    enum GDTRoutingAlgorithm{
        /** Automatic, use first from the list (no cfgd required) */
        GDT_RA_AUTO    = 0,
        /** Weighted Round Robin (cfgd required) */
        GDT_RA_WRR     = 1
    };


    // fwd declaration
    class GDTClient;
    class GDTPayload;
    class GDTSession;

    /**
     * GDT Callback arguments class
     *
     */
    class GDTCallbackArgs {
    private:
        /** input argument list */
        std::map<GDTCBArgType, void*> in_args;
        /** output argument list */
        std::map<GDTCBArgType, void*> out_args;

    public:
        GDTCallbackArgs();

        /**
         * Add argument to list
         * @param[in]   _args_type  List which argument will be inserted into
         * @param[in]   _arg_type   Type of argument
         * @param[in]   _arg        Pointer to argument
         */
        void add_arg(GDTCBArgsType _args_type, GDTCBArgType _arg_type, void *_arg);

        /**
         * Get argument from list
         * @param[in]   _args_type  List used for search operation
         * @param[in]   _arg_type   Type of argument
         * @return      Pointer to argument or NULL if not found
         */
        void* get_arg(GDTCBArgsType _args_type, GDTCBArgType _arg_type);

        /**
         * Get argument from list
         * @param[in]   _args_type  List used for search operation
         * @param[in]   _arg_type   Type of argument
         * @return      Pointer to argument or NULL if not found
         */
        template <typename T>
        T *get(GDTCBArgsType _args_type, GDTCBArgType _arg_type) {
            void *p = get_arg(_args_type, _arg_type);
            if (!p)
                return NULL;
            return static_cast<T *>(p);
        }

        /**
         * Clear arguments from the list
         * @param[in]   _args_type  List which will be cleared
         *
         */
        void clear_args(GDTCBArgsType _args_type);

        /**
         * Clear arguments from the both input and output lists
         */
        void clear_all_args();

        /**
         * Get number of arguments currently present in the list
         * @param[in]   _arg_type   List which will be queried
         */
        int get_arg_count(GDTCBArgsType _arg_type);
    };

    /**
     * GDT Callback method
     *
     */
    class GDTCallbackMethod {
    public:
        GDTCallbackMethod();
        virtual ~GDTCallbackMethod();

        /**
         * Run callback method
         * @param[in]   args    Pointer to callback arguments
         */
        virtual void run(GDTCallbackArgs *args);

        /**
         * Cleanup after callback method
         * @param[in]   args    Pointer to callback arguments
         */
        virtual void cleanup(GDTCallbackArgs *args);

        /**
         * Set continue callback method
         * @param[in]   cb      Pointer to callback method
         */
        void set_continue_callback(GDTCallbackMethod *cb);

        /**
         * Remove continue callback method
         */
        void remove_continue_callback();

        /**
         * Run continue handler
         * @param[in]   args    Pointer to callback arguments
         */
        void run_continue(GDTCallbackArgs *args);

    private:
        /** continue callback */
        GDTCallbackMethod *cb_cont;
    };

    class GDTCallbackHandler {
    private:
        /** Callback method map */
        std::map<GDTEventType, GDTCallbackMethod*> callback_map;
    public:
        GDTCallbackHandler();
        ~GDTCallbackHandler();

        /**
         * Set callback
         * @param[in]   type    Event type to attach callback to
         * @param[in]   method  Pointer to callbacl method
         */
        void set_callback(GDTEventType type, GDTCallbackMethod *method);

        /**
         * Get callback
         * @param[in]   type    Event type to search for
         * @return      Pointer to callback method or NULL if not found
         */
        GDTCallbackMethod* get_callback(GDTEventType type);

        /**
         * Remove callback
         * @param[in]   type    Event type to search for and remove
         *
         */
        void remove_callback(GDTEventType type);

        /**
         * Clear all callabcks
         */
        void clear();

        /**
         * Execute callback method
         * @param[in]   type    Event type to search for
         * @param[in]   args    Pointer to callback arguments passed to callback run method
         * @return      True if callback method is found or False otherwise
         */
        bool process_callback(GDTEventType type, GDTCallbackArgs *args);

        /**
         * Cleanup callback method
         * @param[in]   type    Event type to search for
         * @param[in]   args    Pointer to callback arguments passed to callback cleanup method
         * @return      True if callback method is found or False otherwise
         */
        bool process_cleanup(GDTEventType type, GDTCallbackArgs *args);
    };

    /**
     * GDT Stream
     */
    class GDTStream {
    friend class GDTClient;
    friend class GDTStateMachine;
    friend class GDTSession;
    private:
        /** Random number generator */
        mink_utils::Randomizer *random_generator;
        /** Stream UUID */
        unsigned char uuid[16];
        /** Stream sequence number */
        uint32_t sequence_num;
        /** Reply received flag */
        bool sequence_reply_received;
        /** Sequence position flag */
        GDTSequenceFlag sequence_flag;
        /** Client connection */
        GDTClient *client;
        /** Stream callback event handler */
        GDTCallbackHandler callback_handler;
        /** Stream destination type */
        char destination_type[50];
        /** Stream destination id */
        char destination_id[50];
        /** Stream GDTMessage output buffer */
        asn1::GDTMessage *gdt_message;
        /** Stream GDTPayload output buffer */
        GDTPayload *gdt_payload;
        /** Unix timestamp of Last stream update */
        time_t timestamp;
        /** General parameter map */
        std::map<uint32_t, void*> params;
        /** Stream timeout flag */
        bool timeout;
        /** Linked stream (same guid) */
        GDTStream *linked_stream;
        /** Last stream side used (duplicate streams, same guids) */
        GDTStream *last_linked_side;
        /** Stream initiator */
        GDTStreamInitiatorType initiator;

    public:
        GDTStream();

        /**
         * Custom constructor which sets random number generator used in UUID generation
         * @param[in]   _random_generator   Pointer to random number generator
         */
        GDTStream(mink_utils::Randomizer *_random_generator);
        ~GDTStream();

        /**
         * Set GDTMessage output buffer
         * @param[in,out]   _gdt_message   Pointer to GDTMessage
         */
        void set_gdt_message(asn1::GDTMessage *_gdt_message);

        /**
         * Get GDTMessage output buffer
         * @return  Pointer to GDTMessage output buffer
         */
        asn1::GDTMessage* get_gdt_message();

        /**
         * Set GDTPayload output buffer
         * @param[in,out]   _gdt_payload   Pointer to GDTPayload output buffer
         */
        void set_gdt_payload(GDTPayload *_gdt_payload);

        /**
         * Get GDTPayload output buffer
         * @return  Pointer to GDTPayload output buffer
         */
        GDTPayload* get_gdt_payload();

        /**
         * Get client connection
         * @return Pointer to client connection
         */
        GDTClient* get_client();

        /**
         * Set stream destination
         * @param[in]   _dest_type  Stream destination type
         * @param[in]   _dest_id    Stream destination id
         */
        void set_destination(const char *_dest_type, const char *_dest_id);

        /**
         * Increment sequence number
         */
        void inc_sequence_num();

        /**
         * Set sequence flag to END
         */
        void end_sequence();

        /**
         * Set sequence flag to CONTINUE
         */
        void continue_sequence();

        /**
         * Set sequence flag to WAIT
         */
        void wait_sequence();

        /**
         * Set GDTMessage output buffer's sequence flag to CONTINUE
         */
        void set_continue_flag();

        /**
         * Set random number generator
         * @param[in]   _random_generator   Random number generator
         */
        void set_random_generator(mink_utils::Randomizer *_random_generator);

        /*
         * Get UUID
         * @return  Pointer to UUID buffer
         */
        unsigned char* get_uuid();

        /**
         * Generate new random UUID
         */
        void generate_uuid();

        /**
         * Set UUID
         * @param[in]   _uuid   Pointer to UUID data
         */
        void set_uuid(unsigned char *_uuid);

        /**
         * Get sequence number
         * @return      Current sequence number
         */
        unsigned int get_sequence_num();

        /**
         * Get sequence flag
         * @return      Current sequence flag
         */
        GDTSequenceFlag get_sequence_flag();

        /**
         * Reset stream parameters
         * @param[in]   reset_uuid  Generate new UUID flag
         */
        void reset(bool reset_uuid);

        /**
         * Set sequence flag
         * @param[in]   _sequence_flag  New sequence flag
         */
        void set_sequence_flag(GDTSequenceFlag _sequence_flag);

        /**
         * Generate sequence header and push to output queue
         * @param[in]   include_body    Include GDT body flag
         */
        void send(bool include_body = true);

        /**
         * Set client connection
         * @param[in]   _client     Pointer to client connection
         */
        void set_client(GDTClient *_client);

        /**
         * Toggle reply received flag
         */
        void toggle_seq_reply_received();

        /**
         * Get reply received flag
         * @return  Reply received flag
         */
        bool get_seq_reply_received();

        /**
         * Set timestamp of last activity
         * @param[in]   _timestamp  Unix timestamp
         */
        void set_timestamp(time_t _timestamp);

        /**
         * Get unix timestamp of last activity
         * @return  Unix timestamp of last activity
         */
        time_t get_timestamp();

        /**
         * Execute callback method
         * @param[in]   type    Event type to search for
         * @param[in]   args    Pointer to callback arguments passed to callback run method
         * @return      True if callback method is found or False otherwise
         */
        bool process_callback(GDTEventType type, GDTCallbackArgs *args);

        /**
         * Set callback
         * @param[in]   callback_type   Event type to attach callback to
         * @param[in]   callback_method Pointer to callback method
         */
        void set_callback(GDTEventType callback_type, GDTCallbackMethod *callback_method);

        /**
         * Get callback
         * @param[in]   callback_type   Event type to search for
         * @return      Pointer to callback method of NULL if not found
         */
        GDTCallbackMethod* get_callback(GDTEventType callback_type);

        /**
         * Remove callback
         * @param[in]   callback_type   Event type to search for and remove
         *
         */
        void remove_callback(GDTEventType callback_type);

        /**
         * Clear all callabcks
         */
        void clear_callbacks();

        /**
         * Get stream parameter
         * @param[in]   param_id    Parameter id
         * @return      Pointer to parameter
         */
        void* get_param(uint32_t param_id);

        /**
         * Set stream parameter
         * @param[in]   param_id    Parameter id
         * @param[in]   param       Pointer to parameter
         */
        void set_param(uint32_t param_id, void *param);

        /**
         * Remove stream parameter
         * @param[in]   param_id    Parameter id
         * @return      Number of parameters removed
         */
        int remove_param(uint32_t param_id);

        /**
         * Clear stream parameters
         */
        void clear_params();

        /**
         * Get timeout status
         * @return  timeout status
         */
        bool get_timeout_status();

        /**
         * Set timeout status
         * @param[in]   _status Timeout status
         */
        void set_timeout_status(bool _status);

    };

    /**
     * GDT Statistics
     */
    class GDTStats {
    public:
        /** Total packets */
        mink::Atomic<uint64_t> packets;
        /** Total bytes */
        mink::Atomic<uint64_t> bytes;
        /** Datagram count */
        mink::Atomic<uint64_t> datagrams;
        /** Datagram bytes */
        mink::Atomic<uint64_t> datagram_bytes;
        /** Datagram errors */
        mink::Atomic<uint64_t> datagram_errors;
        /** Stream count */
        mink::Atomic<uint64_t> streams;
        /** Stream bytes */
        mink::Atomic<uint64_t> stream_bytes;
        /** Stream errors */
        mink::Atomic<uint64_t> stream_errors;
        /** Discarded packets */
        mink::Atomic<uint64_t> discarded;
        /** Malformed packets */
        mink::Atomic<uint64_t> malformed;
        /** Socket errors */
        mink::Atomic<uint64_t> socket_errors;
        /** Stream allocation errors */
        mink::Atomic<uint64_t> strm_alloc_errors;
        /** Stream timeouts */
        mink::Atomic<uint64_t> strm_timeout;
        /** Stream loopback */
        mink::Atomic<uint64_t> strm_loopback;

        GDTStats();
        GDTStats& operator=(GDTStats& rhs);

    };

    class GDTStateMachine{
    public:
        GDTStateMachine();
        ~GDTStateMachine();

        void init(GDTClient *_gdtc);
        void run();
        void process_sf_continue(GDTStream *tmp_stream, bool remove_stream = true);
        void process_sf_end(GDTStream *tmp_stream, bool remove_stream = true);
        void process_sf_stream_complete(GDTStream *tmp_stream);

        GDTClient *gdtc;
        int res;
        int sctp_len;
        pollfd fds_lst[1];
        int poll_timeout;
        unsigned char tmp_buff[8192];
        sctp_sndrcvinfo rcvinfo;
        sctp_notification *sctp_ntf;
        sctp_assoc_change *sctp_assoc;
        int sctp_flags;
        asn1::GDTMessage gdt_in_message;
        asn1::GDTMessage gdt_out_message;
        asn1::ASN1Node root_asn1_node;
        uint64_t tmp_in_session_id;
        asn1::ASN1Pool asn1_pool;
        GDTCallbackArgs cb_args;
        GDTCallbackArgs cb_stream_args;
        asn1::SessionId _in_session_id;
        bool include_body;
        bool mem_switch;
        GDTClient *route_c;
        std::vector<GDTClient*> routes;
        bool route_this;
        int custom_seq_flag;
        asn1::TLVNode *seq_flag_tlv;
        asn1::TLVNode *seq_num_tlv;
        asn1::Header *header;
        asn1::TLVNode *uuid_tlv;
        char d_id[17];
        char d_type[17];
    };

    /**
     * GDT Client connection
     *
     */
    class GDTClient {
    friend class GDTSession;
    friend class GDTStateMachine;
    private:

        /**
         * Initialize reconnection procedure
         */
        void init_reconnect();

        /**
         * Check for stream timeout
         * @param[in]   override    If True, timeout all active streams
         */
        void process_timeout(bool override = false);

        /**
         * Initialize internal variables
         */
        void init();

        /**
         * Execute callbackrun  method
         * @param[in]   type    Event type to search for
         * @param[in]   args    Pointer to callback arguments passed to callback run method
         * @return      True if callback method is found or False otherwise
         */
        bool process_callback(GDTEventType type, GDTCallbackArgs *args);

        /**
         * Execute callback cleanup method
         * @param[in]   type    Event type to search for
         * @param[in]   args    Pointer to callback arguments passed to callback run method
         * @return      True if callback method is found or False otherwise
         */
        bool process_cleanup(GDTEventType type, GDTCallbackArgs *args);

        /**
         * Start reconnection loop, try to re-establish broken connection
         */
        int reconnect_socket();

        /**
         * Inbound thread method
         * @param[in]   args    Pointer to GDTClient
         * @return      NULL
         */
        static void* in_loop(void *args);

        /**
         * Inbound connection cleanup method
         * @param[in]   args    Pointer to GDTClient
         * @return      NULL
         */
        static void* exit_loop(void *args);

        /**
         * Outbound thread method
         * @param[in]   args    Pointer to GDTClient
         * @return      NULL
         */
        static void* out_loop(void *args);

        /**
         * Stream timeout thread method
         * @param[in]   args    Pointer to GDTClient
         * @return      NULL
         */
        static void* timeout_loop(void *args);

        /**
         * Client registration timeout thread method
         * @param[in]   args    Pointer to GDTClient
         * @return      NULL
         */
        static void* reg_timeout_loop(void *args);

        /**
         * Set connection activity status
         * @param[in]   _is_active  Connection activity flag
         */
        void set_activity(bool _is_active);

        /**
         * Send packet via SCTP
         * @param[in]   sctp_stream_id  SCTP stream id
         * @param[in]   data            Pointer to data
         * @param[in]   data_length     Length of data
         * @return      0 if data successfully send or 1 if error occurred
         */
        int send(unsigned int sctp_stream_id, const unsigned char *data, unsigned int data_length);

        /**
         * Validate sequence number
         * @param[in]   data                Raw 4 byte big endian data containing sequence number
         * @param[in]   data_len            Length of data, should be 4
         * @param[in]   expected_seq_num    Expected sequence number
         * @return      True if sequence number equals to expected_seq_num of False otherwise
         */
        bool validate_seq_num(unsigned char *data, unsigned int data_len, unsigned int expected_seq_num);

        /**
         * Get routing capable client
         * @param[in]   in_msg  Pointer to GDT message
         * @param[in]   sess_id Current GDT session id
         * @param[out]  routes  Pointer to output vector for matched routes
         * @param[out]  d_id    Pointer to C string to receive daemon id
         * @param[out]  d_type  Pointer to C string to receive daemon type
         * @return      0 for success or error code otherwise
         */
        int route(asn1::GDTMessage *in_msg, 
                  uint64_t sess_id, 
                  std::vector<GDTClient*> *routes, 
                  char *d_id, 
                  char *d_type);

        /**
         * Process outbound package
         * @param[in]       gdtpld     Pointer to GDT payload
         * @param[in,out]   cb_args     Pointer to callback args
         * @return          0 for success or error code otherwise
         */
        int out_process(GDTPayload *gdtpld, GDTCallbackArgs *cb_args);

        /** Session connection */
        GDTSession *session;
        /** Client socket id */
        int client_socket;
        /** Client id */
        int client_id;
        /** Socket poll interval */
        int poll_interval;
        /** End point address */
        char end_point_address[16];
        /** End point port */
        unsigned int end_point_port;
        /** Local point ddress */
        char local_point_address[16];
        /** Local point port */
        unsigned int local_point_port;
        /** End point daemon type */
        char end_point_daemon_type[17];
        /** End point daemon id */
        char end_point_daemon_id[17];
        /** Callback handler */
        GDTCallbackHandler callback_handler;
        /** random number generator */
        mink_utils::Randomizer random_generator;
        /** activity flag */
        mink::Atomic<uint8_t> active;
        /** Router capabilities flag */
        bool router;
        mink::Atomic<uint8_t> registered;
        /** Stream timeout check flag */
        mink::Atomic<uint8_t> stream_timeout_check;
        /** Reconnect flag */
        mink::Atomic<uint8_t> reconnect_queued;
        /** List of active streams */
        std::vector<GDTStream*> streams;
        mink::RingBuffer<GDTPayload*> out_queue;
        lockfree::SpscQ<GDTPayload> internal_out_queue;
        mink::Atomic<unsigned int> thread_count;
        /** Inbound thread id */
        pthread_t in_thread;
        /** Outbound thread id */
        pthread_t out_thread;
        /** Shutdown cleanup thread id */
        pthread_t exit_thread;
        /** Timeout thread id */
        pthread_t timeout_thread;
        /** GDT client registrationTimeout thread id */
        pthread_t reg_timeout_thread;
        /** Inbound thread attributes */
        pthread_attr_t in_thread_attr;
        /** Outbound thread attributes */
        pthread_attr_t out_thread_attr;
        /** Timeout thread attributes */
        pthread_attr_t timeout_thread_attr;
        /** Inbound statistics */
        GDTStats in_stats;
        /** Outbound statistics */
        GDTStats out_stats;
        /** Active streams mutex */
        pthread_mutex_t mtx_streams;
        pthread_spinlock_t slock_callback;
        pthread_spinlock_t slock_uuid;
        /** Raw chunk memory pool */
        memory::Pool<memory::MemChunk<1024>, true > mc_pool;
        /** GDTPayload memory pool */
        memory::Pool<GDTPayload, true> pld_pool;
        /** GDTMessage memory pool */
        memory::Pool<asn1::GDTMessage, true> gdtm_pool;
        /** GDTStream memory pool */
        memory::Pool<GDTStream, true> stream_pool;
        mink::Atomic<uint32_t> ref_counter;
        GDTStateMachine gdt_sm;
        mink::Atomic<uint8_t> streams_active;
        mink::Atomic<time_t> timestamp;

    public:
        GDTClient();

        /**
         * Custom constructor
         * @param[in]   _client_socket              SCTP socket id
         * @param[in]   end_point_address           End point (PEER) address (IP)
         * @param[in]   end_point_port              End point (PEER) port number
         * @param[in]   _local_point_address        Local address (IP)
         * @param[in]   _local_point_port           Local port number
         * @param[in]   _direction                  Connection direction (SERVER/CLIENT)
         * @param[in]   _max_concurrent_streams     Maximum number of concurrent GDT streams
         * @param[in]   _stream_timeout             GDT stream timeout in seconds
         * @param[in]   _poll_interval              Socket poll interval in seconds
         */
        GDTClient(int _client_socket,
                  const char *end_point_address,
                  unsigned int end_point_port,
                  const char *_local_point_address,
                  unsigned int _local_point_port,
                  GDTConnectionDirection _direction,
                  int _max_concurrent_streams,
                  int _stream_timeout,
                  int _poll_interval);

        ~GDTClient();

        /**
         * Increment ref counter
         * @return  Value after increment
         */
        uint32_t inc_refc();

        /**
         * Decrement ref counter
         * @return  Value after decrement
         */
        uint32_t dec_refc();

        /**
         * Get ref counter
         * @return  Current counter value
         */
        uint32_t get_refc();

        /**
         * Generate uuid
         * @param[out]  out Output buffer
         * @return  0 for success or error code
         */
        int generate_uuid(unsigned char *out);

        /**
         * Get connection activity status
         * @return  True if connection is active or False otherwise
         */
        uint8_t is_active();

        /**
         * Set registration flag
         * @param[in]   _reg_flag   Registration flag
         */
        void set_reg_flag(bool _reg_flag);

        /**
         * Get registration flag
         * @return  Registration flag
         */
        bool is_registered();

        /**
         * Set end point daemon id
         * @param[in]   _did    Pointer to daemon id C string
         */
        void set_end_point_daemon_id(const char *_did);

        /**
         * Set end point daemon type
         * @param[in]   _dtype  Pointer to daemon type C string
         */
        void set_end_point_daemon_type(const char *_dtype);

        /**
         * Get end point daemon id
         * @return  Pointer to daemon id C string
         */
        char* get_end_point_daemon_id();

        /**
         * Get end point daemon type
         * @return  Pointer to daemon type C string
         */
        char* get_end_point_daemon_type();

        /**
         * Register client (INBOUND, used internally)
         * @return  0 on success or -1 if error occurred
         */
        int register_client();

        /**
         * Get SCTP socket id
         * @return  SCTP socket id
         */
        int get_client_socket();

        /**
         * Get client id
         * @return  Client id
         */
        int get_client_id();

        /**
         * Disconnect
         * @return  0 on success or -1 if error occurred
         */
        int disconnect();

        /**
         * Get end point address (IP)
         * @return  Pointer to data containing IP remote address
         */
        char* get_end_point_address();

        /**
         * Get end point port
         * @return  End point port number
         */
        unsigned int get_end_point_port();

        /**
         * Get local address (IP)
         * @return  Pointer to data containing local IP address
         */
        char* get_local_point_address();

        /**
         * Get local port number
         * @return  Local port number
         */
        unsigned int get_local_point_port();

        /**
         * Set router capabilities flag
         * @param[in]   _is_router  Router status flag
         */
        void set_router_flag(bool _is_router);

        /**
         * Get router status
         * @return  True if router enabled or False otherwise
         */
        bool is_router();

        /**
         * Initialize threads
         */
        void init_threads();

        /**
         * Get connection statistics
         * @param[in]   stats_type  Type of data requested (IN/OUT)
         * @param[out]  result      Pointer to result/output data structure
         */
        void get_stats(GDTStatsType stats_type, GDTStats *result);

        /**
         * Get connection statistics pointer
         * @param[in]   stats_type  Type of data requested (IN/OUT)
         * @return      Pointer to stats data structure
         */
        GDTStats* get_stats(GDTStatsType stats_type);

        /**
         * Genereate ACK message
         * @param[in]   gdt_orig_message   Pointer to original GDT message
         * @param[out]  gdt_out_message    Pointer to output GDT message
         * @param[in]   _orig_session_id   Current session id of original GDT message
         * @param[in]   _out_session_id    New session id of output message (should be 1)
         * @param[out]  gdtld              Pointer to GDT output payload
         * @param[in]   include_body       Include body flag (if True, body will be included in otput message)
         * @param[in]   mem_switch         Memory switch flag (if True, data pointer in output GDT 
         *                                 message  will be changed to point to output GDT payload 
         *                                 instead of original GDT message)
         */
        void generate_ack(asn1::GDTMessage *gdt_orig_message,
                          asn1::GDTMessage *gdt_out_message,
                          uint64_t _orig_session_id,
                          uint64_t _out_session_id,
                          GDTPayload *gdtld,
                          bool include_body,
                          bool mem_switch);

        /**
         * Genereate ERR message
         * @param[in]   gdt_orig_message       Pointer to original GDT message
         * @param[out   gdt_out_message        Pointer to output GDT message
         * @param[in]   _orig_session_id       Current session id of original GDT message
         * @param[in]   _out_session_id        New session id of output message (should be 1)
         * @param[out]  gdtld                  Pointer to GDT output payload
         * @param[in]   mem_switch             Memory switch flag (if True, data pointer in output GDT 
         *                                     message  will be changed to point to output GDT payload 
         *                                     instead of original GDT message)
         * @param[in]   _custom_seq_flag       Custom sequence flag
         * @param[in]   _custom_dtype          Custom daemon type
         * @param[in]   _custom_did            Custom daemon id
         * @param[in]   _error_code            Error code to include in GDT output mesage
         */
        void generate_err(asn1::GDTMessage *gdt_orig_message,
                          asn1::GDTMessage *gdt_out_message,
                          uint64_t _orig_session_id,
                          uint64_t _out_session_id,
                          GDTPayload *gdtld,
                          bool mem_switch,
                          int _custom_seq_flag,
                          char *_custom_dtype,
                          char *_custom_did,
                          int _error_code);

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
        void set_destination_id(asn1::GDTMessage *gdt_orig_message,
                                asn1::GDTMessage *gdt_out_message,
                                uint64_t _orig_session_id,
                                uint64_t _out_session_id,
                                unsigned char *_destination_id,
                                int _destination_length,
                                GDTPayload *gdtld);

        /**
         * U[date hop data 
         * @param[in]   gdt_orig_message    Pointer to original GDT message
         * @param[out]  gdt_out_message     Pointer to output GDT message
         * @param[in]   _orig_session_id    Current session id of original GDT message
         * @param[in]   _out_session_id     New session id of output message (should be 1)
         * @param[in]   _destination_id     Pointer to destination id
         * @param[in]   _destination_length Length of destination id
         * @param[out]  gdtld               Pointer to GDT output payload
         */
        int update_hop_info(asn1::GDTMessage *gdt_orig_message,
                            asn1::GDTMessage *gdt_out_message,
                            uint64_t _orig_session_id,
                            uint64_t _out_session_id,
                            unsigned char *_destination_id,
                            int _destination_length,
                            GDTPayload *gdtld);


        /**
         * Genereate stream complete message
         * @param[in]   gdt_orig_message    Pointer to original GDT message
         * @param[out]  gdt_out_message     Pointer to output GDT message
         * @param[in]   _orig_session_id    Current session id of original GDT message
         * @param[in]   _out_session_id     New session id of output message (should be 1)
         * @param[out]  gdtld               Pointer to GDT output payload
         */
        void generate_stream_complete(asn1::GDTMessage *gdt_orig_message,
                                      asn1::GDTMessage *gdt_out_message,
                                      uint64_t _orig_session_id,
                                      uint64_t _out_session_id,
                                      GDTPayload *gdtld);

        /**
         * Genereate initial stream header
         * @param[out]  gdt_out_message     Pointer to output GDT message
         * @param[in]   stream              Pointer to GDT stream
         * @param[in]   _session_id         New session id of output message (should be 1)
         * @param[out]  gdtld               Pointer to GDT output payload
         * @param[in]   include_body        Include GDT body flag
         * @param[in]   _dest_type          Stream destination type
         * @param[in]   _dest_id            Stream destination id
         */
        void generate_stream_header(asn1::GDTMessage *gdt_out_message,
                                    GDTStream *stream,
                                    uint64_t _session_id,
                                    GDTPayload *gdtld,
                                    bool _include_body,
                                    const char *_dest_type,
                                    const char *_dest_id);


        /**
         * Push to output queue
         * @param[in]   payload Pointer to GDT payload
         * @return      0 for success or -1 if error occurred
         */
        int push_out_queue(GDTPayload *payload);

        /**
         * Pop from output queue
         */
        GDTPayload* pop_out_queue();

        /**
         * Set session connection
         * @param[in]   _session    Pointer to session connection
         */
        void set_session(GDTSession *_session);

        /**
         * Get session connection
         * @return      Pointer to session connection
         */
        GDTSession* get_session();

        /**
         * Get active thread count
         * @return      Number of active threads
         */
        unsigned int get_thread_count();

        /**
         * Increment active thread count
         * @return      New number of active threads
         */
        unsigned int inc_thread_count();

        /**
         * Decrement active thread count
         * @return      New number of active threads
         */
        unsigned int dec_thread_count();

        /**
         * Create new GDT stream
         * @return      Pointer to new GDT stream
         */
        GDTStream* create_stream();

        /**
         * Initialize new GDT stream
         *
         * @msc
         *
         *      a [label="Client"], b [label="Server"];
         *      a box b [label="Example of NORMAL STREAMING", textbgcolour="#ff7f7f"];
         *      |||;
         *      a=>b    [label="sf-start seq #1"];
         *      b=>a    [label="sf-continue seq #1"];
         *      a=>b    [label="sf-continue seq #2"];
         *      b=>a    [label="sf-end seq #2"];
         *      a=>b    [label="sf-stream-complete seq #2"];
         *      a box b [label="Example of STREAMING WITH DELAYED REPLY", textbgcolour="#ff7f7f"];
         *      |||;
         *      a=>b    [label="sf-start seq #1"];
         *      b=>a    [label="sf-continue seq #1"];
         *      a=>b    [label="sf-continue seq #2"];
         *      b=>a    [label="sf-continue-wait seq #2"];
         *      b=>a    [label="sf-continue seq #2"];
         *      a=>b    [label="sf-end seq #3"];
         *      b=>a    [label="sf-stream-complete seq #3"];
         *
         * @endmsc
         * @param[in]   _dest_type              Stream destination type
         * @param[in]   _dest_id                Stream destination id
         * @param[in]   _on_sent_callback       Payload send callback
         * @param[in]   _on_reply_callback      Reply received callback (Stream Continue received from peer)
         * @return      Pointer to new and initialized stream
         */
        GDTStream* new_stream(const char *_dest_type,
                              const char *_dest_id,
                              GDTCallbackMethod *_on_sent_callback,
                              GDTCallbackMethod *_on_reply_callback);

        /**
         * Add stream to list of active streams
         * @param[in]   _stream     Pointer to new active stream
         */
        void add_stream(GDTStream *_stream);

        /**
         * Check if stream is active
         * @param[in]   _stream     Pointer to stream
         * @return      True if stream is active
         */
        bool stream_exists(GDTStream *_stream);

        /**
         * Remove stream from list of active streams (thread safe)
         * @param[in]   _stream Pointer to stream which will be removed
         */
        void remove_stream(GDTStream *_stream);

        /**
         * Remove stream from list of active streams (thread unsafe)
         * @param[in]   _stream Pointer to stream which will be removed
         */
        void remove_stream_unsafe(GDTStream *_stream);

        /**
         * Get stream by UUID
         * @param[in]   _uuid   UUID to search for
         * @return      Pointer to stream or NULL if not found
         */
        GDTStream* get_stream(const unsigned char *_uuid);

        /**
         * Get stream by index
         * @param[in]   index   Stream list index
         * @return      Pointer to stream or NULL if not found
         */
        GDTStream* get_stream(unsigned int index);

        /**
         * Get number of active streams
         * @return      Number of active streams
         */
        int get_stream_count();


        /**
         * Send datagram and use raw bytes for payload
         *
         * @msc
         *      a [label="Client"], b [label="Server"];
         *      a box b [label="Example of NORMAL STATELESS MODE", textbgcolour="#ff7f7f"];
         *      |||;
         *      a=>b    [label="sf-stateless"];
         *      b=>a    [label="sf-stream-complete"];
         *      a box b [label="Example of SCTP DEPENDENT STATELESS MODE", textbgcolour="#ff7f7f"];
         *      |||;
         *      a=>b    [label="sf-stateless-no-reply"];
         *
         * @endmsc
         *
         * @param[in]   payload_type                Payload type (GDT DATA)
         * @param[in]   payload                     Pointer to payload data
         * @param[in]   payload_length              Length to payload data
         * @param[in]   on_sent_callback_method     Payload send callback
         * @param[in]   on_reply_callback_method    Reply received callback (if NULL, datagram will be 
         *                                          sent as GDT_ST_STATELESS_NO_REPLY)
         * @param[in]   dest_daemon_type            Datagram destination type
         * @param[in]   dest_daemon_id              Datagram destination id
         * @return      0 for success or 1 if error occurred
         *
         */
        int send_datagram(int payload_type,
                          unsigned char *payload,
                          int payload_length,
                          GDTCallbackMethod *on_sent_callback_method,
                          GDTCallbackMethod *on_reply_callback_method,
                          const char *dest_daemon_type,
                          const char *dest_daemon_id);

        /**
         * Send datagram and use already prepared GDT BODY for payload
         *
         * @msc
         *      a [label="Client"], b [label="Server"];
         *      a box b [label="Example of NORMAL STATELESS MODE", textbgcolour="#ff7f7f"];
         *      |||;
         *      a=>b    [label="sf-stateless"];
         *      b=>a    [label="sf-stream-complete"];
         *      a box b [label="Example of SCTP DEPENDENT STATELESS MODE", textbgcolour="#ff7f7f"];
         *      |||;
         *      a=>b    [label="sf-stateless-no-reply"];
         *
         * @endmsc
         *
         * @param[in]   body                        Pointer GDT BODY Payload
         * @param[in]   on_sent_callback_method     Payload send callback
         * @param[in]   on_reply_callback_method    Reply received callback (if NULL, datagram will 
         *                                          be sent as GDT_ST_STATELESS_NO_REPLY)
         * @param[in]   dest_daemon_type            Datagram destination type
         * @param[in]   dest_daemon_id              Datagram destination id
         * @return      0 for success or 1 if error occurred
         *
         */
        int send_datagram(asn1::Body *body,
                          GDTCallbackMethod *on_sent_callback_method,
                          GDTCallbackMethod *on_reply_callback_method,
                          const char *dest_daemon_type,
                          const char *dest_daemon_id);



        /**
         * Set event callback handler
         * @param[in]   callback_type       Event type for callback
         * @param[in]   callback_method     Pointer to callback handler method
         * @param[in]   unsafe              If True, do not lock mutex
         */
        void set_callback(GDTEventType callback_type, GDTCallbackMethod *callback_method, bool unsafe = false);

        /**
         * Get callback
         * @param[in]   callback_type   Event type to search for
         * @param[in]   unsafe          If True, do not lock mutex
         * @return      Pointer to callback method of NULL if not found
         */
        GDTCallbackMethod* get_callback(GDTEventType callback_type, bool unsafe = false);

        /**
         * Remove callbak handler
         * @param[in]   callback_type   Event type for callback
         * @param[in]   unsafe          If True, do not lock mutex
         */
        void remove_callback(GDTEventType callback_type, bool unsafe = false);

        /**
         * Deallocate memory chunk and return back to memory pool
         * @param[in]   mem_chunk       Pointer to memory chunk which will be returned to pool
         * @return      0 for success or error code if error occurred
         */
        int deallocate_mc_pool(memory::MemChunk<1024> *mem_chunk);

        /**
         * Allocate memory chunk from memory pool
         * @return  0 for success or error code if error occurred
         */
        memory::MemChunk<1024>* allocate_mc_pool();

        /**
         * Deallocate payload and return back to memory pool
         * @param[in]   gdtpld  Pointer to payload which will be returned to pool
         * @return      0 for success or error code if error occurred
         *
         */
        int deallocate_pld_pool(GDTPayload *gdtpld);

        /**
         * Allocate payload from memory pool
         * @return  Pointer to allocated payload
         */
        GDTPayload* allocate_pld_pool();

        /**
         * Deallocate GDT message and return back to memory pool
         * @param[in]   gdtm    Pointer to GDT message which will be returned to pool
         * @return      0 for success or error code if error occurred
         *
         */
        int deallocate_gdtm_pool(asn1::GDTMessage *gdtm);

        /**
         * Allocate GDT message from memory pool
         * @return  0 for success or error code if error occurred
         */
        asn1::GDTMessage* allocate_gdtm_pool();

        /**
         * Deallocate stream and return back to memory pool
         * @param[in]   stream  Pointer to stream which will be returned to pool
         * @return      0 for success or error code if error occurred
         *
         */
        int deallocate_stream_pool(GDTStream *stream);

        /**
         * Allocate stream from memory pool
         * @return  Pointer to allocated stream
         */
        GDTStream* allocate_stream_pool();
        /** Connection direction (SERVER/CLIENT) */
        GDTConnectionDirection direction;
        /** Maximum number of concurrent GDT streams */
        int max_concurrent_streams; 
        /** Stream timout */
        int stream_timeout;
    };

    /**
     * GDT payload
     *
     */
    class GDTPayload {
    private:
        /** Callback handler */
        GDTCallbackHandler callback_handler;
    public:
        GDTPayload();
        ~GDTPayload();

        /**
         * Execute callback method
         * @param[in]   type    Event type to search for
         * @param[in]   args    Pointer to callback arguments passed to callback run method
         * @return      True if callback method is found or False otherwise
         */
        void process_callback(GDTEventType type, GDTCallbackArgs *args);

        /**
         * Set callback
         * @param[in]   callback_type   Event type to attach callback to
         * @param[in]   callback_method Pointer to callbacl method
         */
        void set_callback(GDTEventType callback_type, GDTCallbackMethod *callback_method);

        /**
         * Remove callback
         * @param[in]   callback_type   Event type to search for and remove
         *
         */
        void remove_callback(GDTEventType callback_type);

        /**
         * Clear all callbacks
         */
        void clear_callbacks();
        /** Free on send flag, payload set to be deallocated after successful transfer */
        bool free_on_send;
        /** Sctp socket id */
        unsigned int sctp_sid;
        /** Stream type */
        GDTStreamType gdt_stream_type;
        /** Pointer to raw encoded data */
        unsigned char *raw_data;
        /** Length of raw encoded data */
        unsigned int raw_data_length;
        /** Client connection */
        GDTClient *client;
        /** Stream connection */
        GDTStream *stream;
        /** Processed in out queue flag */
        mink::Atomic<uint8_t> out;
    };

    /**
     * Routing handler
     */
    class RouteHandlerMethod {
    public:
        RouteHandlerMethod(GDTSession *_gdts);
        virtual ~RouteHandlerMethod();

        /**
         * Run handler method
         * @param[in]   all_routes      Pointer to a list of acceptable routes
         * @param[out]  chosen_routes   Pointer to output vector containing chosen routes
         */
        virtual void run(std::vector<GDTClient*> *all_routes, 
                         std::vector<GDTClient*> *chosen_routes);
        virtual void* add_node(GDTClient *gdtc,
                               const char *node_type,
                               const char *node_id,
                               mink_utils::PooledVPMap<uint32_t> *params);
        virtual void* get_node(const char *node_type, const char *node_id);
        virtual void* update_client(GDTClient *gdtc,
                                    const char *node_type,
                                    const char *node_id);
        virtual int remove_type(const char *node_type);
        virtual int remove_node(const char *node_type, const char *node_id);
        virtual void clear();

    private:
        GDTSession *gdts;

    };


    /**
     * WRR Routing handler
     */
    class WRRRouteHandler: public RouteHandlerMethod{
    public:
        // types
        typedef std::map<uint32_t, mink_utils::WRR<gdt::GDTClient*> > wrr_map_t;
        typedef wrr_map_t::iterator wrr_map_it_t;
        typedef wrr_map_t::value_type wrr_map_value_t;
        typedef std::pair<wrr_map_it_t, bool> wrr_map_insert_t;

        WRRRouteHandler(GDTSession *_gdts);
        ~WRRRouteHandler();

        /**
         * Run handler method
         * @param[in]   all_routes      Pointer to a list of acceptable routes
         * @param[out]  chosen_routes   Pointer to output vector containing chosen routes
         */
        void run(std::vector<GDTClient*> *all_routes, 
                 std::vector<GDTClient*> *chosen_routes);
        void* add_node(GDTClient *gdtc,
                       const char *node_type,
                       const char *node_id,
                       mink_utils::PooledVPMap<uint32_t> *params);
        void* get_node(const char *node_type, const char *node_id);
        void* update_client(GDTClient *gdtc,
                            const char *node_type,
                            const char *node_id);
        int remove_type(const char *node_type);
        int remove_node(const char *node_type, const char *node_id);
        void clear();

    private:
        wrr_map_t wrr_map;

    };

    /**
     * GDT Session information
     *
     */
    class GDTSession {
    friend class RouteHandlerMethod;
    friend class WRRRouteHandler;
    public:
        /**
         * Custom constructor
         * @param[in]   _daemon_type                Session daemon type
         * @param[in]   _daemon_id                  Session daemon id
         * @param[in]   _max_concurrent_streams     Maximum number of concurrent GDT streams
         * @param[in]   _stream_timeout             GDT stream timeout
         * @param[in]   _router                     GDT router capability flag
         * @param[in]   _poll_interval              Socket poll interval in seconds
         */
        GDTSession(const char *_daemon_type,
                   const char *_daemon_id,
                   int _max_concurrent_streams,
                   int _stream_timeout,
                   bool _router,
                   int _poll_interval);

        ~GDTSession();

        /**
         * Register client
         * @param[in]   client              Pointer to GDTClient
         * @param[in]   dest_daemon_type    Pointer to registration point daemon type
         */
        int register_client(GDTClient *client, const char *dest_daemon_type);

        /**
         * Set routing handler
         * @param[in]   rhandler    Pointer to user defined routing handler
         */
        void set_routing_handler(RouteHandlerMethod *rhandler);

        /**
         * Set routing algorithm
         * @param[in]   algo    Routing algorithm
         */
        void set_routing_algo(GDTRoutingAlgorithm algo);

        /**
         * Get routing handler
         * @return      Pointer to user defined routing handler
         */
        RouteHandlerMethod* get_routing_handler();

        /**
         * Add client to list of active clients
         * @param[in]   client  Pointer to client connection
         */
        void add_client(GDTClient *client);

        /**
         * Lock client list
         */
        void lock_clients();

        /**
         * Unlock client list
         */
        void unlock_clients();

        /**
         * Get router flag
         * @return  True if router capabilities are active or False otherwise
         */
        bool is_router();

        /**
         * Find acceptable route for specific daemon type and/or daemon id
         * @param[in]   _client         Pointer to calling client
         * @param[in]   _daemon_type    Pointer to daemon type C string
         * @param[in]   _daemon_id      Pointer to daemon id C string
         * @param[out]  routes          Pointer to output vector for matched routes
         * @return      0 for success or error code otherwise
         */
        int find_route(GDTClient *_client,
                       const char *_daemon_type,
                       const char *_daemon_id,
                       std::vector<GDTClient*> *routes);

        /**
         * Execute callback method
         * @param[in]   type    Event type to search for
         * @param[in]   args    Pointer to callback arguments passed to callback run method
         * @return      True if callback method is found or False otherwise
         */
        void process_callback(GDTEventType type, GDTCallbackArgs *args);

        /**
         * Get number of active threads (server thread only for now)
         * @return      Number of active threads
         */
        unsigned int get_thread_count();

        /**
         * Increment number of active threads
         * @return      New number of active threads
         */
        unsigned int inc_thread_count();

        /**
         * Decrement number of active threds
         * @return      New number of active threads
         */
        unsigned int dec_thread_count();

        /**
         * Get deamon type
         * @return      Pointer to data containing daemon type
         */
        char* get_daemon_type();

        /**
         * Get deamon id
         * @return      Pointer to data containing daemon id
         */
        char* get_daemon_id();

        /**
         * Get active client by index
         * @param[in]   client_index    Client index in active client list
         * @param[in]   unsafe          Use mutex if False
         * @return      Pointer to client connection
         */
        GDTClient* get_client(unsigned int client_index, bool unsafe = false);

        /**
         * Get active and registered client by index
         * @param[in]   client_index    Client index in active client list
         * @param[in]   unsafe          Use mutex if False
         * @return      Pointer to client connection
         */
        GDTClient* get_registered_client(unsigned int client_index, bool unsafe = false);

        /**
         * Get active and registered client by type
         * @param[in]   daemon_type     Client type
         * @param[in]   unsafe          Use mutex if False
         * @return      Pointer to client connection
         */
        GDTClient* get_registered_client(const char *daemon_type, bool unsafe = false);

        /**
         * Get active and registered client by type and id
         * @param[in]   daemon_type     Client type
         * @param[in]   daemon_id       Client id
         * @param[in]   unsafe          Use mutex if False
         * @return      Pointer to client connection
         */
        GDTClient* get_registered_client(const char *daemon_type, const char *daemon_id, bool unsafe = false);

        /**
         * Get active client by index
         * @param[in]   client  Pointer to client
         * @return      Pointer to active client or NULL if terminated
         */
        GDTClient* get_client(GDTClient *client);

        /**
         * Get number of acrive clients
         * @param[in]   unsafe  Use mutex if False
         * @return      Number of active clients
         */
        unsigned int get_client_count(bool unsafe = false);

        /**
         * Remove client by index
         * @param[in]   client_index    Client index in active client list
         * @return      0 for success or -1 if error occurre
         */
        int remove_client(unsigned int client_index);

        /**
         * Remoce client
         * @param[in]   gdt_client      Pointer to client connection
         * @return      0 for success or -1 if error occurre
         */
        int remove_client(GDTClient *gdt_client);

        /**
         * Establish SCTP connection to end point
         * @param[in]   end_point_address   End point address (IP)
         * @param[in]   end_point_port      End point port number
         * @param[in]   stream_count        SCTP stream count
         * @param[in]   local_address       Local address (IP) - if NULL, automatic bind
         * @param[in]   local_port          Local port number (if zero, automatic port)
         * @param[in]   skip_gdt_reg        If True, skip GDT Registration (mandatory for routing)
         * @return      Pointer to new GDT client with established SCTP socket connection
         */
        GDTClient* connect(const char *end_point_address,
                           unsigned int end_point_port,
                           int stream_count,
                           const char *local_address,
                           unsigned int local_port,
                           bool skip_gdt_reg = false);

        /**
         * Get server socket id
         * @return  Server socket id
         */
        int get_server_socket();

        /**
         * Set server socket id
         * @param[in]   _socket     Server socket id
         */
        void set_server_socket(int _socket);

        /**
         * Get server activity flag
         * @return  Server activity flag
         */
        bool get_server_mode();

        /**
         * Set server activity flag
         * @param[in]   _server_mode    Server activity flag
         */
        void set_server_mode(bool _server_mode);

        /**
         * Start server
         * @param[in]   bind_address    Local address (IP) - if NULL, automatic bind
         * @param[in]   bind_port       Local port number (if zero, automatic port)
         * @return      Server socket id
         */
        int start_server(const char *bind_address, unsigned int bind_port);

        /**
         * Stop server
         * @return  0 for success, -1 if error occurred
         */
        int stop_server();

        /**
         * Set callback
         * @param[in]   callback_type       Event type to attach callback to
         * @param[in]   callback_method     Pointer to callbacl method
         */
        void set_callback(GDTEventType callback_type, GDTCallbackMethod *callback_method);

        /**
         * Remove callback
         * @param[in]   callback_type   Event type to search for and remove
         *
         */
        void remove_callback(GDTEventType callback_type);


    private:
        /**
         * Server thread method
         * @param[in]   args    Pointer to GDTClient
         * @return      NULL
         */
        static void* server_loop(void *args);
        /** Callback handler */
        GDTCallbackHandler callback_handler;
        /** Callback mutex */
        pthread_mutex_t mtx_callback;
        /** Active clients mutex */
        pthread_mutex_t mtx_clients;
        mink::Atomic<unsigned int> thread_count;
        /** Server thread id */
        pthread_t server_thread;
        /** Server thread attributes */
        pthread_attr_t server_thread_attr;
        mink::Atomic<int> server_socket;
        /** Socket poll interval */
        int poll_interval;
        mink::Atomic<uint8_t> server_mode;
        /** Session daemon type */
        char daemon_type[50];
        /** Session daemon id */
        char daemon_id[50];
        /** List of active clients (inbound + outbound) */
        std::vector<GDTClient*> clients;
        /** Maximum number of concurrent GDT streams */
        int max_concurrent_streams;
        /** GDT stream timeout */
        int stream_timeout;
        /** Router capability flag */
        bool router;
        /** Routing handler */
        RouteHandlerMethod *rh_method;

    };

    /**
     * Heartbeat info
     */
    class HeartbeatInfo {
    private:
        mink::Atomic<uint8_t> active;
        mink::Atomic<uint8_t> next;
        /** Sent heartbeat counter */
        mink::Atomic<uint64_t> total_sent_count;
        /** Sent heartbeat counter */
        mink::Atomic<uint64_t> total_received_count;
        /** Missed heartbeat counter */
        mink::Atomic<uint64_t> missed_count;
        /** Received heartbeat counter */
        mink::Atomic<uint64_t> received_count;

    public:
        HeartbeatInfo();
        ~HeartbeatInfo();

        /**
         * Heartbeat thread method
         * @param[in]   args    Pointer to HeartbeatInfo
         * @return      NULL
         */
        static void* heartbeat_loop(void *args);

        /**
         * Get activity status
         * @return      True if connection is active or False otherwise
         */
        bool is_active();

        /**
         * Get ready for next status
         * @return True if ready for next ot False otherwise
         */
        bool next_ready();

        /**
         * Set readu for next status
         */
        void set_next(bool _next);

        /**
         * Set connection activity status
         * @param[in]   _is_active      Connection activity flag
         */
        void set_activity(bool _is_active);

        /**
         * Increment total number of received heartbeats
         */
        void inc_total_received();

        /**
         * Increment total number of sent heartbeats
         */
        void inc_total_sent();

        /**
         * Get toal number of received heartbeats
         * @return      Total number of received heartbeats
         */
        uint64_t get_total_received();

        /**
         * Get total number of sent heartbeats
         * @return      Total number of sent heartbeats
         */
        uint64_t get_total_sent();

        /**
         * Increment total number of error free heartbeats
         */
        void inc_received();

        /**
         * Increment total number of missed heartbeats
         */
        void inc_missed();

        /**
         * Get total number of error free heartbeats
         * @return      Total number of error free heartbeats
         */
        uint64_t get_received();

        /**
         * Get total number of missed heartbeats
         * @return      Total number of missed heartbeats
         */
        uint64_t get_missed();

        /**
         * Reset missed number of heartbeats to 0
         */
        void reset_missed();

        /** GDT client connection */
        GDTClient *gdtc;
        /** Heartbeat interval in seconds */
        unsigned int interval;
        /** Target daemon type */
        char target_daemon_type[17];
        /** Target daemon id */
        char target_daemon_id[17];
        /** On heartbeat received event */
        GDTCallbackMethod *on_received;
        /** On heartbeat missed event */
        GDTCallbackMethod *on_missed;
        /** On heartbeat cleanup event */
        GDTCallbackMethod *on_cleanup;

    };


    /**
     * Initialize GDT session
     * @param[in]   _daemon_type                Session daemon type
     * @param[in]   _daemon_id                  Session daemon id
     * @param[in]   _max_concurrent_streams     Maximum number of concurrent GDT streams
     * @param[in]   _stream_timeout             GDT stream timeout in seconds
     * @param[in]   _router                     GDT router capability flag
     * @param[in]   _poll_interval              Socket poll interval
     * @return      Pointer to GDT session
     */
    GDTSession* init_session(const char *_daemon_type,
                             const char *_daemon_id,
                             int _max_concurrent_streams,
                             int _stream_timeout,
                             bool _router,
                             int _poll_interval);


    /**
     * Destroy GDT Session
     * @param[in,out]   gdt_session     Pointer to GDT session
     * @return          0 for success, 1 if error occurred
     */
    int destroy_session(GDTSession *gdt_session);

    /**
     * Initialize heartbeat session
     * @param[in]   _daemon_type    Target daemon type
     * @param[in]   _daemon_id      Target daemon id
     * @param[in]   _client         GDT client connection
     * @param[in]   interval        Heartbeat interval in seconds
     * @param[in]   _on_received    On heartbeat received event
     * @param[in]   _on_missed      On heartbeat missed event
     * @param[in]   _on_cleanup     On heartbeat cleanup event
     * @return      Pointer to HeartbeatInfo or NULL if error occurred
     *
     */
    HeartbeatInfo* init_heartbeat(const char *_daemon_type,
                                  const char *_daemon_id,
                                  GDTClient *_client,
                                  unsigned int interval,
                                  GDTCallbackMethod *_on_received,
                                  GDTCallbackMethod *_on_missed,
                                  GDTCallbackMethod *_on_cleanup);

    /**
     * Stop heartbeat session
     * @param[in]   Pointer to heartbeat info
     */
    void stop_heartbeat(HeartbeatInfo *hi);


}

#endif /* ifndef GDT_H_ */
