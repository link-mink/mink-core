/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef GDT_STATS_H_
#define GDT_STATS_H_

#include <gdt.h>

namespace gdt {
    /**
     * Trap id
     */
    class TrapId {
    public:
        TrapId(const char *_label = NULL);
        TrapId(const std::string &_label);

        std::string label;
    };

    /**
     * User id comparison for user map
     */
    class TrapIdCompare {
    public:
        /**
         * Custom operator '()'
         */
        bool operator()(const TrapId &x, const TrapId &y) const;
    };

    // fwd declarations
    class TrapStreamNew;
    class GDTStatsSession;
    class TrapId;

    class TrapClientDone : public GDTCallbackMethod {
    public:
        // event handler method
        void run(gdt::GDTCallbackArgs *args);
    };

    class TrapStreamDone : public GDTCallbackMethod {
    public:
        // event handler method
        void run(gdt::GDTCallbackArgs *args);
        TrapStreamNew *snew;
    };

    class TrapStreamNext : public GDTCallbackMethod {
    public:
        // event handler method
        void run(gdt::GDTCallbackArgs *args);
        TrapStreamDone sdone;
    };

    class TrapStreamNew : public GDTCallbackMethod {
    public:
        TrapStreamNew();
        // event handler method
        void run(gdt::GDTCallbackArgs *args);
        TrapStreamNext snext;
        std::map<TrapId, uint64_t, TrapIdCompare> traps;
        std::map<TrapId, uint64_t, TrapIdCompare>::iterator trap_iter;
        // int trap_index;
        uint32_t trap_count;
        uint32_t pt_stats_id;
        uint32_t pt_stats_count;
        uint32_t pt_stats_value;
        uint32_t pt_stats_desc;
        uint32_t stats_action;
        GDTStatsSession *ss;
        TrapStreamNew *snew;
    };

    class TrapClientNew : public GDTCallbackMethod {
    public:
        TrapClientNew();
        // event handler method
        void run(gdt::GDTCallbackArgs *args);
        TrapStreamNew snew;
        GDTStatsSession *ss;
    };

    /**
     * Custom trap handler
     */
    class GDTTrapHandler {
    public:
        GDTTrapHandler();
        virtual ~GDTTrapHandler();
        virtual void run();
        /** Last retrieved value */
        uint64_t value;
    };

    // GDTStatsHandler
    class GDTStatsHandler : public GDTTrapHandler {
    public:
        GDTStatsHandler(mink::Atomic<uint64_t> *_sval_p);
        void run();

    private:
        mink::Atomic<uint64_t> *sval_p;
    };

    // GDTStatsClientCreated
    class GDTStatsClientCreated : public gdt::GDTCallbackMethod {
    public:
        void run(gdt::GDTCallbackArgs *args);

        GDTStatsSession *gdt_stats;
    };

    class GDTStatsClientDestroyed : public gdt::GDTCallbackMethod {
    public:
        void run(gdt::GDTCallbackArgs *args);

        GDTStatsSession *gdt_stats;
    };

    /**
     * Stats session managment
     */
    class GDTStatsSession {
    public:
        /**
         * Constructor
         * @param[in]       _poll_interval  Trap data acquisition interval
         * @param[in]       _host_gdts      Pointer to host GDT session
         * @param[in]       _stats_port     Stats GDT inbound port
         */
        GDTStatsSession(int _poll_interval, 
                        gdt::GDTSession *_host_gdts,
                        int _stats_port = 0);

        /**
         * Destructor
         */
        ~GDTStatsSession();

        /**
         * Add new trap
         * @param[in]       trap_id         Trap id
         * @param[in]       handler         Pointer to trap handler
         * @return  0 for success or error code
         */
        int add_trap(const TrapId *trap_id, GDTTrapHandler *handler);

        /**
         * Add new trap
         * @param[in]       trap_id         Trap id
         * @param[in]       handler         Pointer to trap handler
         * @return  0 for success or error code
         */
        int add_trap(const TrapId &trap_id, GDTTrapHandler *handler);

        /**
         * Remove trap
         * @param[in]       trap_id         Trap id
         * @return  Pointer to trap handler or NULL of not found
         */
        GDTTrapHandler *remove_trap(const TrapId &trap_id);

        /**
         * Get trap handler
         * @param[in,out]   trap_id         Trap id to match and update
         * @param[in]       unsafe          If True, do not lock mutex
         * @return  Pointer to trap handler or NULL of not found
         */
        GDTTrapHandler *get_trap(TrapId *trap_id, bool unsafe);

        /**
         * Get trap value
         * @param[in,out]   trap_id         Trap id to match and update
         * @return  Last trap value
         */
        uint64_t get_trap_value(TrapId *trap_id);

        /**
         * Data acquisition thread method
         * @param[in]       args    Pointer to GDTStatsSession
         * @return  NULL
         */
        static void *trap_loop(void *args);

        /**
         * Start stats session
         */
        void start();

        /**
         * Stop stats session
         */
        void stop();

        /**
         * Set required events
         * @param[in]       _client Pointer to client
         */
        void setup_client(gdt::GDTClient *_client);

        /**
         * Get GDT stats session
         */
        gdt::GDTSession *get_gdt_session();

        /**
         * Lock mutex
         */
        void lock();

        /**
         * Unlock mutex
         */
        void unlock();

        void init_gdt_session_stats(GDTSession *_gdts);

        std::map<TrapId, GDTTrapHandler *, TrapIdCompare> *
        /** Trap map */
        get_trap_map();
        /** Data acquisition interval in seconds */
        int poll_interval;

    private:
        /**
         * Increment number of active threads
         * @return  New number of active threads
         */
        unsigned int inc_thread_count();

        /**
         * Decrement number of active threds
         * @return  New number of active threads
         */
        unsigned int dec_thread_count();

        /**
         * Get number of active threads (server thread only for now)
         * @return  Number of active threads
         */
        unsigned int get_thread_count();

        /**
         * Set connection activity status
         * @param[in]       _is_active      Connection activity flag
         */

        void set_activity(bool _is_active);

        /**
         * Get connection activity status
         * @return  True if connection is active or False otherwise
         */
        bool is_active();

        /** Stats mutex */
        pthread_mutex_t mtx_stats;
        /** Activity flag */
        bool active;
        /** Active thread count */
        int thread_count;
        /** Stats inbound port */
        int stats_port;
        /** Pointer to GDT stats session */
        gdt::GDTSession *gdts;
        /** Pointer to GDT host session */
        gdt::GDTSession *host_gdts;
        /** Trap map */
        std::map<TrapId, GDTTrapHandler *, TrapIdCompare> trap_map;
        /** New client event */
        TrapClientNew new_client;
        /** Client terminated event */
        TrapClientDone client_done;
        /** Client creted event */
        GDTStatsClientCreated client_created;
        /** Client destroyed event */
        GDTStatsClientDestroyed client_destroyed;
    };

} // namespace gdt

#endif /* GDT_STATS_H_ */
