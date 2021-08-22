/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_DAEMON_H_
#define MINK_DAEMON_H_

#include <iostream>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <vector>
#include <map>
#include <sstream>
#include <atomic.h>

namespace mink {
    /**
     * Log level type
     */
    enum LogLevelType{
        LLT_ERROR       = 3,
        LLT_WARNING     = 4,
        LLT_INFO        = 6,
        LLT_DEBUG       = 7,
        LLT_DEBUG1      = 71,
        LLT_DEBUG2      = 73,
        LLT_DEBUG3      = 73,
        LLT_DEBUG4      = 74

    };

    /**
     * Daemon descriptor class
     */
    class DaemonDescriptor {
    public:
        /**
         * Daemon termination flag
         */
        static bool DAEMON_TERMINATED;

        /**
         * Default constructor
         */
        DaemonDescriptor();

        /**
         * Custom constructor
         * @param[in]   _type   Daemon type C string
         * @param[in]   _id     Daemon id C string
         * @param[in]   _desc   Daemon description C string
         */
        DaemonDescriptor(const char* _type, const char* _id, const char* _desc);

        /**
         * Default destructor
         */
        virtual ~DaemonDescriptor();

        /**
         * Get daemon type
         * @return  Daemon type C string
         */
        const char* get_daemon_type();

        /**
         * Set daemon type
         * @param[in]   _type   Daemon type C string
         * @return      0 for success or error code
         */
        int set_daemon_type(const char* _type);

        /**
         * Get daemon description
         * @return  Daemon description C string
         */
        const char* get_daemon_description();

        /**
         * Set daemon description
         * @param[in]   _desc   Daemon description C string
         */
        int set_daemon_description(const char* _desc);

        /**
         * Get daemon id
         * @return  Daemon id C string
         */
        const char* get_daemon_id();

        /**
         * Get full daemon id
         * @return  Full daemon id C string
         */
        const char* get_full_daemon_id();

        /**
         * Set daemon id
         * @param[in]   _id     Daemon id C string
         * @return      0 for success or error code
         */
        int set_daemon_id(const char* _id);

        /**
         * Process command line arguments
         * @param[in]   argc    Argument count
         * @param[in]   argv    Pointer to list of arguments
         *
         */
        virtual void process_args(int argc, char** argv);

        /**
         * Print help to standard output
         */
        virtual void print_help();

        /**
         * Signal handler method
         * @param[in]   signum  Signal code
         */
        virtual void signal_handler(int signum);

        /**
         * Log event
         * @param[in]   _log_level  Log level
         * @param[in]   msg         Log message C string
         * @param[in]   ...         Extra variable arguments
         */
        void log(LogLevelType _log_level, const char* msg, ...);

        /**
         * Get log output stream
         * @return  Log output stream
         */
        std::ostringstream& get_log_stream();

        /**
         * Flush log output stream
         * @param[in]   _log_level  Log level
         */
        void flush_log_stream(LogLevelType _log_level);

        /**
         *  Set log level
         *  @param[in]  _log_level  Log level
         */
        void set_log_level(LogLevelType _log_level);

        /**
         * Get log level
         * @return      Current log level
         */
        LogLevelType get_log_level();

        /**
         * Terminate event handler
         */
        virtual void terminate();

        /**
         * Get daemon parameter
         * @param[in]   param_id    Parameter id
         * @return      Pointer to parameter
         */
        void* get_param(int param_id);

        /**
         * Set parameter
         * @param[in]   param_id    Parameter id
         * @param[in]   param       Pointer to parameter
         */
        void set_param(int param_id, void* param);

    protected:
        /** daemon type */
        char daemon_type[17];
        /** daemon id */
        char daemon_id[17];
        /** full daemon id */
        char full_daemon_id[30];
        /** daemon description */
        char daemon_description[501];
        /** log level */
        mink::Atomic<LogLevelType> log_level;
        /** parameter map */
        std::map<int, void*> params;
        /** log output stream */
        std::ostringstream log_stream;
    };

    /**
     * Pointer to current daemon
     */
    extern DaemonDescriptor* CURRENT_DAEMON;

    /**
     * Signal handler method
     * @param[in]   signum  Signal number
     */
    void signal_handler(int signum);

    /**
     * Initialize daemon
     * @param[in]   daemon_descriptor   Pointer to daemon descriptor
     */
    void daemon_init(DaemonDescriptor* daemon_descriptor);

    /**
     * Start daemon
     * @param[in]   daemon_descriptor   Pointer to daemon descriptor
     */
    void daemon_start(DaemonDescriptor* daemon_descriptor);

    /**
     * Terminate daemon
     * @param[in]   daemon_descriptor   Pointer to daemon descriptor
     */
    void daemon_terminate(DaemonDescriptor* daemon_descriptor);

    /**
     * Daemon loop method
     * @param[in]   daemon_descriptor   Pointer to daemon descriptor
     */
    void daemon_loop(DaemonDescriptor* daemon_descriptor);

    /**
     * Check for sufficient capabilities
     */
    bool mink_caps_valid();
}


#endif /* MINK_DAEMON_H_ */
