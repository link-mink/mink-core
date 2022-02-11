/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <daemon.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/capability.h>

// static and extern
bool mink::DaemonDescriptor::DAEMON_TERMINATED = false;
mink::DaemonDescriptor* mink::CURRENT_DAEMON = nullptr;

// DaemonDescriptor
mink::DaemonDescriptor::DaemonDescriptor(){
    DAEMON_TERMINATED = false;
    CURRENT_DAEMON = this;
    log_level.set(LLT_INFO);
}

mink::DaemonDescriptor::DaemonDescriptor(const char* _type, 
                                         const char* _id, 
                                         const char* _desc){
    DAEMON_TERMINATED = false;
    CURRENT_DAEMON = this;
    log_level.set(LLT_INFO);

    if((_id != nullptr) && (set_daemon_id(_id) > 0)){
        std::cout
            << "ERROR: Maximum size of daemon id string is 15 characters!"
            << std::endl;
        exit(EXIT_FAILURE);
    }

    if((_type != nullptr) && (set_daemon_type(_type) > 0)){
        std::cout
            << "ERROR: Maximum size of daemon type string is 15 characters!"
            << std::endl;
        exit(EXIT_FAILURE);
    }

    if((_desc != nullptr) && (set_daemon_description(_desc) > 0)){
        std::cout << "ERROR: Maximum size of daemon description string is "
                     "500 characters!"
                  << std::endl;
        exit(EXIT_FAILURE);
    }


}


mink::DaemonDescriptor::~DaemonDescriptor() = default;

void mink::DaemonDescriptor::print_help(){
    std::cout << daemon_type << " - " << daemon_description << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -?\thelp" << std::endl;

}

void mink::DaemonDescriptor::signal_handler(int signum){
    switch(signum) {
        case SIGTERM:
            // set termination flag
            DaemonDescriptor::DAEMON_TERMINATED = true;
            break;

        default:
            break;
    }

}

void mink::DaemonDescriptor::set_log_level(LogLevelType _log_level){
    log_level.set(_log_level);
}

mink::LogLevelType mink::DaemonDescriptor::get_log_level(){
    return log_level.get();
}

void mink::DaemonDescriptor::terminate(){
    // implemented in dereived classes
}

void* mink::DaemonDescriptor::get_param(int param_id){
    if(params.find(param_id) != params.end()) return params[param_id];
    return nullptr;
}

void mink::DaemonDescriptor::set_param(int param_id, void* param){
    params[param_id] = param;
}


std::ostringstream& mink::DaemonDescriptor::get_log_stream(){
    return log_stream;
}


void mink::DaemonDescriptor::flush_log_stream(LogLevelType _log_level){
    log(_log_level, log_stream.str().c_str());
    log_stream.str("");
}


void mink::DaemonDescriptor::log(LogLevelType _log_level, const char* msg, ...){
    // all DEBUG levels translate to syslog's DEBUG level
    // create va list
    va_list argp;
    va_start(argp, msg);
    // log level check
    if(_log_level <= log_level.get()){
        // open log
        openlog(CURRENT_DAEMON->get_full_daemon_id(), LOG_PID | LOG_CONS, LOG_USER);
        // log
        vsyslog(LOG_USER | _log_level, msg, argp);
    }
    va_end(argp);
}


void mink::DaemonDescriptor::process_args(int argc, char** argv){
    if(argc == 1){
        print_help();
        exit(EXIT_FAILURE);
    }else{
        int opt;
        while ((opt = getopt(argc, argv, "?")) != -1) {
            switch(opt){
                // help
                case '?':
                    print_help();
                    exit(EXIT_FAILURE);

                default:
                    break;
            }
        }
    }

}

int mink::DaemonDescriptor::set_daemon_id(const char* _id){
    if(_id == nullptr) return 1;
    if(strnlen(_id, 16) == 0) return 1;
    if(strnlen(_id, 16) < 16){
        daemon_id.assign(_id);
        // prefix with "mink."
        full_daemon_id.assign("mink.");
        // add daemon id after prefix
        full_daemon_id.append(daemon_id);
        return 0;
    }

    return 1;

}
const char* mink::DaemonDescriptor::get_daemon_id() const {
    return daemon_id.c_str();
}

const char* mink::DaemonDescriptor::get_full_daemon_id() const {
    return full_daemon_id.c_str();
}


int mink::DaemonDescriptor::set_daemon_type(const char* _type){
    if(_type == nullptr) return 1;
    if(strnlen(_type, sizeof(daemon_type) - 1) == 0) return 1;
    if(strnlen(_type, sizeof(daemon_type) - 1) < 16) {
        daemon_type.assign(_type);
        return 0;
    }

    return 1;

}
int mink::DaemonDescriptor::set_daemon_description(const char* _desc){
    if(strnlen(_desc, sizeof(daemon_description) - 1) == 0) return 1;
    if(strnlen(_desc, sizeof(daemon_description) - 1) <= 500){
        daemon_description.assign(_desc);
        return 0;
    }

    return 1;

}

const char* mink::DaemonDescriptor::get_daemon_type() const {
    return daemon_type.c_str();
}

const char* mink::DaemonDescriptor::get_daemon_description() const {
    return daemon_description.c_str();
}


void mink::daemon_start(const DaemonDescriptor* daemon_descriptor){
    if(daemon_descriptor != nullptr){
        // open log
        openlog(daemon_descriptor->get_full_daemon_id(), LOG_PID | LOG_CONS, LOG_USER);
        // log
        syslog(LOG_INFO, "starting...");
#ifdef ENABLE_SCHED_FIFO
        // caps check
        if(!mink_caps_valid()){
            // log
            syslog(LOG_ERR,
                   "User has insufficient privileges, enable CAP_SYS_NICE "
                   "capability or set pam_limits RTPRIO value to 100");
            // exit
            exit(EXIT_FAILURE);
        }
#endif
    }

}

void mink::daemon_terminate(DaemonDescriptor* daemon_descriptor){
    if(daemon_descriptor != nullptr){
        syslog(LOG_INFO, "terminating...");
        daemon_descriptor->terminate();
        closelog();
    }
}

void mink::daemon_loop(DaemonDescriptor* daemon_descriptor){
    while(!mink::DaemonDescriptor::DAEMON_TERMINATED){
        sleep(30);

    }
    // release memory
    daemon_terminate(daemon_descriptor);


}

bool mink::mink_caps_valid(){
    // check caps
    cap_t caps;
    caps = cap_get_proc();
    // check if CAP_SYS_NICE privilege is set
    cap_flag_value_t t;
    cap_get_flag(caps, CAP_SYS_NICE, CAP_PERMITTED, &t);
    // free mem
    cap_free(caps);
    // if CAP_SYS_NICE was set, return (running under root probably)
    if(t == CAP_SET) return true;
    // check rlimits
    rlimit rlim;
    getrlimit(RLIMIT_RTPRIO, &rlim);
    // if RLIMIT_RTPRIO soft and hard limites are set to 100, return
    if((rlim.rlim_cur == 100) && (rlim.rlim_max == 100)) return true;
    // both CAP_SYS_NICE and RLIMIT_RTPRIO privileges are insufficient,
    // return false
    return false;
}


void mink::signal_handler(int signum){
    if(CURRENT_DAEMON != nullptr) CURRENT_DAEMON->signal_handler(signum);
}


void mink::daemon_init(const DaemonDescriptor* daemon_descriptor){
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if(pid < 0) exit(EXIT_FAILURE);

    /* If we got a good PID, then we can exit the parent process. */
    if(pid > 0) exit(EXIT_SUCCESS);

    /* child process executing from here, fork return 0 in child process */

    /* Change the file mode mask */
    umask(S_IRWXO);

    /* Create a new SID for the child process */
    sid = setsid();
    if(sid < 0) exit(EXIT_FAILURE);

    /* Change the current working directory.  This prevents the current
       directory from being locked; hence not being able to remove it. */
    if((chdir("/")) < 0) exit(EXIT_FAILURE);

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // custom signal handlers
    signal(SIGTERM, &signal_handler);

    // start daemon
    daemon_start(daemon_descriptor);


}

