/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <exception>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <mink_pkg_config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <thread>
#include <fstream>
#include <atomic>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <limits.h>
#include <sysagent.h>
#include <boost/asio.hpp>

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_GET_SYSMON_DATA,
    // end of list marker
    -1
};

/***********/
/* Aliases */
/***********/
using SysStats = std::tuple<uint32_t, uint32_t>;

/******************/
/* Memory and CPU */
/******************/
std::atomic_uint mem_ttl;
std::atomic_uint mem_used;
std::atomic_uint mem_free;
std::atomic_uint cpu_usg;
char hostname[HOST_NAME_MAX + 1];

/****************/
/* Get CPU info */
/****************/
static std::vector<size_t> get_cpu_tms() {
    std::ifstream proc_stat("/proc/stat");
    proc_stat.ignore(5, ' '); // Skip the 'cpu' prefix.
    std::vector<size_t> tms;
    for (size_t t; proc_stat >> t; tms.push_back(t));
    return tms;
}

/***********************/
/* Get CPU time values */
/***********************/
static bool get_cpu_tms(size_t &idl_tm, size_t &ttl_tm) {
    const std::vector<size_t> cpu_tms = get_cpu_tms();
    if (cpu_tms.size() < 4)
        return false;
    idl_tm = cpu_tms[3];
    ttl_tm = std::accumulate(cpu_tms.begin(), cpu_tms.end(), 0);
    return true;
}

/****************/
/* Get MEM info */
/****************/
static void get_mem_info(){
    struct sysinfo si;
    uint32_t total_mem;
    uint32_t free_mem;
    if (sysinfo(&si) == -1)
        return;

    free_mem = ((uint64_t)si.freeram * si.mem_unit) / 1024;
    total_mem = ((uint64_t)si.totalram * si.mem_unit) / 1024;

    // set global atomic
    mem_ttl.store(total_mem);
    mem_free.store(free_mem);
}

/*************************/
/* System monitor thread */
/*************************/
static void thread_sysmon(){
    // cpu usage vars
    size_t prv_idle_tm = 0;
    size_t prv_ttl_tm = 0;
    size_t idle_tm = 0;
    size_t ttl_tm = 0;

    // run
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED) {
        get_cpu_tms(idle_tm, ttl_tm);
        // sleep
        sleep(1);
        // get another sample
        const float idle_tm_dlt = idle_tm - prv_idle_tm;
        const float ttl_tm_dlt = ttl_tm - prv_ttl_tm;
        const float utilization = 100.0 * (1.0 - idle_tm_dlt / ttl_tm_dlt);
        prv_idle_tm = idle_tm;
        prv_ttl_tm = ttl_tm;
        // mem info
        get_mem_info();
        const uint32_t mfp = 100 * (mem_free.load() / (float)mem_ttl.load());
        mem_used.store(mfp);
        cpu_usg.store((unsigned int)utilization);

    }
}



/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    // init atomic values
    mem_ttl.store(0);
    mem_free.store(0);
    mem_used.store(0);
    cpu_usg.store(0);

    // get hostname
    gethostname(hostname, sizeof(hostname));

    // init system monitor thread
    std::thread th_sysmon(&thread_sysmon);
    th_sysmon.detach();

    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/*************************/
/* local command handler */
/*************************/
extern "C" int run_local(mink_utils::PluginManager *pm,
                         mink_utils::PluginDescriptor *pd,
                         int cmd_id,
                         mink_utils::PluginInputData &p_id){

    // sanity/type check
    if (!p_id.data())
        return -1;

    // UNIX socket local interface
    if(p_id.type() == mink_utils::PLG_DT_JSON_RPC){
        // TODO
        return 0;
    }

    // plugin2plugin local interface
    if(p_id.type() == mink_utils::PLG_DT_SPECIFIC){
        if (cmd_id != gdt_grpc::CMD_GET_SYSMON_DATA)
            return -1;

        SysStats *stats = static_cast<SysStats *>(p_id.data());
        std::get<0>(*stats) = cpu_usg.load();
        std::get<1>(*stats) = mem_used.load();

        return 0;
    }

    // unknown interface
    return -1;
}


/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm,
                   mink_utils::PluginDescriptor *pd,
                   int cmd_id,
                   mink_utils::PluginInputData &p_id){

    // sanity/type check
    if (!(p_id.data() && p_id.type() == mink_utils::PLG_DT_GDT))
        return 1;

    return 0;
}


