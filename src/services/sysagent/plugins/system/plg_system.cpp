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

#include <mink_plugin.h>
#include <gdt_utils.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <proc/readproc.h>
#include <config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
int COMMANDS[] = {
    gdt_grpc::CMD_GET_SYSINFO,
    gdt_grpc::CMD_GET_CPUSTATS,
    gdt_grpc::CMD_GET_MEMINFO,
    gdt_grpc::CMD_GET_UNAME,
    gdt_grpc::CMD_GET_PROCESS_LST,
    gdt_grpc::CMD_GET_FILE_STAT,
    gdt_grpc::CMD_SHELL_EXEC,
    // end of list marker
    -1
};

typedef struct proc_stat_cpu_s {
    unsigned long user;
    unsigned long nice;
    unsigned long system;
    unsigned long idle;
    unsigned long iowait;
    unsigned long irq;
    unsigned long softirq;
    unsigned long steal;
} proc_stat_cpu_t;


static int proc_stat_cpu_get(proc_stat_cpu_t *proc_stat_cpu) {
    int error = 0;
    FILE *file_descriptor = NULL;

    file_descriptor = fopen("/proc/stat", "r");
    if (file_descriptor == NULL) {
        error = -1;
        goto error_out;
    }

    if (fscanf(file_descriptor, "cpu  %lu %lu %lu %lu %lu %lu %lu %lu",
               &proc_stat_cpu->user, &proc_stat_cpu->nice,
               &proc_stat_cpu->system, &proc_stat_cpu->idle,
               &proc_stat_cpu->iowait, &proc_stat_cpu->irq,
               &proc_stat_cpu->softirq, &proc_stat_cpu->steal) != 8) {
        error = -1;
        goto error_out;
    }

    goto out;

error_out:

out:
    if (file_descriptor) {
        fclose(file_descriptor);
    }

    return error ? -1 : 0;
}


/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

static void get_sysinfo(gdt::ServiceMessage *smsg){
    struct sysinfo info;
    int error = sysinfo(&info);
    if (error < 0) return;

    using namespace gdt_grpc;
    smsg->vpset(PT_SI_LOAD_AVG_1_MIN, std::to_string((int64_t)info.loads[0]));
    smsg->vpset(PT_SI_LOAD_AVG_5_MIN, std::to_string((int64_t)info.loads[1]));
    smsg->vpset(PT_SI_LOAD_AVG_15_MIN, std::to_string((int64_t)info.loads[2]));
    smsg->vpset(PT_SI_MEM_TOTAL, std::to_string((int64_t)info.totalram));
    smsg->vpset(PT_SI_MEM_FREE, std::to_string((int64_t)info.freeram));
    smsg->vpset(PT_SI_MEM_BUFFERS, std::to_string((int64_t)info.bufferram));
    smsg->vpset(PT_SI_MEM_SWAP_TOTAL, std::to_string((int64_t)info.totalswap));
    smsg->vpset(PT_SI_MEM_SWAP_FREE, std::to_string((int64_t)info.freeswap));
    smsg->vpset(PT_SI_MEM_HIGH_TOTAL, std::to_string((int64_t)info.totalhigh));
    smsg->vpset(PT_SI_MEM_HIGH_FREE, std::to_string((int64_t)info.freehigh));
    smsg->vpset(PT_SI_MEM_UNIT_SIZE, std::to_string((int64_t)info.mem_unit));
}

static void get_cpustats(gdt::ServiceMessage *smsg){
    proc_stat_cpu_t proc_stat_cpu_t1;
    proc_stat_cpu_t proc_stat_cpu_t2;

    unsigned long long proc_stat_cpu_total_t1 = 0;
    unsigned long long proc_stat_cpu_total_t2 = 0;
    unsigned long long proc_stat_cpu_total_delta = 0;
    unsigned int proc_stat_cpu_user_percent = 0;
    unsigned int proc_stat_cpu_nice_percent = 0;
    unsigned int proc_stat_cpu_system_percent = 0;

    int error = proc_stat_cpu_get(&proc_stat_cpu_t1);
    if (error) {
        return;
    }
    sleep(1);
    error = proc_stat_cpu_get(&proc_stat_cpu_t2);
    if (error) {
        return;
    }
    proc_stat_cpu_total_t1 = proc_stat_cpu_t1.user + proc_stat_cpu_t1.nice +
        proc_stat_cpu_t1.system + proc_stat_cpu_t1.idle +
        proc_stat_cpu_t1.iowait + proc_stat_cpu_t1.irq +
        proc_stat_cpu_t1.softirq + proc_stat_cpu_t1.steal;
    proc_stat_cpu_total_t2 = proc_stat_cpu_t2.user + proc_stat_cpu_t2.nice +
        proc_stat_cpu_t2.system + proc_stat_cpu_t2.idle +
        proc_stat_cpu_t2.iowait + proc_stat_cpu_t2.irq +
        proc_stat_cpu_t2.softirq + proc_stat_cpu_t2.steal;
    proc_stat_cpu_total_delta = proc_stat_cpu_total_t2 - proc_stat_cpu_total_t1;

    proc_stat_cpu_user_percent =
        (unsigned int)((double)(proc_stat_cpu_t2.user - proc_stat_cpu_t1.user) /
                       (double)proc_stat_cpu_total_delta * 100);
    proc_stat_cpu_nice_percent =
        (unsigned int)((double)(proc_stat_cpu_t2.nice - proc_stat_cpu_t1.nice) /
                       (double)proc_stat_cpu_total_delta * 100);
    proc_stat_cpu_system_percent =
        (unsigned int)((double)(proc_stat_cpu_t2.system -
                                proc_stat_cpu_t1.system) /
                       (double)proc_stat_cpu_total_delta * 100);

    // test return param
    using namespace gdt_grpc;
    // PT_CPU_USER_PERCENT
    smsg->vpset(PT_CPU_USER_PERCENT, std::to_string(proc_stat_cpu_user_percent));
    // PT_CPU_NICE_PERCENT
    smsg->vpset(PT_CPU_NICE_PERCENT, std::to_string(proc_stat_cpu_nice_percent));
    // PT_CPU_SYSTEM_PERCENT
    smsg->vpset(PT_CPU_SYSTEM_PERCENT, std::to_string(proc_stat_cpu_system_percent));
}

static void get_meminfo(gdt::ServiceMessage *smsg){
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return;

    char buf[80] = {0};
    char *c;
    uint32_t id = 0;
    using namespace gdt_grpc;
    while (fgets(buf, sizeof(buf), f)) {
        c = strchr(buf, ':');
        if (!c) {
            continue;
        }
        *c = '\0';

        if (strcmp(buf, "MemTotal") == 0)
            id = PT_MI_TOTAL;
        else if (strcmp(buf, "MemFree") == 0)
            id = PT_MI_FREE;
        else if (strcmp(buf, "Buffers") == 0)
            id = PT_MI_BUFFERS;
        else if (strcmp(buf, "Cached") == 0)
            id = PT_MI_CACHED;

        if (id != 0) {
            unsigned long int value = strtoul(c + 1, NULL, 10);
            smsg->vpset(id, std::to_string((int64_t)value));
        }

        id = 0;
    }
    fclose(f);

}

static void get_uname(gdt::ServiceMessage *smsg){
    struct utsname utsname;
    int error = uname(&utsname);
    if (error < 0)
        return;
   
    using namespace gdt_grpc; 
    smsg->vpset(PT_UNM_SYSNAME, utsname.sysname);
    smsg->vpset(PT_UNM_NODENAME, utsname.nodename);
    smsg->vpset(PT_UNM_RELEASE, utsname.release);
    smsg->vpset(PT_UNM_VERSION, utsname.version);
    smsg->vpset(PT_UNM_MACHINE, utsname.machine);

}

static void get_processlst(gdt::ServiceMessage *smsg){
    PROCTAB *proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);

    proc_t proc_info;
    memset(&proc_info, 0, sizeof(proc_info));
    int i = 0;
    using namespace gdt_grpc;
    while (readproc(proc, &proc_info) != NULL) {
        smsg->vpset(PT_PL_CMD, proc_info.cmd, i);
        smsg->vpset(PT_PL_TID, std::to_string(proc_info.tid), i);
        smsg->vpset(PT_PL_PPID, std::to_string(proc_info.ppid), i);
        smsg->vpset(PT_PL_RESIDENT, std::to_string(proc_info.resident), i);
        smsg->vpset(PT_PL_UTIME, std::to_string(proc_info.utime), i);
        smsg->vpset(PT_PL_STIME, std::to_string(proc_info.stime), i);
        ++i;
    }

    closeproc(proc);

}

static void get_filestat(gdt::ServiceMessage *smsg){
    // check for file path
    mink_utils::VariantParam *vp_fpath = smsg->vpget(9029);
    if (!vp_fpath) return;


}

static void impl_shell_exec(gdt::ServiceMessage *smsg){
    using namespace gdt_grpc;

    // shell command
    mink_utils::VariantParam *vp_cmd = smsg->vpget(PT_SHELL_CMD);
    if(!vp_cmd) return;

    // buffers, and commands
    std::array<char, 128> buff;
    std::string res;
    std::string cmd(static_cast<char*>(*vp_cmd));
    // merge stdout and stderr
    cmd += " 2>&1";
    // run command
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), &pclose);
    if (!pipe) return;

    // output
    while (fgets(buff.data(), buff.size(), pipe.get()) != nullptr) {
        res += buff.data();
    }
   
    // send shell output 
    smsg->vpset(PT_SHELL_STDOUT, res);
}

/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm, 
                   mink_utils::PluginDescriptor *pd, 
                   int cmd_id,
                   void *data){

    if(!data) return 1;
    gdt::ServiceMessage *smsg = static_cast<gdt::ServiceMessage*>(data);

    // check command id
    switch (cmd_id) {
        case gdt_grpc::CMD_GET_SYSINFO:
            get_sysinfo(smsg);
            break;

        case gdt_grpc::CMD_GET_CPUSTATS:
            get_cpustats(smsg);
            break;

        case gdt_grpc::CMD_GET_MEMINFO:
            get_meminfo(smsg);
            break;

        case gdt_grpc::CMD_GET_UNAME:
            get_uname(smsg);
            break;

        case gdt_grpc::CMD_GET_PROCESS_LST:
            get_processlst(smsg);
            break;

        case gdt_grpc::CMD_GET_FILE_STAT:
            get_filestat(smsg);
            break;

        case gdt_grpc::CMD_SHELL_EXEC:
            impl_shell_exec(smsg);
            break;

        default:
            break;
    }
    return 0;
}


