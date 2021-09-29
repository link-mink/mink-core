/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
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
constexpr int COMMANDS[] = {
    gdt_grpc::CMD_GET_PROCESS_LST,
    gdt_grpc::CMD_SHELL_EXEC,
    // end of list marker
    -1
};


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

static void impl_processlst(gdt::ServiceMessage *smsg){
    PROCTAB *proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);

    proc_t proc_info;
    memset(&proc_info, 0, sizeof(proc_info));
    int i = 0;
    using namespace gdt_grpc;
    while (readproc(proc, &proc_info) != nullptr) {
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

static void impl_shell_exec(gdt::ServiceMessage *smsg){
    using namespace gdt_grpc;

    // shell command
    const mink_utils::VariantParam *vp_cmd = smsg->vpget(PT_SHELL_CMD);
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
    auto smsg = static_cast<gdt::ServiceMessage*>(data);

    // check command id
    switch (cmd_id) {
        case gdt_grpc::CMD_GET_PROCESS_LST:
            impl_processlst(smsg);
            break;

        case gdt_grpc::CMD_SHELL_EXEC:
            impl_shell_exec(smsg);
            break;

        default:
            break;
    }
    return 0;
}


