/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "mink_utils.h"
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <config.h>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
extern "C" {
#include <clips/clips.h>
}
#include <thread>
#include <fstream>
#include <atomic>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <limits.h>
#include <sysagent.h>

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_SET_DATA,
    gdt_grpc::CMD_RUN_RULES,
    gdt_grpc::CMD_LOAD_RULES,

    // end of list marker
    -1
};

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

/****************/
/* Push via GDT */
/****************/
static void gdt_push(const std::string data, 
                     const std::string &inst_name,
                     const std::string &d_type,
                     const std::string &d_id,
                     const std::string &auth_usr,
                     const std::string &auth_pwd){

    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // local routing daemon pointer
    gdt::GDTClient *gdtc = nullptr;
    // get new router if connection broken
    if (!(dd->rtrd_gdtc && dd->rtrd_gdtc->is_registered()))
        dd->rtrd_gdtc = dd->gdts->get_registered_client("routingd");
    // local routing daemon pointer
    gdtc = dd->rtrd_gdtc;
    // null check
    if (!gdtc) return;
    // smsgm
    gdt::ServiceMsgManager *smsgm = dd->gdtsmm;

    // allocate new service message
    gdt::ServiceMessage *smsg = smsgm->new_smsg();
    // msg sanity check
    if (!smsg) return;

    // service id
    smsg->set_service_id(asn1::ServiceId::_sid_sysagent);

    // get sparam
    gdt::ServiceParam *sp = smsgm->get_param_factory()
                                 ->new_param(gdt::SPT_OCTETS);
    // null check 
    if(!sp){
        smsgm->free_smsg(smsg);
        return;
    }

    // set source daemon type
    smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_type,
                         dd->get_daemon_type());
    // set source daemon id
    smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_daemon_id,
                         dd->get_daemon_id());

    // set credentials
    smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_auth_id,
                         auth_usr.c_str());
    smsg->vpmap.set_cstr(asn1::ParameterType::_pt_mink_auth_password,
                         auth_pwd.c_str());

    // UBUS_CALL
    smsg->vpmap.erase_param(asn1::ParameterType::_pt_mink_command_id);
    smsg->vpmap.set_int(asn1::ParameterType::_pt_mink_command_id,
                        gdt_grpc::CMD_UBUS_CALL);
    smsg->vpmap.set_cstr(gdt_grpc::PT_OWRT_UBUS_PATH, "lcmd");
    smsg->vpmap.set_cstr(gdt_grpc::PT_OWRT_UBUS_METHOD, "container_stop");

    std::string clips_inst_name("{\"container\": \"");
    clips_inst_name.append(inst_name);
    clips_inst_name.append("\"}");
    smsg->vpmap.set_cstr(gdt_grpc::PT_OWRT_UBUS_ARG, clips_inst_name.c_str());

    // randomizer
    mink_utils::Randomizer rand;
    // generate guid
    uint8_t guid_b[16];
    rand.generate(guid_b, 16);
    smsg->vpmap.set_octets(asn1::ParameterType::_pt_mink_guid,
                           guid_b,
                           16);


    // sync vpmap
    if (smsgm->vpmap_sparam_sync(smsg, nullptr) != 0) {
        smsgm->free_smsg(smsg);
        return;
    }


    // send service message
    int r = smsgm->send(smsg,
                        gdtc,
                        d_type.c_str(),
                        (!d_id.empty() ? d_id.c_str() : nullptr),
                        true,
                        nullptr);
    if (r) {
        smsgm->free_smsg(smsg);
        return;
    }

}

/**********************/
/* GDT push for CLIPS */
/**********************/
extern "C" void mink_clips_gdt_push(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue mink_dt;
    UDFValue mink_did;
    UDFValue inst_lbl;
    UDFValue clips_str;
    UDFValue auth_usr;
    UDFValue auth_pwd;
    
    // check arg count
    unsigned int argc = UDFArgumentCount(uctx);
    if(argc < 4){
        return;
    }
    
    // validate args
    if (!UDFFirstArgument(uctx, STRING_BIT, &mink_dt) ||
        !UDFNextArgument(uctx, STRING_BIT, &mink_did) ||
        !UDFNextArgument(uctx, STRING_BIT, &inst_lbl) ||
        !UDFNextArgument(uctx, STRING_BIT, &clips_str) ||
        !UDFNextArgument(uctx, STRING_BIT, &auth_usr) ||
        !UDFNextArgument(uctx, STRING_BIT, &auth_pwd)) {
        return;
    }

    std::cout << "===== CLIPS ====" << std::endl;
    std::cout << mink_dt.lexemeValue->contents << std::endl;
    std::cout << mink_did.lexemeValue->contents << std::endl;
    std::cout << inst_lbl.lexemeValue->contents << std::endl;
    std::cout << clips_str.lexemeValue->contents << std::endl;
    std::cout << auth_usr.lexemeValue->contents << std::endl;
    std::cout << auth_pwd.lexemeValue->contents << std::endl;
    std::cout << "================" << std::endl;
    
    // push via GDT
    gdt_push(clips_str.lexemeValue->contents, 
             inst_lbl.lexemeValue->contents,
             mink_dt.lexemeValue->contents, 
             mink_did.lexemeValue->contents,
             auth_usr.lexemeValue->contents,
             auth_pwd.lexemeValue->contents);
            

 
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

        // print
        /*
        std::cout << "[" << hostname << "]"
                  << ": CPU: [" << (uint32_t)utilization << "%], RAM: [" << mfp << "%]"
                  << std::endl;
        */
    }
}

/****************/
/* CLIPS thread */
/****************/
static void thread_clips(){
    Environment *env;
    env = CreateEnvironment();
    CLIPSValue cv;
    Instance *inst;
    
    // add function
     AddUDF(env, 
            "mink_gdt_push",
            "v", 
            6, 6, 
            "s;s;s;s;s;s;s", 
            &mink_clips_gdt_push,
            "mink_clips_mem_hndlr", 
            nullptr);

    Load(env, "/etc/mink/rules.clp");
    Reset(env);

    // instance
    std::string s("(h of HOST (label \"");
    s.append(hostname);
    s.append("\"))");
    
    // create instance
    inst = MakeInstance(env, s.c_str());
    if(!inst){
        std::cout << "Cannot crate instance" << std::endl;
        return;
    }

    // run
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED) {
        DirectPutSlotInteger(inst, "mem_used", mem_used.load());
        DirectPutSlotInteger(inst, "cpu", cpu_usg.load());
        Run(env, -1);
        sleep(1);
    }


}

extern "C" void mink_clips_cpu_hndlr(Environment *env, UDFContext *uctx, UDFValue *out){

}

extern "C" void mink_clips_mem_hndlr(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue name;
    UDFValue mem;
    // first argument.
    if (!UDFFirstArgument(uctx, STRING_BIT, &name)) {
        return;
    }

    // next arg
    if (!UDFNextArgument(uctx, INTEGER_BIT, &mem)) {
        return;
    }
 
    std::cout << "mink: memory usage for [" 
              << name.lexemeValue->contents 
              << "]  = [" 
              << mem.integerValue->contents 
              << "]" << std::endl;


}



extern "C" void mink_clips_print(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue a;
    UDFValue b;
    // first argument.
    if (!UDFFirstArgument(uctx, STRING_BIT, &a)) {
        return;
    }

    // next arg
    if (!UDFNextArgument(uctx, INTEGER_BIT, &b)) {
        return;
    }
 
    std::cout << "Hello from mINK plugin!!! [" 
              << a.lexemeValue->contents 
              << "] [" 
              << b.integerValue->contents 
              << "]" << std::endl;

    
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

    // init CLIPS thread
    std::thread th_clips(&thread_clips);
    th_clips.detach();



    return 0;
/*
    Environment *env;
    env = CreateEnvironment();
    CLIPSValue cv;
    Instance *inst;
    int err = AddUDF(env, 
                     "mink_clips_mem_hndlr", 
                      "v", 
                      2, 2, 
                      "s;s;l", 
                      &mink_clips_mem_hndlr, 
                      "mink_clips_mem_hndlr", 
                      nullptr);

    std::cout << "================ " << err << " ===============" << std::endl;
    Load(env, "/home/dfranusic/dev/mink-core/test/data/clips2.clp");
    Reset(env);

    // instance
    inst = MakeInstance(env, "(h1 of HOST (label \"Linux_Arch_x86_64\"))");

    // get mem info
    MemInfo mi;
    get_meminfo(&mi);

    DirectPutSlotInteger(inst, "mem_total", mi.mi_total);
    DirectPutSlotInteger(inst, "mem_free", mi.mi_free);
    DirectPutSlotInteger(inst, "mem_threshold", mi.mi_total / 2);

    std::thread clips_th([env, inst](){
        CLIPSValue cv;
        MemInfo mi = {};
        get_meminfo(&mi);
        std::random_device dev;
        std::mt19937 rng(dev());
        std::uniform_int_distribution<std::mt19937::result_type> dist(1, 512);

        while (1) {
            sleep(5);
            //DirectPutSlotInteger(inst, "mem", dist(rng));
            DirectPutSlotInteger(inst, "mem_free", mi.mi_free);
            Run(env, -1);

        }
    });
    clips_th.detach();
*/
    //DestroyEnvironment(env);
    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}


// Implementation of "SET_DATA" command
static void impl_set_data(gdt::ServiceMessage *smsg){
    
}

// Implementation of "RUN_RULES" command
static void impl_run_rules(gdt::ServiceMessage *smsg){
    
}

// Implementation of "LOAD_RULES" command
static void impl_load_rules(gdt::ServiceMessage *smsg){
    
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
        case gdt_grpc::CMD_SET_DATA:
            impl_set_data(smsg);
            break;
        case gdt_grpc::CMD_RUN_RULES:
            impl_run_rules(smsg);
            break;
        case gdt_grpc::CMD_LOAD_RULES:
            impl_load_rules(smsg);
            break;

        default:
            break;
    }
    return 0;
}


