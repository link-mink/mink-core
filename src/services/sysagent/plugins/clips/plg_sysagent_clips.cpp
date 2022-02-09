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
#include <exception>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <config.h>
#include <stdexcept>
#include <vector>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
extern "C" {
#include <clips.h>
}
#include <thread>
#include <fstream>
#include <atomic>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <limits.h>
#include <json_rpc.h>
#include <sysagent.h>

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_clips.so";

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
/* CLIPS env data */
/******************/
struct CLIPSEnvData {
    mink_utils::PluginManager *pm;
};


using SysStats = std::tuple<uint32_t, uint32_t>;
using Jrpc = json_rpc::JsonRpc;
char hostname[HOST_NAME_MAX + 1];

/****************/
/* Push via GDT */
/****************/
static void gdt_push(const std::string &inst_name,
                     const std::string &d_type,
                     const std::string &d_id,
                     const std::string &auth_usr,
                     const std::string &auth_pwd,
                     const int cmd_id,
                     const std::map<int, std::string> &pmap){

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

    // add CMD
    smsg->vpmap.erase_param(asn1::ParameterType::_pt_mink_command_id);
    smsg->vpmap.set_int(asn1::ParameterType::_pt_mink_command_id, cmd_id);
    // add PT_*
    for (auto it = pmap.cbegin(); it != pmap.cend(); ++it) {
        // STRING only (256 bytes max)
        if (it->second.size() > smsg->vpmap.get_max()) {
            continue;
        }
        smsg->vpmap.set_cstr(it->first, it->second.c_str());
    }

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
/* CMD call for CLIPS */
/**********************/
extern "C" void mink_clips_cmd_call(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue mink_cmd;
    UDFValue inst_lbl;
    UDFValue cmd_fld;
    UDFValue auth_usr;
    UDFValue auth_pwd;

    // check arg count
    unsigned int argc = UDFArgumentCount(uctx);
    if(argc < 5){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cmd_call argc < 5]");
        return;
    }

    // validate args
    if (!UDFFirstArgument(uctx, STRING_BIT, &mink_cmd) ||
        !UDFNextArgument(uctx, STRING_BIT, &inst_lbl) ||
        !UDFNextArgument(uctx, MULTIFIELD_BIT, &cmd_fld) ||
        !UDFNextArgument(uctx, STRING_BIT, &auth_usr) ||
        !UDFNextArgument(uctx, STRING_BIT, &auth_pwd)) {

        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cmd_call invalid arguments]");
        return;
    }

    // process multifield
    CLIPSValue *cv = cmd_fld.multifieldValue->contents;
    // multifield length check
    if(cmd_fld.multifieldValue->length < 2){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [MULTIFIELD argc < 2]");
        return;
    }
 
    // validate CMD value type
    if(cv[0].header->type != STRING_TYPE){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [CMD != STRING_TYPE]");
        return;
    }
   
    // find command id
    int cmd_id = Jrpc::get_method_id(mink_cmd.lexemeValue->contents);
    if(cmd_id == -1){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_clips: [Unknown CMD]");
        return;
    }

    // values
    std::vector<std::string> vals;

    // process values
    try {
        // validate params (PT_*)
        for (size_t i = 0; i < cmd_fld.multifieldValue->length; i++) {
            // STRING_TYPE only
            if (cv[i].header->type != STRING_TYPE) {
                continue;
            }
            // add to values
            vals.push_back(cv[i].lexemeValue->contents);
        }

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_clips: [%s]", e.what());
        return;
    }

    // get plugin manager
    void *edp = GetEnvironmentData(env, USER_ENVIRONMENT_DATA + 0);
    if (!edp) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot find PM pointer]");
        return;
    }

    // cast to PM pointer
    CLIPSEnvData *ced = static_cast<CLIPSEnvData *>(edp);
    // run CMD
    ced->pm->run(cmd_id, &vals, true);
}

/**********************/
/* GDT push for CLIPS */
/**********************/
extern "C" void mink_clips_gdt_push(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue mink_dt;
    UDFValue mink_did;
    UDFValue inst_lbl;
    UDFValue cmd_fld;
    UDFValue auth_usr;
    UDFValue auth_pwd;
    
    // check arg count
    unsigned int argc = UDFArgumentCount(uctx);
    if(argc < 6){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [gdt_push argc < 6]");
        return;
    }
    
    // validate args
    if (!UDFFirstArgument(uctx, STRING_BIT, &mink_dt) ||
        !UDFNextArgument(uctx, STRING_BIT, &mink_did) ||
        !UDFNextArgument(uctx, STRING_BIT, &inst_lbl) ||
        !UDFNextArgument(uctx, MULTIFIELD_BIT, &cmd_fld) ||
        !UDFNextArgument(uctx, STRING_BIT, &auth_usr) ||
        !UDFNextArgument(uctx, STRING_BIT, &auth_pwd)) {

        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [gdt_push invalid arguments]");
        return;
    }

    // process multifield
    CLIPSValue *cv = cmd_fld.multifieldValue->contents;
    // multifield length check
    if(cmd_fld.multifieldValue->length < 1){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [MULTIFIELD argc < 1]");
        return;
    }
  
  
    // validate CMD value type
    if(cv[0].header->type != STRING_TYPE){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [CMD != STRING_TYPE]");
        return;
    }
   
    // find command id
    int cmd_id = Jrpc::get_method_id(cv[0].lexemeValue->contents);
    if(cmd_id == -1){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_clips: [Unknown CMD]");
        return;
    }
    
    // param map
    std::map<int, std::string> pmap;

    // process params
    try {
        // validate params (PT_*)
        for (size_t i = 1; i < cmd_fld.multifieldValue->length; i++) {
            // STRING_TYPE only
            if (cv[i].header->type != STRING_TYPE) {
                continue;
            }
            // extract param:value
            std::string tmp_s(cv[i].lexemeValue->contents);
            auto sz = tmp_s.find_first_of(":");
            if ((sz == std::string::npos) || (sz >= tmp_s.size() - 1)) {
                throw std::invalid_argument("invalid parameter type");
            }
            // find param id
            int p_id = Jrpc::get_param_id(tmp_s.substr(0, sz));
            if (p_id == -1) {
                throw std::invalid_argument("unknown parameter");
            }

            // add to param map (overwrite)
            pmap[p_id] = tmp_s.substr(sz + 1);
        }

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_clips: [%s]", e.what());
        return;
    }

    // push via GDT
    gdt_push(inst_lbl.lexemeValue->contents,
             mink_dt.lexemeValue->contents, 
             mink_did.lexemeValue->contents,
             auth_usr.lexemeValue->contents,
             auth_pwd.lexemeValue->contents,
             cmd_id,
             pmap);
            
 
}

/****************/
/* CLIPS thread */
/****************/
static void thread_clips(mink_utils::PluginManager *pm){
    Environment *env;
    CLIPSValue cv;
    Instance *inst;
    SysStats stats;
    PluginsConfig *pcfg;
    std::string rls;

    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);

    // get config
    try {
        pcfg = static_cast<PluginsConfig *>(dd->dparams.get_pval<void *>(4));

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [configuration file missing]");
        return;
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [CLIPS configuration missing]");
        return;
    }

    // get rules file
    try {
        rls = (*it)["rules"].get<std::string>();
        // check file size
        int sz = mink_utils::get_file_size(rls.c_str());
        if ((sz <= 0)) {
            throw std::invalid_argument("invalid filesize");
        }

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot load rules]");
        return;
    }

    // create env
    env = CreateEnvironment();
    
    // add plugin manager pointer to env
    if (!AllocateEnvironmentData(env, 
                                 USER_ENVIRONMENT_DATA + 0,
                                 sizeof(CLIPSEnvData),
                                 nullptr)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot setup Environment]");
        return;
    }
    // set PM poiner
    void *edp = GetEnvironmentData(env, USER_ENVIRONMENT_DATA + 0);
    CLIPSEnvData *ced = static_cast<CLIPSEnvData *>(edp);
    ced->pm = pm;

    // add function (mink_gdt_push)
    AddUDF(env, 
           "mink_gdt_push", 
           "v", 
           6, 6, 
           ";s;s;s;m;s;s",
           &mink_clips_gdt_push, 
           "mink_clips_gdt_push", 
           nullptr);

    // add function (mink_cmd_call)
    AddUDF(env, 
           "mink_cmd_call", 
           "v", 
           5, 5, 
           ";s;s;m;s;s",
           &mink_clips_cmd_call, 
           "mink_clips_cmd_call", 
           nullptr);

    Load(env, rls.c_str());
    Reset(env);

    // instance
    std::string s("(h of HOST (label \"");
    s.append(hostname);
    s.append("\"))");

    // create instance
    inst = MakeInstance(env, s.c_str());
    if (!inst) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot create instance (%s)",
                                  s.c_str());
        return;
    }

    // run
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED) {
        // get values
        pm->run(gdt_grpc::CMD_GET_SYSMON_DATA, &stats, true);        
        // set and run rules
        DirectPutSlotInteger(inst, "mem_used", std::get<1>(stats));
        DirectPutSlotInteger(inst, "cpu", std::get<0>(stats));
        Run(env, -1);
        sleep(1);
    }

    // cleanup
    DestroyEnvironment(env);

}


/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    // get hostname
    gethostname(hostname, sizeof(hostname)); 

    // init CLIPS thread
    std::thread th_clips(&thread_clips, pm);
    th_clips.detach();

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


