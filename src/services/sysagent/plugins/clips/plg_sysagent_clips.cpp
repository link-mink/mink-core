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
#include <deque>
#include <exception>
#include <memory>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <config.h>
#include <mutex>
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
#include <boost/variant.hpp>

/***********/
/* Aliases */
/***********/
using CLIPSSharedVariant = boost::variant<long long, std::string>;
using Jrpc = json_rpc::JsonRpc;
namespace stdc = std::chrono;
struct CLIPSEnv2EnvDescriptor;
class CLIPSEnv2Env;

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_clips.so";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    // end of list marker
    -1
};

/******************/
/* CLIPS ENV data */
/******************/
struct CLIPSEnvData {
    mink_utils::PluginManager *pm;
    CLIPSEnv2Env *env2env;
};

/*************************/
/* ENV -> ENV Descriptor */
/*************************/
struct CLIPSEnv2EnvDescriptor {
    // queue max
    int q_max = 10;
    // ENV packet queue
    std::deque<CLIPSSharedVariant> q;

    // push if not full
    int push(CLIPSSharedVariant &d){
        if (q.size() < q_max){
            q.push_back(d);
            return 0;
        }
        return 1;
    }

    CLIPSSharedVariant &get(){
        if (!q.empty())
            return q.front();

        throw std::invalid_argument("env queue is empty");
    }

    void pop(){
        if (!q.empty())
            q.pop_front();
    }

};

/************************/
/* CLIPS ENV Descriptor */
/************************/
struct CLIPSEnvDescriptor {
    // clips environment
    Environment *env;
    // label
    std::string name;
    // auto start flag
    bool auto_start;
    // in case of long running
    // envs, time between each
    // execution of rules 
    // 0 - one time execution
    uint64_t interval;
    // run CLIPS (reset) before
    // each iteration
    bool rbr;
    // activity flag (used only
    // with long running envs)
    std::shared_ptr<std::atomic_bool> active;
    // path to rules file (clp)
    std::string r_path;
    // arbitrary user data
    CLIPSEnvData data;
    // env2env interface
    CLIPSEnv2EnvDescriptor env2env_d;
};


/************************/
/* ENV -> ENV Interface */
/************************/
class CLIPSEnv2Env {
public:
    CLIPSEnv2Env() = default;
    ~CLIPSEnv2Env() = default;
    CLIPSEnv2Env(const CLIPSEnv2Env &o) = delete;
    CLIPSEnv2Env &operator=(const CLIPSEnv2Env &o) = delete;

    int send(const std::string &dst, CLIPSSharedVariant &&d) {
        return send(dst, d);

    }
    int send(const std::string &dst, CLIPSSharedVariant &d) {
        // lock
        std::unique_lock<std::mutex>(mtx);
        // find env
        auto it = data.find(dst);
        if (it == data.end())
            return -1;

        // ENV found, push data
        int r = it->second.env2env_d.push(d);
        return r;
    }

    CLIPSEnvDescriptor &get_envd(const std::string &n){
        // lock
        std::unique_lock<std::mutex>(mtx);
        auto it = data.find(n);
        if(it != data.end()) return it->second;
        // not found 
        throw std::invalid_argument("env not found");
    }

    CLIPSEnv2EnvDescriptor &new_envd(const CLIPSEnvDescriptor &d){
        // lock
        std::unique_lock<std::mutex>(mtx);
        // find env
        auto it = data.find(d.name);
        // create new env
        if (it == data.end()){
            auto it2 = data.emplace(std::make_pair(d.name, d));
            return it2.first->second.env2env_d;
            
        // return existing env 
        }else{
            return it->second.env2env_d;

        }   
    }
    bool env_exists(const std::string &n){
        return data.find(n) != data.end();
    }

    void process_envs(const std::function<void(CLIPSEnvDescriptor &)> &f){
        // lock
        std::unique_lock<std::mutex>(mtx);
        for (auto it = data.begin(); it != data.end(); ++it)
            f(it->second);
    }

    CLIPSSharedVariant &recv(const std::string &dst){
        // lock
        std::unique_lock<std::mutex>(mtx);
        // find env
        auto it = data.find(dst);
        if (it == data.end())
            throw std::invalid_argument("recv: env not found");

        // env found
        return it->second.env2env_d.get();
    }
    
    void pop(const std::string &dst){
        // lock
        std::unique_lock<std::mutex>(mtx);
        // find env
        auto it = data.find(dst);
        if (it == data.end())
            throw std::invalid_argument("recv: env not found");

        // env found
        it->second.env2env_d.pop();

    }    


private:
    std::mutex mtx;
    std::map<std::string, CLIPSEnvDescriptor> data;
};


/***************/
/* Global vars */
/***************/
char hostname[HOST_NAME_MAX + 1];
CLIPSEnv2Env env2env;

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

/***********************/
/* CLIPS ENV send data */
/***********************/
extern "C" void mink_clips_env_send(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue env_id;
    UDFValue val;

    // check arg count
    unsigned int argc = UDFArgumentCount(uctx);
    if(argc < 2){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_send argc < 2]");
        return;
    }
    // get first argument
    if(!UDFFirstArgument(uctx, STRING_BIT, &env_id)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_send invalid argument]");
        return;

    }
    
    // check second (INT or STRING)
    if(!UDFNextArgument(uctx, INTEGER_BIT | STRING_BIT, &val)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_send invalid value]");
        return;

    }

    // get ENV shared data
    void *rsdp = GetEnvironmentData(env, USER_ENVIRONMENT_DATA + 0);
    if (!rsdp) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot find ENV shared data]");
        return;
    }
    // cast to PM pointer
    CLIPSEnvData *sdp = static_cast<CLIPSEnvData *>(rsdp);

    // -----------
    // 0 = int 
    // 1 = string
    // -----------
    // get data type (variant)
    try{
        int dt = val.header->type;
        if(dt == INTEGER_TYPE){
            CLIPSSharedVariant sv = val.integerValue->contents;
            if(sdp->env2env->send(env_id.lexemeValue->contents, sv)){
                throw std::logic_error("env queue is full");
            }

        }else if(dt == STRING_TYPE){
            CLIPSSharedVariant sv = val.lexemeValue->contents;
            if(sdp->env2env->send(env_id.lexemeValue->contents, sv)){
                throw std::logic_error("env queue is full");
            }

        }else{
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_clips: [set_shared unknown data type]");
     
        }

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, "plg_clips: %s", e.what());
    }
} 

/***********************/
/* CLIPS ENV recv data */
/***********************/
extern "C" void mink_clips_env_recv(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue env_id;

    // check arg count
    unsigned int argc = UDFArgumentCount(uctx);
    if(argc < 1){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_recv argc < 1]");
    }

    // validate args
    if (!UDFFirstArgument(uctx, STRING_BIT, &env_id)){

        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_recv invalid arguments]");
        return;
    }

    // get ENV shared data
    void *rsdp = GetEnvironmentData(env, USER_ENVIRONMENT_DATA + 0);
    if (!rsdp) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot find ENV shared data]");
        return;
    }

    // cast to PM pointer
    CLIPSEnvData *sdp = static_cast<CLIPSEnvData *>(rsdp);
  
    try {
        CLIPSSharedVariant &d = sdp->env2env->recv(env_id.lexemeValue->contents);
        // INTEGER
        long long *p = boost::get<long long>(&d);
        if (p){
            out->integerValue = CreateInteger(env, *p);

        // STRING
        }else {
            std::string *p2 = boost::get<std::string>(&d);
            if (p2)
                out->lexemeValue = CreateString(env, p2->c_str());
            else
                mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                          "plg_clips: [get_shared unknown data type]");
        }

    } catch (std::exception &e) {
         mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_recv env queue is empty]");
        
    }

}

/**********************/
/* CLIPS ENV pop data */
/**********************/
extern "C" void mink_clips_env_pop(Environment *env, UDFContext *uctx, UDFValue *out){
    UDFValue env_id;

    // check arg count
    unsigned int argc = UDFArgumentCount(uctx);
    if(argc < 1){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_pop argc < 1]");
        return;
    }

    // validate args
    if (!UDFFirstArgument(uctx, STRING_BIT, &env_id)){

        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_pop invalid arguments]");
        return;
    }

    // get ENV shared data
    void *rsdp = GetEnvironmentData(env, USER_ENVIRONMENT_DATA + 0);
    if (!rsdp) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot find ENV shared data]");
        return;
    }

    // cast to PM pointer
    CLIPSEnvData *sdp = static_cast<CLIPSEnvData *>(rsdp);
  
    try {
        sdp->env2env->pop(env_id.lexemeValue->contents);

    } catch (std::exception &e) {
         mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [env_pop env not found]");
        
    }

}


/*********************/
/* CLIPS Environment */
/*********************/
static void thread_clips_env(CLIPSEnvDescriptor *ed){
    // create env
    ed->env = CreateEnvironment();

    // add env data
    if (!AllocateEnvironmentData(ed->env, 
                                 USER_ENVIRONMENT_DATA + 0,
                                 sizeof(CLIPSEnvData),
                                 nullptr)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot setup ENV data (%s)]",
                                  ed->name.c_str());
        return;
    }

    // set user data in CLIPS ENV
    void *edp = GetEnvironmentData(ed->env, USER_ENVIRONMENT_DATA + 0);
    CLIPSEnvData *ced = static_cast<CLIPSEnvData *>(edp);
    *ced = ed->data;

    // add function (mink_gdt_push)
    AddUDF(ed->env, 
           "mink_gdt_push", 
           "v", 
           6, 6, 
           ";s;s;s;m;s;s",
           &mink_clips_gdt_push, 
           "mink_clips_gdt_push", 
           nullptr);

    // add function (mink_cmd_call)
    AddUDF(ed->env, 
           "mink_cmd_call", 
           "v", 
           5, 5, 
           ";s;s;m;s;s",
           &mink_clips_cmd_call, 
           "mink_clips_cmd_call", 
           nullptr);


    // add function (env_recv)
    AddUDF(ed->env, 
           "mink_env_recv", 
           "ls", 
           1, 1, 
           ";s",
           &mink_clips_env_recv, 
           "mink_clips_env_recv", 
           nullptr);

    // add function (env_send)
    AddUDF(ed->env, 
           "mink_env_send", 
           "v", 
           2, 2, 
           ";s;ls",
           &mink_clips_env_send, 
           "mink_clips_env_send", 
           nullptr);

    // add function (env_pop)
    AddUDF(ed->env, 
           "mink_env_pop", 
           "v", 
           1, 1, 
           ";s",
           &mink_clips_env_pop, 
           "mink_clips_env_pop", 
           nullptr);


    // load rules
    Load(ed->env, ed->r_path.c_str());
    Reset(ed->env);

    // run
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED && ed->active->load()){
        Run(ed->env, -1);
        std::this_thread::sleep_for(stdc::milliseconds(ed->interval));
        if(ed->rbr) Reset(ed->env);
    }
 
}

/********************************/
/* Process static configuration */
/********************************/
static int process_cfg(mink_utils::PluginManager *pm) {
    PluginsConfig *pcfg;
    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);

    // get config
    try {
        pcfg = static_cast<PluginsConfig *>(dd->dparams.get_pval<void *>(4));

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [configuration file missing]");
        return -1;
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [CLIPS configuration missing]");
        return -2;
    }

    // get envs
    try{
        // get reference to envs
        const auto j_envs = (*it)["envs"].get_ref<const json::array_t &>();
        // iterate and verify envs
        for(auto it = j_envs.begin(); it != j_envs.end(); ++it){
            // check type
            if(!it->is_object()){
                throw std::invalid_argument("envs element != object");
            }
            // ******************************* 
            // *** Get ENV values (verify) ***
            // ******************************* 
            // get name
            auto j_name = (*it)["name"];
            // check for duplicate name
            if(env2env.env_exists(j_name.get<std::string>()))
                throw std::invalid_argument("env already exists");

            // get auto_start
            auto j_as = (*it)["auto_start"];
            // get interval
            auto j_intrvl = (*it)["interval"];
            // check interval range
            if(!j_intrvl.is_number_unsigned()){
                throw std::invalid_argument("invalid interval");
            }
            // get clear_before_run
            auto j_rbr = (*it)["reset_before_run"];
            // get rules file
            auto j_rpath = (*it)["rpath"];
            // check rules file size
            int sz = mink_utils::get_file_size(j_rpath.get<std::string>().c_str());
            if ((sz <= 0)) {
                throw std::invalid_argument("invalid rpath");
            }

            // create ENV descriptor
            CLIPSEnvDescriptor ed{
                nullptr,
                j_name.get<std::string>(),
                j_as.get<json::boolean_t>(),
                j_intrvl.get<json::number_unsigned_t>(),
                j_rbr.get<json::boolean_t>(),
                std::make_shared<std::atomic_bool>(j_as.get<json::boolean_t>()),
                j_rpath.get<std::string>(),
                { .pm = pm, .env2env = &env2env }
            };

            // add to list
            env2env.new_envd(ed);
        }

    } catch(std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_clips: [cannot process rule_sets: %s]",
                                   e.what());
        return -3;

    }

    return 0;
}


/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    // process cfg
    if (process_cfg(pm)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR, 
                                  "plg_clips: [cannot process plugin configuration]");
        return 1;
    }
    // get hostname
    gethostname(hostname, sizeof(hostname)); 
    // create environments
    env2env.process_envs([](CLIPSEnvDescriptor &d){
        // check if ENV should auto-start
        if (d.auto_start && d.interval > 0) {
            mink::CURRENT_DAEMON->log(mink::LLT_INFO,
                                      "plg_clips: [starting ENV (%s)]",
                                      d.name.c_str());

            std::thread th(&thread_clips_env, &d);
            th.detach();
        }
    });

    return 0;
}

/*********************/
/* terminate handler */
/*********************/
extern "C" int terminate(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    return 0;
}

/*******************/
/* command handler */
/*******************/
extern "C" int run(mink_utils::PluginManager *pm, 
                   mink_utils::PluginDescriptor *pd, 
                   int cmd_id,
                   void *data){

    if(!data) return 1;

    return 0;
}


