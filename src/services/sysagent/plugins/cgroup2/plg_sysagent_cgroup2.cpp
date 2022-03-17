/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <boost/filesystem/operations.hpp>
#include <boost/system/detail/error_code.hpp>
#include <exception>
#include <mink_plugin.h>
#include <gdt_utils.h>
#include <config.h>
#include <stdexcept>
#ifdef ENABLE_GRPC
#include <gdt.pb.h>
#else
#include <gdt.pb.enums_only.h>
#endif
#include <sysagent.h>
#include <json_rpc.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/bimap.hpp>
#include <regex>
#include <thread>
#include <chrono>

/***********/
/* Aliases */
/***********/
namespace bfs = boost::filesystem;
using ProcInfo = std::tuple<std::string, std::string, int, int>;
using ProcLst = std::vector<ProcInfo>;
namespace stdc = std::chrono;

/*************/
/* Plugin ID */
/*************/
static const char *PLG_ID = "plg_sysagent_cgroup2.so";

/**********************************************/
/* list of command implemented by this plugin */
/**********************************************/
extern "C" constexpr int COMMANDS[] = {
    gdt_grpc::CMD_CG2_GROUP_CREATE,
    gdt_grpc::CMD_CG2_GROUP_DELETE,
    gdt_grpc::CMD_CG2_GROUPS_LST,
    gdt_grpc::CMD_CG2_CONTROLLER_GET,
    gdt_grpc::CMD_CG2_CONTROLLER_SET,
    gdt_grpc::CMD_CG2_CONTROLLERS_LST,
    // end of list marker
    -1
};


/***************************/
/* Cgroup2 controller type */
/***************************/
enum Cgroup2CntrlrType {
    // mechanism for constraining the CPU and memory
    // node placement of tasks to only the resources
    // specified in the cpuset interface files
    CG2_CNTLR_CPUSET    = 0,
    // distribution of CPU cycles
    CG2_CNTLR_CPU       = 1,
    // distribution of IO resources
    CG2_CNTLR_IO        = 2,
    // distribution of memory
    CG2_CNTLR_MEMORY    = 3,
    // controller allows to limit the HugeTLB
    // usage per control group and enforces the
    // controller limit during page fault
    CG2_CNTLR_HUGETLB   = 4,
    // The process number controller is used to
    // allow a cgroup to stop any new tasks from being i
    // fork()'d or clone()'d after a specified limit is
    // reached
    CG2_CNTLR_PIDS      = 5,
    // controller regulates the distribution and
    // accounting of RDMA resources
    CG2_CNTLR_RDMA      = 6,
    // provides the resource limiting and tracking
    // mechanism for the scalar resources which cannot be
    // abstracted like the other cgroup resources
    CG2_CNTLR_MISC      = 7
};

/*********************************/
/* Two-way enum <-> mapping type */
/*********************************/
using cg2_cntlr_type = boost::bimap<Cgroup2CntrlrType, std::string>;

// fwd
class Cgroup2Controller;

/**********************/
/* Cgroup2 descriptor */
/**********************/
struct CgroupDescriptor {
    std::string name;
    std::string path;
    json j_grp;
    std::map<Cgroup2CntrlrType, Cgroup2Controller*> cntrls;
};

/*********************************/
/* Cgroup2 controller base class */
/*********************************/
class Cgroup2Controller {
public:
    Cgroup2Controller() = default;
    virtual ~Cgroup2Controller() = default;
    virtual void process(const json &j_grp, const CgroupDescriptor &d_grp) = 0;

    Cgroup2CntrlrType type;
    std::map<std::string, std::string> vals;
};

/**************************/
/* Cgroup2 CPU controller */
/**************************/
class Cg2CPU : public Cgroup2Controller {
public:
    void process(const json &j_grp, const CgroupDescriptor &d_grp){
        // get root path
        const auto it = j_grp.at("cpu");
        // get "max"
        auto m = it.at("max");
        // validate
        if (!m.is_string()) {
            throw std::invalid_argument("CPU max invalid type");
        }
        // set "cpu.max"
        bfs::path fp(d_grp.path + "/cpu.max");
        if (!bfs::exists(fp)) {
            throw std::invalid_argument("CPU max (cpu.max) not found");
        }
        bfs::ofstream fs(fp);
        fs << m.get<std::string>() << "\n";
        fs.flush();
        fs.close();
    }
};

/*****************************/
/* Cgroup2 MEMORY controller */
/*****************************/
class Cg2MEM : public Cgroup2Controller {
public:
    void process(const json &j_grp, const CgroupDescriptor &d_grp){
        // get root path
        const auto it = j_grp.at("memory");
        // get "max"
        auto m = it.at("max");
        // validate
        if (!m.is_string()) {
            throw std::invalid_argument("MEMORY max invalid type");
        }
        // set "memory.max"
        bfs::path fp(d_grp.path + "/memory.max");
        if (!bfs::exists(fp)) {
            throw std::invalid_argument("MEMORY max (memory.max) not found");
        }
        bfs::ofstream fs(fp);
        fs << m.get<std::string>() << "\n";
        fs.flush();
        fs.close();
    }
};

/*************************/
/* Cgroup2 IO controller */
/*************************/
class Cg2IO : public Cgroup2Controller {
public:
     void process(const json &j_grp, const CgroupDescriptor &d_grp){
        // get root path
        const auto it = j_grp.at("io");
        // get "max"
        auto m = it.at("max");
        // validate
        if (!m.is_string()) {
            throw std::invalid_argument("IO max invalid type");
        }
        // set "io.max"
        bfs::path fp(d_grp.path + "/io.max");
        if (!bfs::exists(fp)) {
            throw std::invalid_argument("IO max (io.max) not found");
        }
        bfs::ofstream fs(fp);
        fs << m.get<std::string>() << "\n";
        fs.flush();
        fs.close();
    }
};

/*****************************/
/* Cgroup2 CPUSET controller */
/*****************************/
class Cg2CPUSET : public Cgroup2Controller {
public:
    void process(const json &j_grp, const CgroupDescriptor &d_grp){
        // get root path
        const auto it = j_grp.at("cpuset");
        // get "cpus"
        auto m = it.at("cpus");
        // validate
        if (!m.is_string()) {
            throw std::invalid_argument("CPUSET cpus invalid type");
        }
        // set "cpuset.cpus"
        bfs::path fp(d_grp.path + "/cpuset.cpus");
        if (!bfs::exists(fp)) {
            throw std::invalid_argument("CPUSET cpus (cpuset.cpus) not found");
        }
        bfs::ofstream fs(fp);
        fs << m.get<std::string>() << "\n";
        fs.flush();
        fs.close();
    }
};


/*******************/
/* Cgroup2 manager */
/*******************/
class Cg2Manager {
public:
    Cg2Manager(){
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_CPUSET, "cpuset"));
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_CPU, "cpu"));
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_IO, "io"));
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_MEMORY, "memory"));
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_HUGETLB, "hugetlb"));
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_PIDS, "pids"));
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_RDMA, "rdma"));
        cg2_ct_map.insert(cg2_cntlr_type::value_type(CG2_CNTLR_MISC, "misc"));
    }
    ~Cg2Manager() = default;
    Cg2Manager(const Cg2Manager &o) = delete;
    Cg2Manager &operator=(const Cg2Manager &o) = delete;

    CgroupDescriptor &create_grp(const std::string &grp,
                                 const json &j_grp,
                                 const std::string &p,
                                 bool do_lock = true) {

        // lock
        if (do_lock) lock();
        // error if GRP is already defined
        if (grps.find(grp) != grps.cend()){
            if (do_lock) unlock();
            throw std::invalid_argument("GRP already exists");
        }
        // create
        auto it = grps.emplace(grp, CgroupDescriptor{.name = grp,
                                                     .path = p,
                                                     .j_grp = j_grp});
        // unlock
        if (do_lock) unlock();
        // return new GRP descriptor
        return it.first->second;
    }

    bool validate_cntlr(const std::string &c){
        if (cg2_ct_map.right.find(c) != cg2_ct_map.right.end())
            return true;
        return false;
    }

    Cgroup2CntrlrType cntlr_str2type(const std::string &s){
        cg2_cntlr_type::right_iterator ri = cg2_ct_map.right.find(s);
        if (ri != cg2_ct_map.right.end())
            return ri->second;

        // unknown
        throw std::invalid_argument("invalid controller string");
    }

    void grp_add_cntlr(CgroupDescriptor &grp,
                       Cgroup2Controller *c,
                       bool do_lock = true){

        // lock
        if (do_lock) lock();
        // add
        if (c && grp.cntrls.find(c->type) == grp.cntrls.cend()) {
            grp.cntrls.emplace(c->type, c);
        }
        // unlock
        if (do_lock) unlock();
    }

    void grp_process(const std::function<bool(const std::string &, const CgroupDescriptor &)> &f,
                     bool do_lock = true){

        // lock
        if (do_lock) lock();
        // process
        for (auto it = grps.cbegin(); it != grps.cend(); ++it)
            f(it->first, it->second);

        // unlock
        if (do_lock) unlock();
    }

    void lock(){
        mtx.lock();
    }

    void unlock(){
        mtx.unlock();
    }

    static Cgroup2Controller *create_cntrlr(Cgroup2CntrlrType type) {
        switch (type) {
            case CG2_CNTLR_CPU:
                return new Cg2CPU();
            case CG2_CNTLR_MEMORY:
                return new Cg2MEM();
            case CG2_CNTLR_IO:
                return new Cg2IO();
            case CG2_CNTLR_CPUSET:
                return new Cg2CPUSET();
            default:
                return nullptr;
        }
    }

private:
    std::map<std::string, CgroupDescriptor> grps;
    std::mutex mtx;
    cg2_cntlr_type cg2_ct_map;
};

/***************/
/* Global vars */
/***************/
Cg2Manager cg2m;

/******************/
/* Get PLG config */
/******************/
json *plg_get_config(){
    // cfg pointer
    PluginsConfig *pcfg = nullptr;
    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // get config
    try {
        pcfg = static_cast<PluginsConfig *>(dd->dparams.get_pval<void *>(4));

    } catch (std::exception &e) {
        throw std::invalid_argument("configuration file missing");
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        throw std::invalid_argument("configuration missing");
    }

    return &*it;
}


/********************************/
/* Get TID and all its children */
/********************************/
static void proc_get_chldrn(ProcLst &lst,
                            const int tid,
                            std::vector<int> &out,
                            int idx = 0) {
    // loop process list
    for (int i = idx; i < lst.size(); i++) {
        // get TID
        auto v = lst[i];
        // match TID with PPID
        if (std::get<2>(v) == tid) {
            // child process TID
            int c_tid = std::get<3>(v);
            // save to outout list
            out.push_back(c_tid);
            // check children TIDs of this child's TID
            proc_get_chldrn(lst, c_tid, out, 0);
        }
    }
}

/**************************/
/* Create TID list string */
/**************************/
static std::string get_proc_tids(const std::string &p, ProcLst &lst){
    std::string r;
    for(auto it = lst.cbegin(); it != lst.cend(); ++it){
        if (std::get<0>(*it) == p){
            r.append(std::to_string(std::get<2>(*it)));
            r += " ";
        }
    }

    return r;
}

/***************/
/* TIDs to GRP */
/***************/
static void procs2grp(const std::string &grp_fp,
                      const json &grp,
                      ProcLst &plst) {
    try {
        // open "cgroup.procs" for writing
        bfs::path grp_procs_fp(grp_fp + "/cgroup.procs");
        if (!bfs::exists(grp_procs_fp)) {
            throw std::invalid_argument("cgroup.procs not found");
        }
        bfs::ofstream grp_procs_fs(grp_procs_fp);
        // get process names
        const auto j_prcs = grp["proc_match"].get_ref<const json::array_t &>();
        // list of tids
        std::string proc_grp_tids;
        // iterate and assign processes to the current group
        for (auto it_p = j_prcs.begin(); it_p != j_prcs.end(); ++it_p) {
            // check type
            if (!it_p->is_string()) {
                throw std::invalid_argument("process element != string");
            }
            // get process match regex
            std::string proc_rgx_s = (*it_p).get<std::string>();
            std::regex proc_rgx(proc_rgx_s);

            // loop process list
            for(auto it_plst = plst.cbegin(); it_plst != plst.cend(); ++it_plst){
                // match process name (regex)
                if (!(std::regex_search(std::get<0>(*it_plst), proc_rgx) ||
                      std::regex_search(std::get<1>(*it_plst), proc_rgx)))
                    continue;

                // TID list (main process and all its children)
                std::vector<int> tid_lst;
                int pid =  std::get<3>(*it_plst);
                // match parent and children
                proc_get_chldrn(plst, pid, tid_lst);
                // move TIDs to GRP
                grp_procs_fs << pid << "\n";
                grp_procs_fs.flush();
                for(auto it = tid_lst.cbegin(); it != tid_lst.cend(); ++it) {
                    grp_procs_fs << *it << "\n";
                    grp_procs_fs.flush();
                }
            }
        }
        // close GRP procs file
        grp_procs_fs.close();


    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [%s]",
                                  e.what());
    }
}

/*********************/
/* proc match thread */
/*********************/
static void thread_proc_assign(int intrvl, mink_utils::PluginManager *pm){
    // plugin cfg
    json *pcfg = nullptr;
    // get config
    try {
        pcfg = plg_get_config();

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [%s]",
                                  e.what());
        return;
    }
    // get root path
    auto cg2_root = pcfg->at("root");
    // root string
    std::string s_cg2_r = cg2_root.get<std::string>();
    // get groups array ref
    const auto j_grps = pcfg->at("groups").get_ref<const json::array_t &>();

    // run
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED){
        // proc lst
        ProcLst proc_lst;
        pm->run(gdt_grpc::CMD_GET_PROCESS_LST,
                mink_utils::PluginInputData(mink_utils::PLG_DT_SPECIFIC, &proc_lst),
                true);
        // iterate and verify groups
        cg2m.grp_process([&proc_lst, &j_grps](const std::string &id, const CgroupDescriptor &grpd){
            // assigns processess to GRPs
            procs2grp(grpd.path, grpd.j_grp, proc_lst);
            // ok
            return true;
        });
        // sleep
        std::this_thread::sleep_for(stdc::milliseconds(intrvl));
    }
}

/******************/
/* Create new GRP */
/******************/
std::string cg2_create_grp(const json &j_grp, const std::string &s_cg2_r){
    // check type
    if (!j_grp.is_object()) {
        throw std::invalid_argument("group element != object");
    }
    // *******************************
    // *** Get GRP values (verify) ***
    // *******************************
    // get name
    auto j_name = j_grp.at("name");
    std::string s_cg = j_name.get<std::string>();

    // create group node
    if (!bfs::exists(s_cg2_r + "/" + s_cg) &&
        !bfs::create_directory(s_cg2_r + "/" + s_cg)) {

        throw std::invalid_argument("cannot create cgroup: " + s_cg);
    }

    // create group leaf node
    if (!bfs::exists(s_cg2_r + "/" + s_cg + "/" + s_cg + ".slice") &&
        !bfs::create_directory(s_cg2_r + "/" +
                               s_cg + "/" +
                               s_cg + ".slice")) {

        throw std::invalid_argument("cannot create cg slice: " + s_cg);
    }

    // set current cgroup parent and leaf (slice)
    std::string s_cg_l(s_cg2_r + "/" + s_cg + "/" + s_cg + ".slice");
    s_cg.insert(0, s_cg2_r + "/");

    // add to CG2Manager
    cg2m.lock();
    // new grp pointer
    CgroupDescriptor *ngrpp = nullptr;
    try {
        // create new GRP
        CgroupDescriptor &ngrp = cg2m.create_grp(j_name.get<std::string>(),
                                                 j_grp,
                                                 s_cg_l,
                                                 false);
        // set new GRP pointer
        ngrpp = &ngrp;

    } catch (std::exception &e) {
        // unlock and re-throw
        cg2m.unlock();
        throw;
    }

    /*************************************/
    /* Setup controllers for current GRP */
    /*************************************/
    // open "cgroup.subtree_control" for writing
    bfs::path sub_tree_fp(s_cg + "/cgroup.subtree_control");
    if (!bfs::exists(sub_tree_fp)) {
        cg2m.unlock();
        throw std::invalid_argument("subtree_control not found");
    }
    bfs::ofstream sub_tree_fs(sub_tree_fp);

    // get controllers
    const auto j_cntrls = ngrpp->j_grp.at("controllers").get_ref<const json::array_t &>();
    // iterate and verify controllers
    for (auto it_c = j_cntrls.begin(); it_c != j_cntrls.end(); ++it_c) {
        // check type
        if (!it_c->is_string()) {
            cg2m.unlock();
            throw std::invalid_argument("controller element != string");
        }
        // get controller (string)
        std::string cntrlr = (*it_c).get<std::string>();
        // enable controller
        sub_tree_fs << "+" << cntrlr << "\n";
        sub_tree_fs.flush();
        // add to CG2Manager
        if (!cg2m.validate_cntlr(cntrlr)) {
            cg2m.unlock();
            throw std::invalid_argument("invalid controller type");
        }
        auto newc = cg2m.create_cntrlr(cg2m.cntlr_str2type(cntrlr));
        // process controller values
        if (newc){
            newc->process(ngrpp->j_grp, *ngrpp);
            cg2m.grp_add_cntlr(*ngrpp, newc, false);
        }
    }
    // unlock
    cg2m.unlock();
    // enable controlers (newline to "cgroup.subtree_control" file)
    sub_tree_fs.close();
    // return GRP path
    return s_cg_l;
}

/********************************/
/* Process static configuration */
/********************************/
static int process_cfg(mink_utils::PluginManager *pm) {
    json *pcfg = nullptr;
    // get config
    try {
        pcfg = plg_get_config();

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [%s]",
                                  e.what());
        return -1;
    }

    // process
    try{
        // ec
        boost::system::error_code ec;
        // get root path
        auto cg2_root = pcfg->at("root");
        if (!bfs::exists(cg2_root.get<std::string>())) {
            throw std::invalid_argument("cgroup2 root dir not found");
        }

        // process match thread interval
        auto j_intrvl = pcfg->at("interval");
        if(!j_intrvl.is_number_unsigned()){
            throw std::invalid_argument("invalid process match interval");
        }
        unsigned int intrvl = j_intrvl.get<json::number_unsigned_t>();

        // root string
        std::string s_cg2_r = cg2_root.get<std::string>();

        // get groups array ref
        const auto j_grps = pcfg->at("groups");

        // proc lst
        ProcLst proc_lst;
        pm->run(gdt_grpc::CMD_GET_PROCESS_LST,
                mink_utils::PluginInputData(mink_utils::PLG_DT_SPECIFIC, &proc_lst),
                true);

        // iterate and verify groups
        for (auto it_g = j_grps.begin(); it_g != j_grps.end(); ++it_g) {
            // create GRP
            std::string s_cg_l = cg2_create_grp(*it_g, s_cg2_r);

            /****************************/
            /* Assign processes to GRPs */
            /****************************/
            procs2grp(s_cg_l, *it_g, proc_lst);
        }

        // init process match thread
        std::thread th(&thread_proc_assign, intrvl, pm);
        th.detach();

    } catch(std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [%s]", e.what());
        return -3;
    }

    return 0;
}

/******************************/
/* local CMD_CG2_GROUP_CREATE */
/******************************/
static void impl_local_cg2_grp_create(json_rpc::JsonRpc &jrpc, const std::string &s_cg2_r){
    // process params
    jrpc.process_params([&s_cg2_r](int id, const std::string &s) {
        // get PT_CG2_GRP_CFG param
        if(id == gdt_grpc::PT_CG2_GRP_CFG){
            // parse as json
            json j = json::parse(s, nullptr, false);
            // json malformed
            if (j.is_discarded()) {
                // error
                throw std::invalid_argument("PT_CG2_GRP_CFG is malformed");
            }

            // process GRP config
            // check type
            if (!j.is_object()) {
                throw std::invalid_argument("group element != object");
            }

            // create GRP
            cg2_create_grp(j, s_cg2_r);
        }
        return true;
    });
}

/****************/
/* init handler */
/****************/
extern "C" int init(mink_utils::PluginManager *pm, mink_utils::PluginDescriptor *pd){
    // process cfg
    if (process_cfg(pm)) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [cannot process plugin configuration]");
        return 1;
    }

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

    // plugin cfg
    json *pcfg = nullptr;
    // get config
    try {
        pcfg = plg_get_config();

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [%s]",
                                  e.what());
        return -1;
    }

    // GRP root
    std::string s_cg2_r;
    // read cfg
    try {
        // get root path
        auto cg2_root = pcfg->at("root");
        if (!bfs::exists(cg2_root.get<std::string>())) {
            throw std::invalid_argument("cgroup2 root dir not found");
        }

        // root string
        s_cg2_r = cg2_root.get<std::string>();

    } catch (std::exception &e) {
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [%s]", e.what());
        return -3;
    }

    // UNIX socket local interface
    if(p_id.type() == mink_utils::PLG_DT_JSON_RPC){
        json *j_d = static_cast<json *>(p_id.data());
        try {
            // create json rpc parser
            json_rpc::JsonRpc jrpc(*j_d);
            // verify
            jrpc.verify(true);
            // get method
            int cmd_id = jrpc.get_method_id();
            // check command id
            switch (cmd_id) {
                case gdt_grpc::CMD_CG2_GROUP_CREATE:
                    impl_local_cg2_grp_create(jrpc, s_cg2_r);
                    break;

                default:
                    break;
            }

        } catch (std::exception &e) {
            mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                      "plg_cgroup2: [%s]",
                                      e.what());
            return -1;
        }
        return 0;
    }

    // plugin2plugin local interface
    if(p_id.type() == mink_utils::PLG_DT_SPECIFIC){
        // TODO
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


