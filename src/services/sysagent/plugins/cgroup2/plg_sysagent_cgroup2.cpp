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
        // set "cpu.max"
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

    CgroupDescriptor &create_grp(const std::string &grp, const std::string &p) {
        // error if GRP is already defined
        if (grps.find(grp) != grps.cend())
            throw std::invalid_argument("GRP already exists");

        // create
        auto it = grps.emplace(grp, CgroupDescriptor{.name = grp, .path = p});

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

    void grp_add_cntlr(CgroupDescriptor &grp, Cgroup2Controller *c){
        if (c && grp.cntrls.find(c->type) == grp.cntrls.cend()) {
            grp.cntrls.emplace(c->type, c);
        }
    }

    static Cgroup2Controller *create_cntrlr(Cgroup2CntrlrType type) {
        switch (type) {
            case CG2_CNTLR_CPU:
                return new Cg2CPU();
            case CG2_CNTLR_MEMORY:
                return new Cg2MEM();
            default:
                return nullptr;
        }
    }

private:
    std::map<std::string, CgroupDescriptor> grps;
    cg2_cntlr_type cg2_ct_map;
};

/***************/
/* Global vars */
/***************/
Cg2Manager cg2m;

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
    PluginsConfig *pcfg;
    // get daemon pointer
    auto dd = static_cast<SysagentdDescriptor *>(mink::CURRENT_DAEMON);
    // get config
    pcfg = static_cast<PluginsConfig *>(dd->dparams.get_pval<void *>(4));
    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    // get root path
    auto cg2_root = (*it)["root"];
    // root string
    std::string s_cg2_r = cg2_root.get<std::string>();
    // get groups array ref
    const auto j_grps = (*it)["groups"].get_ref<const json::array_t &>();

    // run
    while (!mink::CURRENT_DAEMON->DAEMON_TERMINATED){
        // proc lst
        ProcLst proc_lst;
        pm->run(gdt_grpc::CMD_GET_PROCESS_LST, &proc_lst, true);
        // iterate and verify groups
        for (auto it_g = j_grps.begin(); it_g != j_grps.end(); ++it_g) {
            // get GRP name
            auto j_name = (*it_g)["name"];
            std::string s_cg = j_name.get<std::string>();

            // set current cgroup parent and leaf (slice)
            std::string s_cg_l(s_cg2_r + "/" + s_cg + "/" + s_cg + ".slice");
            s_cg.insert(0, s_cg2_r + "/");

            // assigns processess to GRPs
            procs2grp(s_cg_l, *it_g, proc_lst);
        }
        // sleep 
        std::this_thread::sleep_for(stdc::milliseconds(intrvl));
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
                                  "plg_cgroup2: [configuration file missing]");
        return -1;
    }

    // find config for this plugin
    const auto &it = pcfg->cfg.find(PLG_ID);
    if(it == pcfg->cfg.cend()){
        mink::CURRENT_DAEMON->log(mink::LLT_ERROR,
                                  "plg_cgroup2: [configuration missing]");
        return -2;
    }

    // process
    try{
        // ec
        boost::system::error_code ec;
        // get root path
        auto cg2_root = it->at("root");
        if (!bfs::exists(cg2_root.get<std::string>())) {
            throw std::invalid_argument("cgroup2 root dir not found");
        }

        // process match thread interval
        auto j_intrvl = it->at("interval");
        if(!j_intrvl.is_number_unsigned()){
            throw std::invalid_argument("invalid process match interval");
        }
        unsigned int intrvl = j_intrvl.get<json::number_unsigned_t>();

        // root string
        std::string s_cg2_r = cg2_root.get<std::string>();

        // get groups array ref
        const auto j_grps = it->at("groups").get_ref<const json::array_t &>();

        // proc lst
        ProcLst proc_lst;
        pm->run(gdt_grpc::CMD_GET_PROCESS_LST, &proc_lst, true);

        // iterate and verify groups
        for (auto it_g = j_grps.begin(); it_g != j_grps.end(); ++it_g) {
            // check type
            if (!it_g->is_object()) {
                throw std::invalid_argument("group element != object");
            }
            // *******************************
            // *** Get GRP values (verify) ***
            // *******************************
            // get name
            auto j_name = it_g->at("name");
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
            auto ngrp = cg2m.create_grp(j_name.get<std::string>(), s_cg_l);

            /*************************************/
            /* Setup controllers for current GRP */
            /*************************************/
            // open "cgroup.subtree_control" for writing
            bfs::path sub_tree_fp(s_cg + "/cgroup.subtree_control");
            if (!bfs::exists(sub_tree_fp)) {
                throw std::invalid_argument("subtree_control not found");
            }
            bfs::ofstream sub_tree_fs(sub_tree_fp);

            // get controllers
            const auto j_cntrls = it_g->at("controllers").get_ref<const json::array_t &>();
            // iterate and verify controllers
            for (auto it_c = j_cntrls.begin(); it_c != j_cntrls.end(); ++it_c) {
                // check type
                if (!it_c->is_string()) {
                    throw std::invalid_argument("controller element != string");
                }
                // get controller (string)
                std::string cntrlr = (*it_c).get<std::string>();
                // enable controller
                sub_tree_fs << "+" << cntrlr << "\n";
                sub_tree_fs.flush();
                // add to CG2Manager
                if (!cg2m.validate_cntlr(cntrlr)) {
                    throw std::invalid_argument("invalid controller type");
                }
                auto newc = cg2m.create_cntrlr(cg2m.cntlr_str2type(cntrlr));
                // process controller values
                if (newc){
                    newc->process(*it_g, ngrp);
                    cg2m.grp_add_cntlr(ngrp, newc);
                }
            }
            // enable controlers (newline to "cgroup.subtree_control" file)
            sub_tree_fs.close();

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


// Implementation of "test" command
static void impl_test(gdt::ServiceMessage *smsg){
    
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


