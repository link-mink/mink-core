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
#include <iostream>
#include <string>
#include <unistd.h> 
#include <map>
#include <sys/stat.h>
#include <getopt.h>
#include <inja.hpp>
using namespace inja;
using json = nlohmann::json;


/*****************************/
/* Code generator base class */
/*****************************/
class CodeGenBase {
public:
    CodeGenBase(const std::string &n, const std::string &d)
        : name(n), description(d) {}
    virtual ~CodeGenBase() {}

    /**
     * process generator arguments
     *
     * @param[in]   argc    Argument count
     * @param[in]   argv    Argument list
     */
    virtual void process(int argc, char **argv) = 0;

     /**
     * print generator specific help
     */
    virtual void help() = 0;

    /** generator description */
    std::string description;
    /** generator name */
    std::string name;

};

/*************************/
/* Plugin code generator */
/*************************/
class CodeGenPlugin: public CodeGenBase {
public:
    CodeGenPlugin(const std::string &n, const std::string &d)
        : CodeGenBase(n, d) {}
    void process(int argc, char **argv){
        int opt;
        int option_index = 0;
        struct option long_options[] = {{0, 0, 0, 0}};
        // data
        json data;
        data["cmds"];
        data["plg"];
        std::string plg_name;
 
        while ((opt = getopt_long(argc, argv, "a:p:", long_options,
                                  &option_index)) != -1) {
            switch (opt) {
                // stub argument
                case 'a':
                    data["cmds"].push_back(optarg);
                    break;

                // plugin name
                case 'p':
                    plg_name = optarg;
                    data["plg"] = plg_name;
                    break;
            }
        }
        if(data["cmds"].size() == 0){
            std::cout << "Command name(s) missing!" << std::endl;
            help();
            return;
        }
        if(plg_name.empty()){
            std::cout << "Plugin name is undefined!" << std::endl;
            help();
            return;
        }

        // paths
        std::string path("./src/codegen/");
        std::string plg_dir("./src/services/sysagent/plugins/" + plg_name);
        
        // create plugin dir
        std::cout << "Creating plugin [" << plg_name
                  << "] directory: " << plg_dir << std::endl;
        const int dir_err = mkdir(plg_dir.c_str(), 
                                  S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (dir_err) {
            std::cout << "Cannot create plugin directory!" << std::endl;
            exit(1);
        }

        // environment
        Environment env{path, plg_dir + "/"};

        // generate plugin source
        Template temp = env.parse_template("tmpl_plugin.txt");
        std::cout << "Generating plugin source code..." << std::endl;
        env.write(temp, data, "plg_sysagent_" + plg_name + ".cpp");

        // generate makefile
        temp = env.parse_template("tmpl_plg_make.txt");
        std::cout << "Generating Makefile.am..." << std::endl;
        env.write(temp, data, "Makefile.am");

        // update proto definition
        for (json::iterator it = data["cmds"].begin(); it != data["cmds"].end(); ++it) {
            std::string cmd_str((*it).get<std::string>());
            chdir("./src/proto");
            system(std::string("./add_cmd.sh " + cmd_str).c_str());
            
        } 
        system(std::string("./add_plg.sh " + plg_name).c_str());
        system("./gen.sh");

    }

    void help(){
        std::cout << "[" << name << "] generator command line arguments"
                  << std::endl;
        std::cout << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << " -p\tplugin name" << std::endl;
        std::cout << " -a\tcommand name" << std::endl;
        std::cout << std::endl;
    }
};

/**********************************/
/* Stub type -> generator mapping */
/**********************************/
std::map<std::string, CodeGenBase*> genmap = {
    {"plugin", new CodeGenPlugin("plugin", "system agent plugin")}
};

/*********************/
/* Command line help */
/*********************/
void print_help(){
    std::cout << "mink code generator" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -?\thelp" << std::endl;
    std::cout << " -t\tstub type" << std::endl;
    std::cout << " -a\tstub argument (depends on type)" << std::endl;
    std::cout << " -o\toutput file name (without extension)" << std::endl;
    std::cout << std::endl;
}

/**
 * process command line arguments
 *
 * @param[in]   argc    Argument count
 * @param[in]   argv    Argument list
 */
void process_args(int argc, char **argv){
    int opt;
    int option_index = 0;
    struct option long_options[] = {{0, 0, 0, 0}};
    opterr = 0;

    if (argc < 2) {
        print_help();
        exit(EXIT_FAILURE);
        return;
    }

    while ((opt = getopt_long(argc, argv, "?t:a:o:", long_options,
                              &option_index)) != -1) {
        switch (opt) {
            // long options
            case 0:
                break;

            // help
            case '?':
                print_help();
                exit(EXIT_FAILURE);

            // stub type
            case 't':
            {
                auto it = genmap.find(optarg);
                if(it != genmap.end()){
                    it->second->process(argc, argv);
                    return;
                }
                std::cout << "The following generators are supported:"
                          << std::endl;
                for (auto it = genmap.begin(); it != genmap.end(); it++) {
                    std::cout << "[" << it->second->name << "] - "
                              << it->second->description << std::endl;
                }

                break;
            }
            // stub argument
            case 'a':
                break;

            // output filename
            case 'o':
                break;
        }
            
    }


}

// main
int main(int argc, char **argv) {
    // process args
    process_args(argc, argv);
    // normal exit
    return 0;
}
