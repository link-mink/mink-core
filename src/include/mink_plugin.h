/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_PLUGIN
#define MINK_PLUGIN 

#include <daemon.h>

namespace mink_utils {
    /**
     * Plugin function names
     */
    extern std::string const PLG_INIT_FN;
    extern std::string const PLG_TERM_FN;
    extern std::string const PLG_CMD_HNDLR;
    extern std::string const PLG_CMD_LST;

    // fwd declaration
    struct PluginDescriptor;


    /** MINK plugin manager */
    class PluginManager {
    public:
        /**
         * Plugin terminate handler
         *
         * @param[in]   pm      Pointer to MINK plugin manager
         * @param[in]   pd      Pointer to plugin descriptor
         * @return      0 for success
         */
        typedef int (*plg_init_t)(PluginManager *pm, PluginDescriptor *pd);

        /**
         * Plugin terminate handler
         *
         * @param[in]   pm      Pointer to MINK plugin manager
         * @param[in]   pd      Pointer to plugin descriptor
         * @return      0 for success
         */
        typedef int (*plg_term_t)(PluginManager *pm, PluginDescriptor *pd);

        /**
         * Plugin cmd handler
         *
         * @param[in]       pm      Pointer to MINK plugin manager
         * @param[in]       pd      Pointer to plugin descriptor
         * @param[in]       hk      MINK daemon hook
         * @param[in,out]   data    Custom data
         * @return          0 for success
         */
        typedef int (*plg_cmd_hndlr_t)(PluginManager *pm,
                                       PluginDescriptor *pd,
                                       int cmd_id,
                                       void* data);


        PluginManager();
        explicit PluginManager(mink::DaemonDescriptor *dd);
        ~PluginManager();

        /**
         * Load and verify plugin
         *
         * @param[in]   pm          Pointer to plugin manager
         * @param[in]   fpath       Plugin file path
         * @return      new plugin descriptor or NULL on error
         */
         PluginDescriptor *load(const std::string &fpath);

        /**
         * Unload plugin; call plugin's terminate method and
         * remove from list of active plugins
         *
         * @param[in]   pd          Pointer to plugin descriptor
         * @return      0 for success or error
         */
        int unload(PluginDescriptor *pd);

        /**
         * Run plugin hook
         *
         * @param[in]   cmd_id  Command id
         * @param[in]   data    Custom data
         *
         * @return      0 for success or error code
         */
        int run(int cmd_id, void *data);

    private:
        /** Pointer to MINK daemon descriptor */
        mink::DaemonDescriptor *dd;
        /** List of loaded plugins */
        std::vector<PluginDescriptor*> plgs;
        /** List of hooks and plugins attached to them */
        std::map<int, PluginDescriptor*> hooks;
    };

    /**
     * Plugin descriptor
     */
    struct PluginDescriptor {
        /** Plugin handle */
        void *handle;
        /** Plugin name */
        std::string name;
        /** Plugin type */
        int type;
        /** Plugin cmd handler method */
        PluginManager::plg_cmd_hndlr_t cmdh;
        /** Plugin terminate method */
        PluginManager::plg_term_t termh;
        /** Custom data filled by plugin */
        void *data;
    };


}

#endif /* ifndef MINK_PLUGIN */
