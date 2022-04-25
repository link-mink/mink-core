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
#include <vector>

namespace mink_utils {
    // types
    using Plugin_args = std::vector<std::string>;
    using Plugin_data_std = std::vector<std::map<std::string, std::string>>;

    /**
     * Plugin function names
     */
    extern std::string const PLG_INIT_FN;
    extern std::string const PLG_TERM_FN;
    extern std::string const PLG_CMD_HNDLR;
    extern std::string const PLG_CMD_HNDLR_LOCAL;
    extern std::string const PLG_CMD_LST;

    // fwd declaration
    struct PluginDescriptor;

    // input data type for local interface
    enum PluginDataType {
        // unknown data type (error)
        PLG_DT_UNKNOWN  = 0,
        // JSON-RPC (UNIX socket)
        PLG_DT_JSON_RPC = 1,
        // plugin-specific (custom plugin2plugin)
        PLG_DT_SPECIFIC = 2,
        // GDT smsg IN/OUT (network)
        PLG_DT_GDT      = 3,
        // plugin-to-plugin standard in/out format
        // (standard plugin2plugin)
        PLG_DT_STANDARD = 4
    };

    // plugin input data wrapper
    class PluginInputData {
    public:
        PluginInputData() : type_(PLG_DT_UNKNOWN), data_(nullptr) {}
        ~PluginInputData() = default;
        explicit PluginInputData(PluginDataType type, void *data)
            : type_(type)
            , data_(data) {}

        PluginDataType type() const { return type_; }
        void *data() { return data_; }

    private:
        PluginDataType type_;
        void *data_;
    };

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
        using plg_init_t = int (*)(PluginManager *pm, PluginDescriptor *pd);

        /**
         * Plugin terminate handler
         *
         * @param[in]   pm      Pointer to MINK plugin manager
         * @param[in]   pd      Pointer to plugin descriptor
         * @return      0 for success
         */
        using plg_term_t = int (*)(PluginManager *pm, PluginDescriptor *pd);

        /**
         * Plugin cmd handler
         *
         * @param[in]       pm      Pointer to MINK plugin manager
         * @param[in]       pd      Pointer to plugin descriptor
         * @param[in]       hk      MINK daemon hook
         * @param[in,out]   data    Custom data
         * @return          0 for success
         */
        using plg_cmd_hndlr_t = int (*)(PluginManager *pm,
                                        PluginDescriptor *pd,
                                        int cmd_id,
                                        PluginInputData &data);


        PluginManager() = default;
        PluginManager(const PluginManager &o) = delete;
        PluginManager &operator=(const PluginManager &o) = delete;
        explicit PluginManager(mink::DaemonDescriptor *_dd);
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
         * @param[in]   data    Custom data (input/output)
         * @param[in]   local   Local request flag
         *
         * @return      0 for success or error code
         */
        int run(int cmd_id, PluginInputData &data, bool is_local = false);
        // rvalue variant for data argument
        int run(int cmd_id, PluginInputData &&data, bool is_local = false);

    private:
        /** Pointer to MINK daemon descriptor */
        mink::DaemonDescriptor *dd = nullptr;
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
        /** Plugin cmd handler method (local) */
        PluginManager::plg_cmd_hndlr_t cmdh_l;
        /** Plugin terminate method */
        PluginManager::plg_term_t termh;
        /** Custom data filled by plugin */
        void *data;
    };


}

#endif /* ifndef MINK_PLUGIN */
