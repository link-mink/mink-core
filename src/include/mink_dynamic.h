/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef MINK_DYNAMIC_H_
#define MINK_DYNAMIC_H_

namespace mink_dynamic {
    /**
     * Run external plugin command handler
     * @param[in]       _module         Pointer to module path
     * @param[in]       arg_names       Pointer to list of name arguments
     * @param[in]       arg_values      Pointer to list of value arguments
     * @param[in]       arg_count       Number of arguments
     * @param[in]       ncurses         Ncurses flag (if false, use std::cout)
     * @return          nullptr, reserved for future use
     */
    void *run_external_method_handler(const char *_module,
                                      const char **arg_names,
                                      const char **arg_values, 
                                      int arg_count,
                                      bool ncurses);
    /**
     * Run external plugin method
     * @param[in]       handle          Pointer to module handle
     * @param[in]       method          Pointer to method name
     * @param[in]       args            Pointer to list of arguments
     * @param[in]       argc            Number of arguments
     * @param[in]       ncurses         Ncurses flag (if false, use std::cout)
     * @return          Module dependent
     *
     */
    void *run_external_method(void *handle, 
                              const char *method, 
                              void **args,
                              int argc, 
                              bool ncurses);

    /**
     * Run external plugin command handler
     * @param[in]       _module         Pointer to module path
     * @param[in]       method          Pointer to method name
     * @param[in]       args            Pointer to list of arguments
     * @param[in]       argc            Number of arguments
     * @param[in]       ncurses         Ncurses flag (if false, use std::cout)
     * @return          nullptr, reserved for future use
     */
    void *run_external_method(const char *_module,
                              const char *method, 
                              void **args, 
                              int argc,
                              bool ncurses);
    /**
     * Load plugin
     * @param[in]       _module         Pointer to module path
     * @return          Plugin handle
     */
    void *load_plugin(const char *_module);

    /**
     * Unload plugin
     * @param[in]       handle          Plugin handle
     */
    void unload_plugin(void *handle);

} // namespace mink_dynamic

#endif /* ifndef MINK_DYNAMIC_H_ */
