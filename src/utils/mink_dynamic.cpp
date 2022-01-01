/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <dlfcn.h>
#include <mink_dynamic.h>
#include <iostream>
#include <ncurses.h>

void *mink_dynamic::run_external_method_handler(const char *_module,
                                                const char **arg_names,
                                                const char **arg_values,
                                                int arg_count, 
                                                bool ncurses) {
    void *handle = dlopen(_module, RTLD_LAZY);
    if (handle != nullptr) {
        using exec_method = void *(*)(const char **, const char **, int);
        dlerror();
        exec_method exec_m = (exec_method)dlsym(handle, "method_handler");
        const char *dlsym_error = dlerror();
        if (dlsym_error) {
            if (ncurses)
                printw("Cannot load symbol 'method_handler': %s\n",
                       dlsym_error);
            else
                std::cout << "Cannot load symbol 'method_handler': "
                          << dlsym_error << std::endl;
            dlclose(handle);
        } else {
            void *res = exec_m(arg_names, arg_values, arg_count);
            if (ncurses)
                printw("\n");
            else
                std::cout << std::endl;
            dlclose(handle);
            return res;
        }

    } else {
        if (ncurses)
            printw("Cannot open library: %s\n", dlerror());
        else
            std::cout << "Cannot open library: " << dlerror() << std::endl;
    }
    return nullptr;
}

void *mink_dynamic::run_external_method(void *handle, 
                                        const char *method,
                                        void **args, 
                                        int argc, 
                                        bool ncurses) {
    if (handle != nullptr) {
        using exec_block = void *(*)(void **, int);
        dlerror();
        exec_block exec_b = (exec_block)dlsym(handle, method);
        const char *dlsym_error = dlerror();
        if (dlsym_error) {
            if (ncurses)
                printw("Cannot load symbol '%s': %s\n", method, dlsym_error);
            else
                std::cout << "Cannot load symbol '" << method
                          << "': " << dlsym_error << std::endl;
            dlclose(handle);
        } else {
            return exec_b(args, argc);
        }

    } else {
        if (ncurses)
            printw("Cannot open library: %s\n", dlerror());
        else
            std::cout << "Cannot open library: " << dlerror() << std::endl;
    }
    return nullptr;
}

void *mink_dynamic::run_external_method(const char *_module, 
                                        const char *method,
                                        void **args, 
                                        int argc, 
                                        bool ncurses) {
    void *handle = dlopen(_module, RTLD_LAZY);
    if (handle != nullptr) {
        using exec_block = void *(*)(void **, int);
        dlerror();
        exec_block exec_b = (exec_block)dlsym(handle, method);
        const char *dlsym_error = dlerror();
        if (dlsym_error) {
            if (ncurses)
                printw("Cannot load symbol '%s': %s\n", method, dlsym_error);
            else
                std::cout << "Cannot load symbol '" << method
                          << "': " << dlsym_error << std::endl;
            dlclose(handle);
        } else {
            void *res = exec_b(args, argc);
            dlclose(handle);
            return res;
        }

    } else {
        if (ncurses)
            printw("Cannot open library: %s\n", dlerror());
        else
            std::cout << "Cannot open library: " << dlerror() << std::endl;
    }
    return nullptr;
}

void *mink_dynamic::load_plugin(const char *_module) {
    return dlopen(_module, RTLD_LAZY);
}

void mink_dynamic::unload_plugin(void *handle) { dlclose(handle); }

