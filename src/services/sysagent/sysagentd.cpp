/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "sysagent.h"
#include <sys/wait.h>
#include <fcntl.h>

// main
int main(int argc, char **argv) {
    // create daemon
    SysagentdDescriptor dd(DAEMON_TYPE, DAEMON_DESCRIPTION);
    // process arguments
    dd.process_args(argc, argv);
    // init/start daemon
    mink::daemon_start(&dd);
    signal(SIGTERM, &mink::signal_handler);
    // init
    dd.init();
    // loop until terminated
    mink::daemon_loop(&dd);
    // sleep couple of seconds
    sleep(5);
    // normal exit
    return 0;
}
