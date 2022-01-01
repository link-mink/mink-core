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
/*
    pid_t pid = 0;
    int pipefd[2];
    FILE *output;

    pipe(pipefd); // create a pipe
    pid = fork(); // span a child process

    if (pid == 0) {
        // Child. Let's redirect its standard output to our pipe and replace
        // process with tail
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        //execl("/usr/bin/journalctl", "/usr/bin/journalctl", "-f", NULL);
        execl("/usr/bin/ping", "/usr/bin/ping", "8.8.8.8", NULL);
    }

    // Only parent gets here. Listen to what the tail says
    close(pipefd[1]);
    output = fdopen(pipefd[0], "r");
    int fd = fileno(output);  
    fcntl(fd, F_SETFL, O_NONBLOCK);

    auto start_time = std::chrono::steady_clock::now();
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;;
    char buff[1024];
    while(1){
        int res = poll(&pfd, 1, 1000);
        if(res == 1 && (pfd.revents & POLLIN)){

            int br = read(fd, buff, sizeof(buff));
            if(br <= 0) continue;
            buff[br] = '\0'; 
            printf("%s", buff);
        }
        
        auto ts = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(ts - start_time);

        if (ms.count() > 5000) {
            kill(pid, SIGKILL);
            break;
        }   

    }
    int status;
    // or wait for the child process to terminate
    waitpid(pid, &status, 0);
*/

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
