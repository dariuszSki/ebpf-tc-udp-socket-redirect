/*    Copyright (C) 2022  Robert Caamano   */
 /*
  *   This program redirects udp packets that match specific destination prefixes & src/dst ports
  *   to either openziti edge-router tproxy port or to a locally hosted openziti service socket
  *   depending on whether there is an existing egress socket. 
  *
  *   This program is free software: you can redistribute it and/or modify
  *   it under the terms of the GNU General Public License as published by
  *   the Free Software Foundation, either version 3 of the License, or
  *   (at your option) any later version.

  *   This program is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *   GNU General Public License for more details.
  *   see <https://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <arpa/inet.h>

#define OPTIONS_LEVEL_SIZE      10 // characters long
#define DEBUG                   1
#define TRACE                   2
#define INFO                    0

struct options_key {
    char log_verbosity[OPTIONS_LEVEL_SIZE]; // [verbose]
};

struct options_tuple {
    int log_level; // [debug=1,trace=2,info=0]
};

int main(int argc, char **argv){
    /* Make sure user enters correct number of agrguments */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <log level [debug, trace, info]> \n", argv[0]);
        exit(0);
    }

    /* Open options_map */
    union bpf_attr options_map;
    const char *options_map_path = "/sys/fs/bpf/tc/globals/geneve_options_map";

    /* Check command line vars verification*/
    struct options_key key = {"verbose"};
    struct options_tuple optt;
    char allowed_log_level[][OPTIONS_LEVEL_SIZE] = {"debug","trace","info"};
    int len = sizeof(allowed_log_level)/sizeof(allowed_log_level[0]);
    bool match = false;
    /* first argument */
    for (int i = 0; i < len; ++i) {
        if (strncmp(argv[1],allowed_log_level[i],OPTIONS_LEVEL_SIZE) == 0) {
            match = true;
        }
    }
    if (!match ) {
            fprintf(stderr, "Log Level %s is not supported.\n", argv[1]);
            exit(0);
    } else {
        if (strncmp(argv[1],"debug",OPTIONS_LEVEL_SIZE) == 0) {
            optt.log_level = DEBUG;
        } else if (strncmp(argv[1],"trace",OPTIONS_LEVEL_SIZE) == 0) {
            optt.log_level = TRACE;
        } else { 
            optt.log_level = INFO;
        }
    }

    /* open BPF options_map */
    memset(&options_map, 0, sizeof(options_map));
    /* set path name with location of map in filesystem */
    options_map.pathname = (uint64_t) options_map_path;
    options_map.bpf_fd = 0;
    options_map.file_flags = 0;
    /* make system call to get fd for options_map */
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &options_map, sizeof(options_map));
    if (fd == -1){
	    printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    options_map.map_fd = fd;
    options_map.key = (uint64_t)&key;
    options_map.value = (uint64_t)&optt;
    /* Add new entry to options map */
    options_map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &options_map, sizeof(options_map));
    if (result){
	    printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
    } else {
        printf("MAP element updated or created\n");
    }
    close(fd);
}
