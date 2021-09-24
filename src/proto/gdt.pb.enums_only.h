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

#ifndef GDT_GRPC_COMMANDS_H
#define GDT_GRPC_COMMANDS_H 

namespace gdt_grpc {
    
    enum SysagentCommand : int {
      UNKNWON_COMMAND = 0,
      CMD_GET_SYSINFO = 1,
      CMD_GET_CPUSTATS = 2,
      CMD_GET_MEMINFO = 3,
      CMD_GET_UNAME = 4,
      CMD_GET_PROCESS_LST = 5,
      CMD_GET_FILE_STAT = 6,
      CMD_UBUS_CALL = 7,
      CMD_SHELL_EXEC = 8,
    };
    enum ParameterType : int {
      UNKNWON_PARAMETER = 0,
      PT_CPU_USER_PERCENT = 9000,
      PT_CPU_NICE_PERCENT = 9001,
      PT_CPU_SYSTEM_PERCENT = 9002,
      PT_SI_LOAD_AVG_1_MIN = 9003,
      PT_SI_LOAD_AVG_5_MIN = 9004,
      PT_SI_LOAD_AVG_15_MIN = 9005,
      PT_SI_MEM_TOTAL = 9006,
      PT_SI_MEM_FREE = 9007,
      PT_SI_MEM_BUFFERS = 9008,
      PT_SI_MEM_SWAP_TOTAL = 9009,
      PT_SI_MEM_SWAP_FREE = 9010,
      PT_SI_MEM_HIGH_TOTAL = 9011,
      PT_SI_MEM_HIGH_FREE = 9012,
      PT_SI_MEM_UNIT_SIZE = 9013,
      PT_MI_TOTAL = 9014,
      PT_MI_FREE = 9015,
      PT_MI_BUFFERS = 9016,
      PT_MI_CACHED = 9017,
      PT_UNM_SYSNAME = 9018,
      PT_UNM_NODENAME = 9019,
      PT_UNM_RELEASE = 9020,
      PT_UNM_VERSION = 9021,
      PT_UNM_MACHINE = 9022,
      PT_PL_CMD = 9023,
      PT_PL_TID = 9024,
      PT_PL_PPID = 9025,
      PT_PL_RESIDENT = 9026,
      PT_PL_UTIME = 9027,
      PT_PL_STIME = 9028,
      PT_OWRT_UBUS_PATH = 9029,
      PT_OWRT_UBUS_METHOD = 9030,
      PT_OWRT_UBUS_ARG = 9031,
      PT_OWRT_UBUS_RESULT = 9032,
      PT_SHELL_CMD = 9033,
      PT_SHELL_STDOUT = 9034,
      PT_SHELL_STDERR = 9035,
      PT_SHELL_EXIT_CODE = 9036,
    };
}

#endif /* ifndef GDT_GRPC_COMMANDS_H */
