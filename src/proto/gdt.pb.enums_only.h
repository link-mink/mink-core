/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef GDT_GRPC_COMMANDS_H
#define GDT_GRPC_COMMANDS_H 

#include <map>
#include <string>

namespace gdt_grpc {
    
    enum ParameterType : int {
      UNKNWON_PARAMETER = 0,
      PT_MINK_DTYPE = 6000,
      PT_MINK_DID = 6001,
      PT_MINK_ERROR = 6016,
      PT_MINK_ERROR_MSG = 6017,
      PT_MINK_STATUS = 6018,
      PT_MINK_STATUS_MSG = 6019,
      PT_MINK_PERSISTENT_CORRELATION = 6020,
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
      PT_SP_TYPE = 9037,
      PT_SP_PATH = 9038,
      PT_SP_PAYLOAD = 9039,
      PT_FU_DATA = 9040,
      PT_FU_FSIZE = 9041,
      PT_SL_LOGLINE = 9042,
      PT_SL_PORT = 9043,
      PT_RE_PORT = 9044,
      PT_NET_IP = 9045,
      PT_NET_PORT = 9046,
    };
    static const std::map<int, std::string> SysagentParamMap = {
      {UNKNWON_PARAMETER, "UNKNWON_PARAMETER"}, 
      {PT_MINK_DTYPE, "PT_MINK_DTYPE"}, 
      {PT_MINK_DID, "PT_MINK_DID"}, 
      {PT_MINK_ERROR, "PT_MINK_ERROR"}, 
      {PT_MINK_ERROR_MSG, "PT_MINK_ERROR_MSG"}, 
      {PT_MINK_STATUS, "PT_MINK_STATUS"}, 
      {PT_MINK_STATUS_MSG, "PT_MINK_STATUS_MSG"}, 
      {PT_MINK_PERSISTENT_CORRELATION, "PT_MINK_PERSISTENT_CORRELATION"}, 
      {PT_CPU_USER_PERCENT, "PT_CPU_USER_PERCENT"}, 
      {PT_CPU_NICE_PERCENT, "PT_CPU_NICE_PERCENT"}, 
      {PT_CPU_SYSTEM_PERCENT, "PT_CPU_SYSTEM_PERCENT"}, 
      {PT_SI_LOAD_AVG_1_MIN, "PT_SI_LOAD_AVG_1_MIN"}, 
      {PT_SI_LOAD_AVG_5_MIN, "PT_SI_LOAD_AVG_5_MIN"}, 
      {PT_SI_LOAD_AVG_15_MIN, "PT_SI_LOAD_AVG_15_MIN"}, 
      {PT_SI_MEM_TOTAL, "PT_SI_MEM_TOTAL"}, 
      {PT_SI_MEM_FREE, "PT_SI_MEM_FREE"}, 
      {PT_SI_MEM_BUFFERS, "PT_SI_MEM_BUFFERS"}, 
      {PT_SI_MEM_SWAP_TOTAL, "PT_SI_MEM_SWAP_TOTAL"}, 
      {PT_SI_MEM_SWAP_FREE, "PT_SI_MEM_SWAP_FREE"}, 
      {PT_SI_MEM_HIGH_TOTAL, "PT_SI_MEM_HIGH_TOTAL"}, 
      {PT_SI_MEM_HIGH_FREE, "PT_SI_MEM_HIGH_FREE"}, 
      {PT_SI_MEM_UNIT_SIZE, "PT_SI_MEM_UNIT_SIZE"}, 
      {PT_MI_TOTAL, "PT_MI_TOTAL"}, 
      {PT_MI_FREE, "PT_MI_FREE"}, 
      {PT_MI_BUFFERS, "PT_MI_BUFFERS"}, 
      {PT_MI_CACHED, "PT_MI_CACHED"}, 
      {PT_UNM_SYSNAME, "PT_UNM_SYSNAME"}, 
      {PT_UNM_NODENAME, "PT_UNM_NODENAME"}, 
      {PT_UNM_RELEASE, "PT_UNM_RELEASE"}, 
      {PT_UNM_VERSION, "PT_UNM_VERSION"}, 
      {PT_UNM_MACHINE, "PT_UNM_MACHINE"}, 
      {PT_PL_CMD, "PT_PL_CMD"}, 
      {PT_PL_TID, "PT_PL_TID"}, 
      {PT_PL_PPID, "PT_PL_PPID"}, 
      {PT_PL_RESIDENT, "PT_PL_RESIDENT"}, 
      {PT_PL_UTIME, "PT_PL_UTIME"}, 
      {PT_PL_STIME, "PT_PL_STIME"}, 
      {PT_OWRT_UBUS_PATH, "PT_OWRT_UBUS_PATH"}, 
      {PT_OWRT_UBUS_METHOD, "PT_OWRT_UBUS_METHOD"}, 
      {PT_OWRT_UBUS_ARG, "PT_OWRT_UBUS_ARG"}, 
      {PT_OWRT_UBUS_RESULT, "PT_OWRT_UBUS_RESULT"}, 
      {PT_SHELL_CMD, "PT_SHELL_CMD"}, 
      {PT_SHELL_STDOUT, "PT_SHELL_STDOUT"}, 
      {PT_SHELL_STDERR, "PT_SHELL_STDERR"}, 
      {PT_SHELL_EXIT_CODE, "PT_SHELL_EXIT_CODE"}, 
      {PT_SP_TYPE, "PT_SP_TYPE"}, 
      {PT_SP_PATH, "PT_SP_PATH"}, 
      {PT_SP_PAYLOAD, "PT_SP_PAYLOAD"}, 
      {PT_FU_DATA, "PT_FU_DATA"}, 
      {PT_FU_FSIZE, "PT_FU_FSIZE"}, 
      {PT_SL_LOGLINE, "PT_SL_LOGLINE"}, 
      {PT_SL_PORT, "PT_SL_PORT"}, 
      {PT_RE_PORT, "PT_RE_PORT"}, 
      {PT_NET_IP, "PT_NET_IP"}, 
      {PT_NET_PORT, "PT_NET_PORT"}, 
    };
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
      CMD_SET_DATA = 9,
      CMD_RUN_RULES = 10,
      CMD_LOAD_RULES = 11,
      CMD_AUTH = 12,
      CMD_SOCKET_PROXY = 13,
      CMD_FIRMWARE_UPDATE = 14,
      CMD_SYSLOG_START = 15,
      CMD_SYSLOG_STOP = 16,
      CMD_REMOTE_EXEC_START = 17,
      CMD_REMOTE_EXEC_STOP = 18,
      CMD_GET_SYSMON_DATA = 19,
      CMD_NET_TCP_SEND = 20,
      CMD_CG2_GROUP_CREATE = 21,
      CMD_CG2_GROUP_DELETE = 22,
      CMD_CG2_GROUPS_LST = 23,
      CMD_CG2_CONTROLLER_GET = 24,
      CMD_CG2_CONTROLLER_SET = 25,
      CMD_CG2_CONTROLLERS_LST = 26,
    };
    static const std::map<int, std::string> SysagentCommandMap = {
      {UNKNWON_COMMAND, "UNKNWON_COMMAND"}, 
      {CMD_GET_SYSINFO, "CMD_GET_SYSINFO"}, 
      {CMD_GET_CPUSTATS, "CMD_GET_CPUSTATS"}, 
      {CMD_GET_MEMINFO, "CMD_GET_MEMINFO"}, 
      {CMD_GET_UNAME, "CMD_GET_UNAME"}, 
      {CMD_GET_PROCESS_LST, "CMD_GET_PROCESS_LST"}, 
      {CMD_GET_FILE_STAT, "CMD_GET_FILE_STAT"}, 
      {CMD_UBUS_CALL, "CMD_UBUS_CALL"}, 
      {CMD_SHELL_EXEC, "CMD_SHELL_EXEC"}, 
      {CMD_SET_DATA, "CMD_SET_DATA"}, 
      {CMD_RUN_RULES, "CMD_RUN_RULES"}, 
      {CMD_LOAD_RULES, "CMD_LOAD_RULES"}, 
      {CMD_AUTH, "CMD_AUTH"}, 
      {CMD_SOCKET_PROXY, "CMD_SOCKET_PROXY"}, 
      {CMD_FIRMWARE_UPDATE, "CMD_FIRMWARE_UPDATE"}, 
      {CMD_SYSLOG_START, "CMD_SYSLOG_START"}, 
      {CMD_SYSLOG_STOP, "CMD_SYSLOG_STOP"}, 
      {CMD_REMOTE_EXEC_START, "CMD_REMOTE_EXEC_START"}, 
      {CMD_REMOTE_EXEC_STOP, "CMD_REMOTE_EXEC_STOP"}, 
      {CMD_GET_SYSMON_DATA, "CMD_GET_SYSMON_DATA"}, 
      {CMD_NET_TCP_SEND, "CMD_NET_TCP_SEND"}, 
      {CMD_CG2_GROUP_CREATE, "CMD_CG2_GROUP_CREATE"}, 
      {CMD_CG2_GROUP_DELETE, "CMD_CG2_GROUP_DELETE"}, 
      {CMD_CG2_GROUPS_LST, "CMD_CG2_GROUPS_LST"}, 
      {CMD_CG2_CONTROLLER_GET, "CMD_CG2_CONTROLLER_GET"}, 
      {CMD_CG2_CONTROLLER_SET, "CMD_CG2_CONTROLLER_SET"}, 
      {CMD_CG2_CONTROLLERS_LST, "CMD_CG2_CONTROLLERS_LST"}, 
    };
}

#endif /* ifndef GDT_GRPC_COMMANDS_H */
