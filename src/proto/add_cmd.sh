#!/bin/bash

CMD=${1^^}
PLG=$2
PF="gdt.proto"
#COF="gdt.pb.cmds_only.h"

# proto file
LN=`cat $PF|awk '/enum SysagentCommand/,/}/{print NR}'|tail -1`
LID=`cat $PF|awk '/enum SysagentCommand/,/}/'|tail -2|head -1|xargs|cut -f3 -d' '|tr -d ';'`
sed -i "$LN i \ \ \ \ CMD_$CMD = $(($LID + 1));" $PF

# cmd only file
#LN=`cat $COF|awk '/enum SysagentCommand/,/}/{print NR}'|tail -1`
#LID=`cat $COF|awk '/enum SysagentCommand/,/}/'|tail -2|head -1|xargs|cut -f3 -d' '|tr -d ','`
#sed -i "$LN i \ \ \ \ \ \ CMD_$CMD = $(($LID + 1))," $COF
