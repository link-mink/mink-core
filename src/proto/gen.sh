#!/bin/bash

# protobuf
protoc --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin`  gdt.proto
protoc --cpp_out=. gdt.proto

# enums_only
rm -f gdt.pb.enums_only.h
cat gdt.pb.h |awk '/enum ParameterType/,/}/'|grep -v _SENTINEL_DO_NOT_USE_ >> params.tmp
cat gdt.pb.h |awk '/enum SysagentCommand/,/}/'|grep -v _SENTINEL_DO_NOT_USE_ >> cmds.tmp
sed  -i 's/^/    /'  cmds.tmp
sed  -i 's/^/    /'  params.tmp
cp gdt.pb.enums_only.txt gdt.pb.enums_only.h
sed "/@@/r params.tmp" -i gdt.pb.enums_only.h
sed "/@@/r cmds.tmp" -i gdt.pb.enums_only.h
sed -e "s/@@//g" -i gdt.pb.enums_only.h
rm -f cmds.tmp params.tmp
