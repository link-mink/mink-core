#!/bin/bash

# protobuf
protoc --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin`  gdt.proto
protoc --cpp_out=. gdt.proto

# enums_only
rm -f gdt.pb.enums_only.h
cat gdt.pb.h | awk '/enum ParameterType/,/}/' | grep -v _SENTINEL_DO_NOT_USE_ >> params.tmp
cat gdt.pb.h | awk '/enum SysagentCommand/,/}/' | grep -v _SENTINEL_DO_NOT_USE_ >> cmds.tmp
sed  -i 's/^/    /'  cmds.tmp
sed  -i 's/^/    /'  params.tmp
cp gdt.pb.enums_only.txt gdt.pb.enums_only.h
# cmd to string mapping
echo "    static const std::map<int, std::string> SysagentCommandMap = {" >> cmds_map.tmp
cat cmds.tmp | sed -e 's/^ \+//'g | tail +2 | grep -v '}' | sed -e 's/\(.*\) = \(.*\),/      {\1, "\1"}, /g' >> cmds_map.tmp
echo "    };" >> cmds_map.tmp
sed "/@@/r cmds_map.tmp" -i gdt.pb.enums_only.h
sed "/@@/r cmds.tmp" -i gdt.pb.enums_only.h
# params to string mapping
echo "    static const std::map<int, std::string> SysagentParamMap = {" >> params_map.tmp
cat params.tmp | sed -e 's/^ \+//'g | tail +2 | grep -v '}' | sed -e 's/\(.*\) = \(.*\),/      {\1, "\1"}, /g' >> params_map.tmp
echo "    };" >> params_map.tmp
sed "/@@/r params_map.tmp" -i gdt.pb.enums_only.h
sed "/@@/r params.tmp" -i gdt.pb.enums_only.h
# cleanup
sed -e "s/@@//g" -i gdt.pb.enums_only.h
rm -f cmds.tmp params.tmp cmds_map.tmp params_map.tmp
