#            _       _
#  _ __ ___ (_)_ __ | | __
# | '_ ` _ \| | '_ \| |/ /
# | | | | | | | | | |   <
# |_| |_| |_|_|_| |_|_|\_\
#
# SPDX-License-Identifier: MIT
#

# aclocal m4 dir
ACLOCAL_AMFLAGS = -I m4
# subdirs
SUBDIRS = lib/libantlr3c-3.4

# check for debug mode [--enable-debug]
if ENABLE_DEBUG
CXXFLAGS += -O${OLEVEL} -g 
else
CXXFLAGS += -O${OLEVEL}
endif

# check for pmdebug mode [--enable-pmdebug]
if ENABLE_PMDEBUG
CPPFLAGS += -DPMDEBUG
endif

ANTLR_FLAGS = -Ilib/libantlr3c-3.4/include -Ilib/libantlr3c-3.4
ANTLR_LDLIBS = -lantlr3c -Llib/libantlr3c-3.4/.libs

# compiler and linkerflags
COMMON_INCLUDES = -Isrc/include

# MINK directories
confdir = $(sysconfdir)/mink

# MINK git generated files
BUILT_SOURCES = VERSION CHANGELOG AUTHORS
CLEANFILES = VERSION CHANGELOG AUTHORS
VERSION:
	./version.sh
	echo "Configured with: $(CONFIG_FLAGS)" >> VERSION

CHANGELOG:
	./changelog.sh

AUTHORS:
	./authors.sh


# MINK convenience libraries
noinst_LTLIBRARIES = libasn1.la \
                     libgdtdef.la \
                     libdaemon.la \
                     libcfgparser.la \
                     libcfg.la \
                     libantlrutils.la \
                     libcli.la \
                     libgdtutils.la \
                     libstats.la \
                     libminkutils.la \
                     libminkplugin.la

if ENABLE_GRPC
noinst_LTLIBRARIES += libgdtgrpc.la
endif

lib_LTLIBRARIES = libgdt.la

pkglib_LTLIBRARIES = plgcfg.la

bin_PROGRAMS = routingd \
               configd \
               cli_service \
               gdttrapc

if ENABLE_GRPC
bin_PROGRAMS += grpcd
bin_PROGRAMS += grpcc
endif

if ENABLE_CODEGEN
bin_PROGRAMS += codegen
endif

if ENABLE_SYSAGENT
bin_PROGRAMS += sysagentd
endif

# code generator
if ENABLE_CODEGEN
codegen_SOURCES = src/codegen/codegen.cpp
codegen_CPPFLAGS = ${COMMON_INCLUDES} \
                   -Isrc/codegen
endif

# gdt grpc client
if ENABLE_GRPC
grpcc_SOURCES = src/gdt/gdt_grpc_client.cpp
grpcc_CPPFLAGS = ${COMMON_INCLUDES} \
                 -Isrc/proto \
                 ${GRPC_CFLAGS}
grpcc_LDADD = libgdtgrpc.la \
              ${PROTOBUF_LIBS} \
              ${GRPC_LIBS}
endif

# sysagentd
if ENABLE_SYSAGENT
sysagentd_SOURCES = src/services/sysagent/events.cpp \
                    src/services/sysagent/sysagent.cpp \
                    src/services/sysagent/sysagentd.cpp
sysagentd_CPPFLAGS = -I. ${COMMON_INCLUDES} \
                     ${GRPC_CFLAGS} \
                     -Isrc/proto \
                     -Isrc/services/sysagent
sysagentd_LDFLAGS = -export-dynamic
sysagentd_LDADD = libdaemon.la \
                  libcfg.la \
                  libminkutils.la \
                  libgdt.la \
                  libgdtutils.la \
                  libasn1.la \
                  libminkplugin.la \
                  ${NCURSES_LIBS} \
                  -ldl -lcap
endif     

# grpcd
if ENABLE_GRPC
grpcd_SOURCES = src/services/grpc/grpc.cpp \
                src/services/grpc/events.cpp \
                src/services/grpc/gdtgrpc.cpp \
                src/services/grpc/grpcd.cpp
grpcd_CPPFLAGS = ${COMMON_INCLUDES} \
                 -Isrc/proto \
                 -Isrc/services/grpc \
                 ${GRPC_CFLAGS}
grpcd_LDADD = libdaemon.la \
              libcfg.la \
              libminkutils.la \
              libgdt.la \
              libgdtutils.la \
              libasn1.la \
              libgdtgrpc.la \
              ${PROTOBUF_LIBS} \
              ${GRPC_LIBS} \
              ${NCURSES_LIBS} \
              -ldl -lcap
endif

# cli service
cli_service_SOURCES = src/services/cli/cli_service.cpp
cli_service_CPPFLAGS = ${COMMON_INCLUDES} \
                       $(ANTLR_FLAGS)
cli_service_LDFLAGS = -export-dynamic
cli_service_LDADD = libcli.la \
                    libminkutils.la \
                    libantlrutils.la \
                    libcfg.la \
                    libcfgparser.la \
                    ${NCURSES_LIBS} \
                    ${ANTLR_LDLIBS} \
                    -ldl

# gdt trapc client
gdttrapc_SOURCES = src/services/stats/gdttrapc.cpp
gdttrapc_CPPFLAGS = ${COMMON_INCLUDES}
gdttrapc_LDADD = libasn1.la \
                 libgdt.la \
                 libminkutils.la \
                 libcfg.la \
                 ${NCURSES_LIBS} \
                 -ldl 

# configd
configd_SOURCES = src/services/config/events.cpp \
                  src/services/config/configd.cpp
configd_CPPFLAGS = ${COMMON_INCLUDES} \
                   ${ANTLR_FLAGS} \
                   -Isrc/services/config
configd_LDADD = libasn1.la \
                libcfg.la \
                libdaemon.la \
                libgdt.la \
                libminkutils.la \
                libantlrutils.la \
                libcli.la \
                libcfgparser.la \
                ${NCURSES_LIBS} \
                ${ANTLR_LDLIBS} \
                -ldl -lcap


# routingd
routingd_SOURCES = src/services/routing/cfg_events.cpp \
                   src/services/routing/routing.cpp \
                   src/services/routing/routingd_events.cpp \
                   src/services/routing/routingd.cpp
routingd_CPPFLAGS = ${COMMON_INCLUDES} \
                    ${ANTLR_FLAGS} \
                    ${NCURSES_CFLAGS} \
                    -Isrc/services/routing
routingd_LDADD = libgdt.la \
                 libdaemon.la \
                 libstats.la \
                 libgdt.la \
                 libasn1.la \
                 libcfg.la \
                 libminkutils.la \
                 ${NCURSES_LIBS} \
                 -ldl -lcap
              
# mink plugin
libminkplugin_la_SOURCES = src/utils/mink_plugin.cpp
libminkplugin_la_CPPFLAGS = ${COMMON_INCLUDES}

if ENABLE_GRPC
# grpc
libgdtgrpc_la_SOURCES = src/proto/gdt.grpc.pb.cc \
                        src/proto/gdt.pb.cc
libgdtgrpc_la_CPPFLAGS = ${COMMON_INCLUDES} \
                         ${GRPC_CFLAGS}
endif

# utils
libminkutils_la_SOURCES = src/utils/mink_utils.cpp
libminkutils_la_CPPFLAGS = ${COMMON_INCLUDES}

# daemon
libdaemon_la_SOURCES = src/daemon/daemon.cpp
libdaemon_la_CPPFLAGS = $(COMMON_INCLUDES)

# asn1
libasn1_la_SOURCES = src/asn1/asn1.cpp
libasn1_la_CPPFLAGS = $(COMMON_INCLUDES)

# gdt def
libgdtdef_la_SOURCES = src/gdt/gdt_def.cpp
libgdtdef_la_CPPFLAGS = $(COMMON_INCLUDES)

# libcfg parser
libcfgparser_la_SOURCES = src/cfg/minkLexer.c \
                          src/cfg/minkParser.c
libcfgparser_la_CPPFLAGS = ${COMMON_INCLUDES} \
                           ${ANTLR_FLAGS}

# libcfg
libcfg_la_SOURCES = src/cfg/mink_config.cpp
libcfg_la_CPPFLAGS = ${COMMON_INCLUDES}

# libantlrutils
libantlrutils_la_SOURCES = src/cfg/antlr_utils.cpp
libantlrutils_la_CPPFLAGS = ${COMMON_INCLUDES} \
                            ${ANTLR_FLAGS}

# libcli
libcli_la_SOURCES = src/cli/cli.cpp
libcli_la_CPPFLAGS = ${COMMON_INCLUDES} \
                     ${ANTLR_FLAGS}

# gdt utils
libgdtutils_la_SOURCES = src/gdt/gdt_utils.cpp \
                         src/cfg/config_gdt.cpp
libgdtutils_la_CPPFLAGS = ${COMMON_INCLUDES}

# stats
libstats_la_SOURCES = src/stats/gdt_stats.cpp
libstats_la_CPPFLAGS = ${COMMON_INCLUDES}

# MINK libraries
libgdt_la_SOURCES = src/gdt/gdt.cpp \
                    src/gdt/gdt_reg_events.cpp \
                    src/net/sctp.cpp \
                    src/net/chunk.cpp
libgdt_la_CPPFLAGS = $(COMMON_INCLUDES)
libgdt_la_LIBADD = libgdtdef.la \
                   libgdtutils.la \
                   ${SCTP_LIBS}

# MINK configd plugin
plgcfg_la_SOURCES = src/cfg/plgcfg_events.cpp \
                    src/cfg/config_gdt.cpp \
                    src/cfg/plgcfg.cpp
plgcfg_la_CPPFLAGS = ${COMMON_INCLUDES} \
                     ${ANTLR_FLAGS}
plgcfg_la_LDFLAGS = -version-info 1:0:0 \
                    -shared \
                    -module

# /********************/
# /* Sysagent plugins */
# /********************/
if ENABLE_SYSAGENT
# sysagent system plugin
include src/services/sysagent/plugins/system/Makefile.am
# sysagent openwrt plugin
if ENABLE_OPENWRT
include src/services/sysagent/plugins/openwrt/Makefile.am
endif
endif
