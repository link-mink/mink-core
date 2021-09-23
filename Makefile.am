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

lib_LTLIBRARIES = libgdt.la

pkglib_LTLIBRARIES = plgcfg.la

bin_PROGRAMS = routingd \
               configd \
               cli_service \
               gdttrapc

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
                   -lsctp

# MINK configd plugin
plgcfg_la_SOURCES = src/cfg/plgcfg_events.cpp \
                    src/cfg/config_gdt.cpp \
                    src/cfg/plgcfg.cpp
plgcfg_la_CPPFLAGS = ${COMMON_INCLUDES} \
                     ${ANTLR_FLAGS}
plgcfg_la_LDFLAGS = -version-info 1:0:0 \
                    -shared \
                    -module

