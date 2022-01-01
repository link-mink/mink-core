#!/bin/bash

PLG=$1

# update main makefile
sed -i "$(wc -l ../../Makefile.am|cut -d' ' -f1) i # sysagent $PLG plugin" ../../Makefile.am
sed -i "$(wc -l ../../Makefile.am|cut -d' ' -f1) i include src/services/sysagent/plugins/$PLG/Makefile.am" ../../Makefile.am

