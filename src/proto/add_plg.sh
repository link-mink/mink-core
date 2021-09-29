#!/bin/bash

PLG=$1

# update main makefile
echo "# sysagent $PLG plugin" >> ../../Makefile.am
echo "include src/services/sysagent/plugins/$PLG/Makefile.am" >> ../../Makefile.am

