#!/bin/bash
# mink
echo "Running autoreconf on mink..."
autoreconf --install --force -I m4 > /dev/null 2>&1 || { echo "mink autoreconf error!"; exit 1; }
# antlr3c
cd lib/libantlr3c-3.4/
echo "Running autoreconf on antlr3c..."
autoreconf --install --force > /dev/null 2>&1 || { echo "antlr3c autoreconf error!"; exit 1; }

