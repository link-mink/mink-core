#!/bin/bash
git log  --decorate --tags --no-walk > CHANGELOG 2>&1 || { echo "MINK git repository not found!" > CHANGELOG; }
