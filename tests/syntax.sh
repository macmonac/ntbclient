#!/bin/bash

MY_PATH="`pwd`/`dirname \"$0\"`/../src/"
flake8 --ignore=E501 "${MY_PATH}"*.py
