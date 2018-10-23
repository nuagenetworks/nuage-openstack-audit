#!/bin/bash

# Copyright 2018 NOKIA
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

if [[ $1 == 'nocolor' ]];then
    nocolor=1
fi


function red {
    if [[ $nocolor ]];then
        echo "$@"
    else
        echo -e -n "${RED}"; echo "$@"; echo -e -n "${NC}"
    fi
}


function green {
    if [[ $nocolor ]];then
        echo "$@"
    else
       echo -e -n "${GREEN}"; echo "$@"; echo -e -n "${NC}"
    fi
}


success=1
files_checked='.*\.\(py\|sh\|ini\|cfg\|txt\|rst\|yaml\)'


for dir in . `find . -mindepth 1 -maxdepth 1  -type d \
                     -not -path '*/\.*' -not -path './build' \
                     -not -path './*.egg-info' `; \
                     do

    depth=""

    if [ "$dir" == "." ]; then
        depth="-maxdepth 1"
    fi
    crlf=`find $dir $depth -regex $files_checked -exec file '{}' ';' \
          | grep -Hn CRLF`
    if [ "$crlf" ]; then
        red "CRLF(s) at"
        echo "$crlf"
        success=
    fi
    trailing_spaces=`find $dir $depth -regex $files_checked \
                     -exec egrep -l ' $' '{}' ';'`
    if [ "$trailing_spaces" ]; then
        red "Trailing space(s) at:"
        egrep -Hn ' $' $trailing_spaces
        success=
    fi
    tabs=`find $dir $depth -regex $files_checked \
          -exec grep -Hn $'\t' '{}' ';'`
    if [ "$tabs" ]; then
        red "Tab(s) at:"
        echo "$tabs"
        success=
    fi
    todos=`find $dir $depth -regex $files_checked \
           -exec grep -Hn TODO '{}' ';' | grep -v SKIP_TODO_CHECK`
    if [ "$todos" ]; then
        red "TODO(s) at"  # SKIP_TODO_CHECK
        echo "$todos"
        # NOT FATAL AT THIS STAGE  # success=
    fi

done


if [ "$success" ]; then
    echo
    green "  OK"

else
    red "Exiting with error(s)."
    exit 1

fi
