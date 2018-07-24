#!/bin/sh

default_path="/tmp/sxpd.pid"

if [ "$1" == "" ]
then
    while true
    do
        read -p "No parameter specified, use default pid file location ${default_path}?" yn
        case $yn in
            [Yy]* ) path="${default_path}"; break;;
            [Nn]* ) echo "Exit - no path specified"; exit;;
            * ) echo "Please answer yes or no,";;
        esac
    done
else
    path="$1"
fi

if test -e ${path}
then
    pid=`cat ${path}`
    if ps -p ${pid}
    then
        kill -HUP ${pid}
        echo "Success: sent configuration reload trigger to process ${pid}"
    else
        echo "Error: stale pid ${pid} detected, no such process"
    fi
else
    echo "Error: file ${path} does not exist"
fi

