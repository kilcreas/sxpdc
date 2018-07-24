#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

function kill_all_c_childs() {

   echo -e "Killing remaining processes";
   TIMEOUT=6
	for i in `seq 1 $TIMEOUT`
	do
      PIDS=$(pidof cj_topo*);
      if [ "$PIDS" == "" ]; then
         echo -e "Killing remaining processes done";
         break;
      elif [ $i == $TIMEOUT ];then
         echo "Killing remaining processes timeout";
         exit 1;
      else
         echo -e "Killing remaining processes in progress...$PIDS";
         kill -9 $PIDS;
      fi
      sleep 1;
   done
}

function ctrl_c() {
   echo -e "CTRL+C hit..."

   kill_all_c_childs;

   exit 1;
}

trap ctrl_c SIGINT
SYNC="$(mktemp -d)"/lock;
echo "Setting up controller ..."
SetupController 5;

for test in ./cj_topo_8*.sh
do
	NUMBER=${test%*.*}
	echo -e "--------TEST ${NUMBER#*_*_*}--------"
	$test $SYNC
	sleep 2;
    kill_all_c_childs;
done
