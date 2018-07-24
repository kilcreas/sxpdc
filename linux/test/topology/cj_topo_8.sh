#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

SYNC=$1;

cleanUp(){
   cleanConnection 127.0.2.1;
   cleanBindings 127.0.2.1;
};

keepaliveTest(){
	synchronize 10 $SYNC "Init";

	addConnection "127.0.1.1" 64999 $1 4 "none" 127.0.2.1

    echo -e "Sleeping 90 seconds for hold time expiration."
    sleep 90;

	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.1" 64999 "on";then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0) - $1 is not in state on";
		cleanUp;
		return;
	fi;

    synchronize 10 $SYNC "KeepAlive $1";

    echo -e "Sleeping 90 seconds for hold time expiration disconnect."
    sleep 90;

    if waitUntil 30 containsConnection "127.0.2.1" "127.0.1.1" 64999 "$2";then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0) - $1 is not in state $2";
      exit 1
		cleanUp;
		return;
	fi;

	synchronize 10 $SYNC "DeleteHoldDown $1";
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;
};

echo -e "Verify that connection is keep-alive mechanism is working properly\n"

cleanUp;
./cj_topo_8 $SYNC 2> sxp8.log &
keepaliveTest "listener" "pending-on"
keepaliveTest "both" "pending-on"
synchronize 10 $SYNC "Clean Up";
