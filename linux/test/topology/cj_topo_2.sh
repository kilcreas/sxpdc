#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

SYNC=$1;

cleanUp(){
    cleanConnection 127.0.2.1;
};

reconnectTest(){
	synchronize 10 $SYNC "Init";		

	addConnection "127.0.1.1" 64999 $1 4 "none" 127.0.2.1;
	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.1" 64999 "on";then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi;

	synchronize 10 $SYNC "Connected $1";

	if waitUntil 250 containsConnection "127.0.2.1" "127.0.1.1" 64999 "off";then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi;

	synchronize 10 $SYNC  "Disconnected $1";		

	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.1" 64999 "on";then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi;
	
	synchronize 10 $SYNC "Reconnected $1";		
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;
};

echo -e "Verify that SXPD reconnects to and accept connections from configured peers when error occurs\n"

cleanUp;
./cj_topo_2 $SYNC 2> sxp2.log &
reconnectTest "listener"
reconnectTest "speaker"
reconnectTest "both"
synchronize 10 $SYNC "Clean Up";
