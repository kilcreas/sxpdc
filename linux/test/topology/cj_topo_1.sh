#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

SYNC=$1;

cleanUp(){
   cleanConnection 127.0.2.1;
};

connetivityTest(){
	synchronize 10 $SYNC "Init";

	addConnection "127.0.1.1" 64999 $1 4 "password" 127.0.2.1
	if waitUntil 20 containsConnection "127.0.2.1" "127.0.1.1" 64999 "on";then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi;
	synchronize 10 $SYNC "$1";
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;
};

echo -e "Verify that SXPD connects to and accept connections from configured peers with or without TCPMD5\n"

cleanUp;
./cj_topo_1 $SYNC 2> sxp1.log &
connetivityTest "speaker"
connetivityTest "listener"
connetivityTest "both"
synchronize 10 $SYNC "Clean Up";
