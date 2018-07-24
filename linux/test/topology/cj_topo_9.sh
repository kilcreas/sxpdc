#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

SYNC=$1;

cleanUp(){
   cleanConnection 127.0.2.1;
   cleanBindings 127.0.2.1;
};

connetivityMismatchTest(){
	synchronize 10 $SYNC "Init";		

	addConnection "127.0.1.1" 64999 $1 4 "none" 127.0.2.1
   	
	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.1" 64999 "off";then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi;
	synchronize 10 $SYNC "Connetivity missmatch";		
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;
};

echo -e "Verify that connection cannot be established if roles are incompatible\n"

cleanUp;
./cj_topo_9 $SYNC 2> sxp9.log &
connetivityMismatchTest "listener"
connetivityMismatchTest "speaker"
synchronize 10 $SYNC "Clean Up";
