#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

SYNC=$1;

cleanUp(){
   cleanConnection 127.0.2.2;
   cleanBindings 127.0.2.2;
};

bindingsExpansionTest(){
	synchronize 60 $SYNC "Init";

	addConnection "127.0.1.1" 64999 "listener" 1 "none" 127.0.2.2
   	if waitUntil 10 containsConnection "127.0.2.2" "127.0.1.1" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	if waitUntil 10 containsBinding "127.0.2.2" 32 "192.168.1.1/32" ||
	waitUntil 10 containsBinding "127.0.2.2" 30 "192.168.1.2/32" ||
	waitUntil 10 containsBinding "127.0.2.2" 29 "192.168.1.3/32" ||
	waitUntil 10 containsBinding "127.0.2.2" 29 "192.168.1.4/32" ||
	waitUntil 10 containsBinding "127.0.2.2" 29 "192.168.1.5/32" ||
	waitUntil 10 containsBinding "127.0.2.2" 29 "192.168.1.6/32"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
   		cleanUp;
   		return;
	fi
	synchronize 60 $SYNC "Bindings removal";
   
	if waitUntil 10 doesNotcontainsBinding "127.0.2.2" 32 "192.168.1.1/32" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.2" 30 "192.168.1.2/32" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.2" 29 "192.168.1.3/32" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.2" 29 "192.168.1.4/32" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.2" 29 "192.168.1.5/32" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.2" 29 "192.168.1.6/32"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
      		cleanUp;
      		return;
	fi

	synchronize 60 $SYNC "Bindings expansion";   
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;   	
};


echo -e "Verify that bindings expansion works\n"

cleanUp;
./cj_topo_7 $SYNC 2> sxp7.log &
bindingsExpansionTest;
synchronize 10 $SYNC "Clean Up";

