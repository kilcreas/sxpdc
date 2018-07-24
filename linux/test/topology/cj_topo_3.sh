#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

SYNC=$1;

cleanUp(){
    cleanConnection 127.0.2.1;
    cleanBindings 127.0.2.1;
};

listenerPart(){
	synchronize 10 $SYNC "Init";		

	addConnection "127.0.1.1" 64999 "listener" 4 "none" 127.0.2.1	
	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.1" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	if waitUntil 10 containsBinding "127.0.2.1" 40 "192.168.1.1/32" ||
	waitUntil 10 containsBinding "127.0.2.1" 41 "192.168.2.0/24" ||
	waitUntil 10 containsBinding "127.0.2.1" 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" ||
	waitUntil 10 containsBinding "127.0.2.1" 61 "aaaa:eeee:abcf:eeed:0:0:0:0/64"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi;
	synchronize 10 $SYNC "Listener";			
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;
};

speakerPart(){
	synchronize 10 $SYNC "Init";		
	
	addBinding 40 "192.168.1.1/32" 127.0.2.1
	addBinding 41 "192.168.2.0/24" 127.0.2.1
	addBinding 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" 127.0.2.1
	addBinding 61 "aaaa:eeee:abcf:eeed:0:0:0:0/64" 127.0.2.1
	addConnection "127.0.1.1" 64999 "speaker" 4 "none" 127.0.2.1		

	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.1" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi
	
	synchronize 10 $SYNC "Speaker";		
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;   	
};

bothPart(){
	synchronize 10 $SYNC "Init";		
	
	addBinding 42 "192.168.3.1/32" 127.0.2.1
	addBinding 43 "192.168.4.0/24" 127.0.2.1
	addBinding 62 "aaaa:eeee:abcf:cccc:0:0:0:0/128" 127.0.2.1
	addBinding 63 "aaaa:eeee:abcf:cccd:0:0:0:0/64" 127.0.2.1
	addConnection "127.0.1.1" 64999 "both" 4 "none" 127.0.2.1		

	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.1" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0) - connection failed";
		cleanUp;
		return;
	fi

	if waitUntil 30 containsBinding "127.0.2.1" 40 "192.168.1.1/32" ||
	waitUntil 30 containsBinding "127.0.2.1" 41 "192.168.2.0/24" ||
	waitUntil 30 containsBinding "127.0.2.1" 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" ||
	waitUntil 30 containsBinding "127.0.2.1" 61 "aaaa:eeee:abcf:eeed:0:0:0:0/64"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0) - binding not found";
		cleanUp;
		return;
	fi;
	synchronize 60 $SYNC "Both";		

	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;
};

echo -e "Verify that bindings are read from configuration and exported accordingly\n"

cleanUp;
./cj_topo_3 $SYNC 2> sxp3.log &
listenerPart;
speakerPart;
bothPart;
synchronize 10 $SYNC "Clean Up";		

