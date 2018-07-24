#!/bin/bash

source cj_java_rest.sh;
source cj_java_setup.sh;

SYNC=$1;

cleanUp(){
   cleanConnection 127.0.2.1;
   cleanBindings 127.0.2.1;
   cleanConnection 127.0.2.2;
   cleanBindings 127.0.2.2;
   cleanConnection 127.0.2.3;
   cleanBindings 127.0.2.3;
   cleanConnection 127.0.2.4;
   cleanBindings 127.0.2.4;
   cleanConnection 127.0.2.5;
   cleanBindings 127.0.2.5;
};

bindingRemovalTest(){
	synchronize 60 $SYNC "Init";

	addBinding 40 "192.168.1.1/32" 127.0.2.1
	addBinding 42 "192.168.2.0/24" 127.0.2.1
	addBinding 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" 127.0.2.1
	addBinding 62 "aaaa:eeee:abcf:eeed:0:0:0:0/64" 127.0.2.1

	addBinding 41 "192.168.1.1/32" 127.0.2.5
	addBinding 43 "192.168.2.0/24" 127.0.2.5
	addBinding 61 "aaaa:eeee:abcf:eeee:0:0:0:0/128" 127.0.2.5
	addBinding 63 "aaaa:eeee:abcf:eeed:0:0:0:0/64" 127.0.2.5

	addConnection "127.0.2.2" 64999 "speaker" 4 "none" 127.0.2.1
	addConnection "127.0.2.1" 64999 "listener" 4 "none" 127.0.2.2
	addConnection "127.0.1.3" 64999 "speaker" 4 "none" 127.0.2.2
	addConnection "127.0.1.3" 64999 "listener" 4 "none" 127.0.2.4
	addConnection "127.0.1.3" 64999 "speaker" 4 "none" 127.0.2.5
   
	if waitUntil 10 containsConnection "127.0.2.1" "127.0.2.2" 64999 "on" ||
	waitUntil 10 containsConnection "127.0.2.2" "127.0.1.3" 64999 "on" ||
	waitUntil 10 containsConnection "127.0.2.4" "127.0.1.3" 64999 "on" ||
	waitUntil 10 containsConnection "127.0.2.5" "127.0.1.3" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	synchronize 60 $SYNC "Topology ready";		

	if waitUntil 10 containsBinding "127.0.2.4" 41 "192.168.1.1/32" ||
	waitUntil 10 containsBinding "127.0.2.4" 43 "192.168.2.0/24" ||
	waitUntil 10 containsBinding "127.0.2.4" 61 "aaaa:eeee:abcf:eeee:0:0:0:0/128" ||
	waitUntil 10 containsBinding "127.0.2.4" 63 "aaaa:eeee:abcf:eeed:0:0:0:0/64"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi
	
	deleteBinding 40 "192.168.1.1/32" 127.0.2.1
	deleteBinding 42 "192.168.2.0/24" 127.0.2.1
	deleteBinding 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" 127.0.2.1
	deleteBinding 62 "aaaa:eeee:abcf:eeed:0:0:0:0/64" 127.0.2.1
   
	deleteBinding 41 "192.168.1.1/32" 127.0.2.5
	deleteBinding 43 "192.168.2.0/24" 127.0.2.5
	deleteBinding 61 "aaaa:eeee:abcf:eeee:0:0:0:0/128" 127.0.2.5
	deleteBinding 63 "aaaa:eeee:abcf:eeed:0:0:0:0/64" 127.0.2.5
   
	if waitUntil 10 doesNotcontainsBinding "127.0.2.4" 40 "192.168.1.1/32" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.4" 42 "192.168.2.0/24" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.4" 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.4" 62 "aaaa:eeee:abcf:eeed:0:0:0:0/64" ||   
	waitUntil 10 doesNotcontainsBinding "127.0.2.4" 41 "192.168.1.1/32" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.4" 43 "192.168.2.0/24" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.4" 61 "aaaa:eeee:abcf:eeee:0:0:0:0/128" ||
	waitUntil 10 doesNotcontainsBinding "127.0.2.4" 63 "aaaa:eeee:abcf:eeed:0:0:0:0/64"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	synchronize 60 $SYNC "Binding removal 1";
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;   
};

bindingRemovalTest2(){
	synchronize 60 $SYNC "Init";		

	addConnection "127.0.1.2" 64999 "listener" 4 "none" 127.0.2.3
	addConnection "127.0.1.4" 64999 "speaker" 4 "none" 127.0.2.3
	addConnection "127.0.1.5" 64999 "listener" 4 "none" 127.0.2.3
   
	if waitUntil 10 containsConnection "127.0.2.3" "127.0.1.2" 64999 "on" ||
	waitUntil 10 containsConnection "127.0.2.3" "127.0.1.4" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	synchronize 60 $SYNC "Topology ready";
	synchronize 60 $SYNC "Binding removal 2";
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;   
};

echo -e "Verify that binding is withdrawn from the master database once all contributing bindings have been removed\n"

cleanUp;
./cj_topo_6 $SYNC 2> sxp6.log &
bindingRemovalTest;
bindingRemovalTest2;
synchronize 10 $SYNC "Clean Up";
