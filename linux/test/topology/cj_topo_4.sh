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
};

reexportTest(){
	synchronize 60 $SYNC "Init";		

	addConnection "127.0.1.1" 64999 "listener" 4 "none" 127.0.2.2
	addConnection "127.0.1.3" 64999 "speaker" 4 "none" 127.0.2.2
   
	if waitUntil 10 containsConnection "127.0.2.2" "127.0.1.1" 64999 "on" ||
	waitUntil 10 containsConnection "127.0.2.2" "127.0.1.3" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi
   
	synchronize 60 $SYNC "Export start";

	if waitUntil 10 containsBinding "127.0.2.2" 40 "192.168.1.1/32" ||
	waitUntil 10 containsBinding "127.0.2.2" 41 "192.168.2.0/24" ||
	waitUntil 10 containsBinding "127.0.2.2" 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" ||
	waitUntil 10 containsBinding "127.0.2.2" 61 "aaaa:eeee:abcf:eeed:0:0:0:0/64"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	synchronize 60 $SYNC "Reexport 1";		
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;
};

reexportTest2(){
	synchronize 60 $SYNC "Init";		

   	addBinding 40 "192.168.1.1/32" 127.0.2.1
	addBinding 41 "192.168.2.0/24" 127.0.2.1
	addBinding 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" 127.0.2.1
	addBinding 61 "aaaa:eeee:abcf:eeed:0:0:0:0/64" 127.0.2.1
   
  	addConnection "127.0.1.2" 64999 "speaker" 4 "none" 127.0.2.1
 	addConnection "127.0.1.2" 64999 "listener" 4 "none" 127.0.2.3
   
	if waitUntil 10 containsConnection "127.0.2.1" "127.0.1.2" 64999 "on" ||
	waitUntil 10 containsConnection "127.0.2.3" "127.0.1.2" 64999 "on"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	synchronize 60 $SYNC "Export start";

	if waitUntil 10 containsBinding "127.0.2.3" 40 "192.168.1.1/32" ||
	waitUntil 10 containsBinding "127.0.2.3" 41 "192.168.2.0/24" ||
	waitUntil 10 containsBinding "127.0.2.3" 60 "aaaa:eeee:abcf:eeee:0:0:0:0/128" ||
	waitUntil 10 containsBinding "127.0.2.3" 61 "aaaa:eeee:abcf:eeed:0:0:0:0/64"; then
		echo -e "$(tput setaf 1)\tTEST FAILURE$(tput sgr0)";
		cleanUp;
		return;
	fi

	synchronize 60 $SYNC "Reexport 2";		
	echo -e "$(tput setaf 2)\tTEST PASS$(tput sgr0)";
	cleanUp;	
};

echo -e "Verify that received bindings are re-exported to listener\n"

cleanUp;
./cj_topo_4 $SYNC 2> sxp4.log &
reexportTest;
reexportTest2;
synchronize 10 $SYNC "Clean Up";
