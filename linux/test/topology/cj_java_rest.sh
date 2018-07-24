#!/bin/bash

cleanConnection(){
	#NODEID
	CONNECTIONS=$(getConnections $1);
	COUNT=0;
	CONNECTION=$(echo $CONNECTIONS | jq ".output.connections.connection[$COUNT]")
	while [ ! "$CONNECTION" == "null" ]
	do
		IP=$(echo $CONNECTIONS | jq ".output.connections.connection[$COUNT][\"peer-address\"]");
		IP=${IP#\"*};	IP=${IP%*\"};
		PORT=$(echo $CONNECTIONS | jq ".output.connections.connection[$COUNT][\"tcp-port\"]");
		PORT=${PORT#\"*};	PORT=${PORT%*\"};
		deleteConnection 	$IP $PORT $1;
		COUNT=$(expr $COUNT + 1);
		CONNECTION=$(echo $CONNECTIONS | jq ".output.connections.connection[$COUNT]")
	done
};

cleanBindings(){
	#NODEID
	DATA=$(getMasterDatabase $1 "local");
	COUNT_S=0;
	SOURCE=$(echo $DATA | jq ".[\"output\"].binding[${COUNT_S}]")
	while [ ! "$SOURCE" == "null" ]
	do
		COUNT_P=0;
		PREFIX=$(echo $SOURCE | jq ".[\"ip-prefix\"][${COUNT_P}]")
		PREFIX=${PREFIX%*\"*};		PREFIX=${PREFIX#*\"*}
		SGT=$(echo $SOURCE | jq ".[\"sgt\"]")
		while [ ! "$PREFIX" == "null" ]
		do
			deleteBinding  $SGT $PREFIX $1;
			COUNT_P=$(expr $COUNT_P + 1);
			PREFIX=$(echo $SOURCE | jq ".[\"ip-prefix\"][${COUNT_P}]")
		done
		COUNT_S=$(expr $COUNT_S + 1);
		SOURCE=$(echo $DATA | jq ".[\"output\"].binding[${COUNT_S}]")
	done
};

addConnection(){
	#IP/PORT/MODE/VERSION/PASSWORD/NODEID
	PASSWORD=$5
	if [ "$5" == "none" ]; then
		PASSWORD=""
	fi

	RESP=`curl --fail -u admin:admin -H "Content-Type:text/xml" -X POST -d "<input>
	   <requested-node xmlns=\"urn:opendaylight:sxp:controller\">$6</requested-node>
	   <connections xmlns=\"urn:opendaylight:sxp:controller\">
	      <connection>
		 <peer-address>$1</peer-address>
		 <tcp-port>$2</tcp-port>
		 <password>$PASSWORD</password>
		 <mode>$3</mode>
		 <version>version$4</version>
		 <description>Connection to ISR-G2</description>
		 <connection-timers>
			<hold-time-min-acceptable>45</hold-time-min-acceptable>
		        <keep-alive-time>30</keep-alive-time>
			<reconciliation-time>120</reconciliation-time>
		 </connection-timers>
	      </connection>
	   </connections>
	</input>" http://localhost:8181/restconf/operations/sxp-controller:add-connection -s`;
	if [ ! 0 -eq $? ]; then
		echo -e "$(tput setaf 1)\tFAIL AddConnection request$(tput sgr0)";
		exit 1;
	fi;
};

deleteConnection(){
	#IP/PORT/NODEID
	RESP=`curl --fail -u admin:admin -H "Content-Type:text/xml" -X POST -d "<input>
	   <requested-node xmlns=\"urn:opendaylight:sxp:controller\">$3</requested-node>
	   <peer-address xmlns=\"urn:opendaylight:sxp:controller\">$1</peer-address>
	   <tcp-port xmlns=\"urn:opendaylight:sxp:controller\">$2</tcp-port>
	</input>" http://localhost:8181/restconf/operations/sxp-controller:delete-connection -s`;
	if [ ! 0 -eq $? ]; then
		echo -e "$(tput setaf 1)\tFAIL DeleteConnection request$(tput sgr0)";
		exit 1;
	fi;
};

getConnections(){
	#NODEID
	RESP=`curl --fail -u admin:admin -H "Content-Type:text/xml" -X POST -d "<input>
	   <requested-node xmlns=\"urn:opendaylight:sxp:controller\">$1</requested-node>
	</input>" http://localhost:8181/restconf/operations/sxp-controller:get-connections -s`;
	if [ ! 0 -eq $? ]; then
		echo -e "$(tput setaf 1)\tFAIL GetConnections request$(tput sgr0)";
		exit 1;
	fi;
	echo $RESP;
};

addBinding(){
	#SGT/PREFIX/NODEID
	RESP=`curl --fail -u admin:admin -H "Content-Type:text/xml" -X POST -d "<input>
	  <requested-node xmlns=\"urn:opendaylight:sxp:controller\">$3</requested-node>
	  <sgt xmlns=\"urn:opendaylight:sxp:controller\">$1</sgt>
	  <ip-prefix xmlns=\"urn:opendaylight:sxp:controller\">$2</ip-prefix>
	</input>" http://localhost:8181/restconf/operations/sxp-controller:add-entry -s`;
	if [ ! 0 -eq $? ]; then
		echo -e "$(tput setaf 1)\tFAIL AddBinding request$(tput sgr0)";
		exit 1;
	fi;
};

deleteBinding(){
	#SGT/PREFIX/NODEID
	RESP=`curl --fail -u admin:admin -H "Content-Type:text/xml" -X POST -d "<input>
	  <requested-node xmlns=\"urn:opendaylight:sxp:controller\">$3</requested-node>
	  <sgt xmlns=\"urn:opendaylight:sxp:controller\">$1</sgt>
	  <ip-prefix xmlns=\"urn:opendaylight:sxp:controller\">$2</ip-prefix>
	</input>" http://localhost:8181/restconf/operations/sxp-controller:delete-entry -s`;
	if [ ! 0 -eq $? ]; then
		echo -e "$(tput setaf 1)\tFAIL DeleteBinding request $1 $2 $3 $(tput sgr0)";
		exit 1;
	fi;
};

getMasterDatabase(){
	#NODEID
	RESP=`curl --fail -u admin:admin -H "Content-Type:text/xml" -X POST -d "<input>
	   <requested-node xmlns=\"urn:opendaylight:sxp:controller\">$1</requested-node>
  	   <bindings-range xmlns=\"urn:opendaylight:sxp:controller\">${2:-all}</bindings-range>
	</input>" http://localhost:8181/restconf/operations/sxp-controller:get-node-bindings -s`;
	if [ ! 0 -eq $? ]; then
		echo -e "$(tput setaf 1)\tFAIL GetBindings request$(tput sgr0)";
		exit 1;
	fi;
	echo $RESP;
};

containsConnection(){
	#NODEID/IP/PORT/STATE
	DATA=$(getConnections $1);
	COUNT=0;
	CONNECTION=$(echo $DATA | jq ".output.connections.connection[$COUNT]")
	while [ ! "$CONNECTION" == "null" ]
	do
		if [ $(echo $DATA | jq ".output.connections.connection[$COUNT][\"peer-address\"]") == "\"$2\"" ]; then
			if [ $(echo $DATA | jq ".output.connections.connection[$COUNT][\"tcp-port\"]") == "$3" ]; then
				if [ $(echo $DATA | jq ".output.connections.connection[$COUNT].state") == "\"$4\"" ]; then
					return 0;
				fi
			fi
		fi
		COUNT=$(expr $COUNT + 1);
		CONNECTION=$(echo $DATA | jq ".output.connections.connection[$COUNT]")
	done
	return 1;
};

doesNotcontainsBinding(){
	#NODEID/SGT/PREFIX
	containsBinding	$1 $2 $3;
	return $(($? -1));
};

containsBinding(){
	#NODEID/SGT/PREFIX
	DATA=$(getMasterDatabase $1);
	COUNT_S=0;
	SOURCE=$(echo $DATA | jq ".[\"output\"].binding[${COUNT_S}]")
	while [ ! "$SOURCE" == "null" ]
	do
		COUNT_P=0;
		PREFIX=$(echo $SOURCE | jq ".[\"ip-prefix\"][${COUNT_P}]")
		SGT=$(echo $SOURCE | jq ".[\"sgt\"]")
		if [ "$2" == $SGT ]; then
			while [ ! "$PREFIX" == "null" ]
			do
				if [ "\"$3\"" == $PREFIX ];then
					return 0;
				fi;
				COUNT_P=$(expr $COUNT_P + 1);
				PREFIX=$(echo $SOURCE | jq ".[\"ip-prefix\"][${COUNT_P}]")
			done
		fi
		COUNT_S=$(expr $COUNT_S + 1);
		SOURCE=$(echo $DATA | jq ".[\"output\"].binding[${COUNT_S}]")
	done
	return 1;
};
