#!/bin/bash

waitUntil(){
	#DELAY/FUNCT
	TIMES=$1;
	shift;
	for i in `seq 1 $TIMES`
	do
		if "$@"; then
			return 1;
		fi;
		sleep 1;
	done
	echo -e "$(tput setaf 1)FAILED$(tput sgr0)  $@"
	sleep 20;
    return 0;
};

GetNode(){
	echo "        <sxp-node>\n<enabled>true</enabled>\n<node-id>$1</node-id>\n<source-ip>$1</source-ip>\n<tcp-port>64999</tcp-port>\n<version>version4</version>\n<security>\n<password></password>\n</security>\n<mapping-expanded>0</mapping-expanded>\n<description>ODL SXP Controller</description>\n<master-database></master-database>\n<timers>\n<retry-open-time>5</retry-open-time>\n<hold-time-min-acceptable>120</hold-time-min-acceptable>\n<keep-alive-time>30</keep-alive-time>\n<hold-time>90</hold-time>\n<hold-time-min>90</hold-time-min>\n<hold-time-max>180</hold-time-max>\n</timers>\n</sxp-node>\n"
};

dec2ip () {
    local ip dec=$@
    for e in {3..0}
    do
        ((octet = dec / (256 ** e) ))
        ((dec -= octet * 256 ** e))
        ip+=$delim$octet
        delim=.
    done
    printf '%s\n' "$ip"
}

GenerateConfig(){
	for num in `seq 1 $1`
	do
		IP=$(dec2ip $(expr $num + 2130706944))
		DATA=$(GetNode $IP)
		sed -i "s|\(</sxp-controller>\)|${DATA//$'\n'/\n}\1|g" "/tmp/22-sxp-controller-one-node.xml"
	done
};

synchronize() {
	#RETRICOUNT/SYNC/MSG
	for i in `seq 1 $1`
	do
		sleep 1;
		if [ -f $2 ];then
			rm $2;
			echo -e "$(tput setaf 2)SUCCESS$(tput sgr0) $3"
			break;
		elif [ $i == $1 ];then
			echo -e "$(tput setaf 1)FAIL$(tput sgr0)    $3"
			exit 1;
      fi
	done
}

SetupController() {
	#NODECOUNT

	CONTROLLERMEM="2048m"
        ACTUALFEATURES="odl-sxp-controller"
	BRANCH="master"
	OLD_PWD=$PWD;

	NEXUSURL_PREFIX=${ODLNEXUSPROXY:-https://nexus.opendaylight.org}

	cp ./cj_karaf_config.xml /tmp/22-sxp-controller-one-node.xml

	cd /tmp
	# Obtain current pom.xml of integration/distribution, correct branch.
	rm pom.xml
	wget "http://git.opendaylight.org/gerrit/gitweb?p=integration/distribution.git;a=blob_plain;f=pom.xml;hb=refs/heads/$BRANCH" -O "pom.xml"
	# Extract the BUNDLEVERSION from the pom.xml
	BUNDLEVERSION=`xpath  -q -e '/project/version/text()' pom.xml`
	echo "Bundle version is ${BUNDLEVERSION}"
	# Acquire the timestamp information from maven-metadata.xml
	NEXUSPATH="${NEXUSURL_PREFIX}/content/repositories/opendaylight.snapshot/org/opendaylight/integration/distribution-karaf"
	rm maven-metadata.xml
	wget ${NEXUSPATH}/${BUNDLEVERSION}/maven-metadata.xml
	TIMESTAMP=`xpath -q -e "//snapshotVersion[extension='zip'][1]/value/text()" maven-metadata.xml`
	#TIMESTAMP=`xpath -q -e '/metadata/versioning/lastUpdated/text()' maven-metadata.xml`
	echo "Nexus timestamp is ${TIMESTAMP}"
	BUNDLEFOLDER="distribution-karaf-${BUNDLEVERSION}"
	BUNDLE="distribution-karaf-${TIMESTAMP}.zip"
	ACTUALBUNDLEURL="${NEXUSPATH}/${BUNDLEVERSION}/${BUNDLE}"

	echo "Distribution bundle URL is ${ACTUALBUNDLEURL}"
	echo "Distribution bundle is ${BUNDLE}"
	echo "Distribution bundle version is ${BUNDLEVERSION}"
	echo "Distribution folder is ${BUNDLEFOLDER}"
	echo "Nexus prefix is ${NEXUSURL_PREFIX}"

	#TEMP CLEARING
	test -f	/tmp/${BUNDLEFOLDER}/bin/stop && /tmp/${BUNDLEFOLDER}/bin/stop && echo "Karaf is shutting down Cool down for 30 seconds ..." && sleep 30;
	rm -r ${BUNDLEFOLDER}

	test -f /tmp/${BUNDLE} || wget  ${ACTUALBUNDLEURL}
	echo "Setup config"
	GenerateConfig $1
	mkdir -p /tmp/${BUNDLEFOLDER}/etc/opendaylight/karaf/

	mv /tmp/22-sxp-controller-one-node.xml /tmp/${BUNDLEFOLDER}/etc/opendaylight/karaf/
	echo "Extracting the new controller..."
	unzip -q ${BUNDLE}

	echo "Configuring the startup features..."
	FEATURESCONF=/tmp/${BUNDLEFOLDER}/etc/org.apache.karaf.features.cfg
	sed -ie "s/featuresBoot=.*/featuresBoot=config,standard,region,package,kar,ssh,management,${ACTUALFEATURES}/g" ${FEATURESCONF}
	sed -ie "s%mvn:org.opendaylight.integration/features-integration-index/${BUNDLEVERSION}/xml/features%mvn:org.opendaylight.integration/features-integration-index/${BUNDLEVERSION}/xml/features,mvn:org.opendaylight.integration/features-integration-test/${BUNDLEVERSION}/xml/features%g" ${FEATURESCONF}
	cat ${FEATURESCONF}

	echo "Configuring the log..."
	LOGCONF=/tmp/${BUNDLEFOLDER}/etc/org.ops4j.pax.logging.cfg
	sed -ie 's/log4j.appender.out.maxFileSize=1MB/log4j.appender.out.maxFileSize=20MB/g' ${LOGCONF}
	cat ${LOGCONF}

	echo "Configure max memory..."
	MEMCONF=/tmp/${BUNDLEFOLDER}/bin/setenv
	sed -ie 's/JAVA_MAX_MEM="2048m"/JAVA_MAX_MEM="${CONTROLLERMEM}"/g' ${MEMCONF}
	cat ${MEMCONF}


	/tmp/${BUNDLEFOLDER}/bin/start
	echo "Waiting for controller to come up..."
	COUNT="0"
	while true; do
	    RESP="$( curl --user admin:admin -sL -w "%{http_code} %{url_effective}\\n" http://localhost:8181/restconf/modules -o /dev/null )"
	    echo $RESP
	    if [[ $RESP == *"200"* ]]; then
		echo Controller is UP
		break
	    elif (( "$COUNT" > "600" )); then
		echo Timeout Controller DOWN
		echo "Dumping Karaf log..."
		cat /tmp/${BUNDLEFOLDER}/data/log/karaf.log
		echo false
		return;
	    else
		COUNT=$(expr $COUNT + 5);
		sleep 5
		echo waiting $COUNT secs...
	    fi
	done

	echo "Cool down for 30 seconds ..."
	sleep 30
	cd $OLD_PWD;
};
