#!/bin/sh
#
# Tool to add ssl certificate to a java truststore
#
# This tool takes the commands:
# add-java-certificate --alias=ALIAS --certificate=/path/to/certificate
# add-java-certificate --host=my.example.com

COMMAND=""
HOST=""
CERTIFICATE=""
CA_CERT=""
ALIAS=""

while [ $# -gt 0 ]; do
	case $1 in
		add-java-certificate)
			COMMAND=$1
			;;
		--host=*)
			HOST=${1#*=}
			;;
		--certificate=*)
			CERTIFICATE=${1#*=}
			;;
		--authority)
			CA_CERT="-trustcacerts"
			;;
		--alias=*)
			ALIAS=${1#*=}
			;;
		*)
			echo "Unknown option $1" 1>&2
			exit 2
			;;
	esac
	shift
done

if [ -z $COMMAND ]; then
	exit 2
fi

JENKINS_HOME=${HOME}
JENKINS_CONF=${JENKINS_HOME}/org.jenkins-ci.slave.jnlp.conf
JENKINS_WRKSPC=${JENKINS_HOME}/org.jenkins-ci.slave.jnlp
if [ -f ${JENKINS_CONF} ]; then
	. ${JENKINS_CONF}
else
	exit 3
fi

if [ -z "${JAVA_TRUSTSTORE_PASS}" ]; then
	echo "No Java truststore password in slave config, exiting"
	exit 4
fi

case ${COMMAND} in
	add-java-certificate)
		if [ "${HOST}" ]; then
			MASTER_HOST=`echo $HOST | cut -d':' -f2 | cut -d'/' -f3`
			MASTER_HTTP_PORT=443
			[ ! -z $HTTP_PORT ] && MASTER_HTTP_PORT=":${HTTP_PORT}"
			CERTIFICATE="${JENKINS_WRKSPC}/${MASTER_NAME}.cer"
			ALIAS="${MASTER_HOST}"
			openssl s_client -connect ${MASTER_HOST}${MASTER_HTTP_PORT} < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ${CERTIFICATE}
		fi
		if [ ! -z "${ALIAS}" ] && [ -f "${CERTIFICATE}" ]; then
			keytool -import -noprompt ${CA_CERT} -alias ${ALIAS} -file ${CERTIFICATE} -keystore ${JENKINS_WRKSPC}/.keystore -storepass ${JAVA_TRUSTSTORE_PASS}
			keytool -list -v -keystore ${JENKINS_WRKSPC}/.keystore -storepass ${JAVA_TRUSTSTORE_PASS}
		fi
		;;
esac
