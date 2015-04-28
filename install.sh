#!/bin/sh
#
# Install and configure the Jenkins JNLP Slave
#
# See https://github.com/antonyx/jenkins-slave-jnlp for usage

set -u

SERVICE_USER=${SERVICE_USER:-"jenkins"}
SERVICE_GROUP=${SERVICE_GROUP:-"${SERVICE_USER}"}
SERVICE_HOME=${SERVICE_HOME:-"/var/lib/${SERVICE_USER}"}
SERVICE_CONF=""   # set in create_user function
SERVICE_WRKSPC="" # set in create_user function
MASTER_NAME=""    # set default to jenkins later
MASTER_USER=""    # set default to `whoami` later
MASTER=""
MASTER_HTTP_PORT=""
SLAVE_NODE=""
SLAVE_TOKEN=${SLAVE_TOKEN:-""}
OSX_KEYCHAIN="login.keychain"
OSX_KEYCHAIN_PASS=${OSX_KEYCHAIN_PASS:-""}
KEYSTORE_PASS=""
JAVA_ARGS=${JAVA_ARGS:-""}
INSTALL_TMP=`mktemp -d -q -t org.jenkins-ci.slave.jnlp.XXXXXX`
DOWNLOADS_PATH=https://raw.github.com/antonyx/jenkins-slave-jnlp/master
SUDO_CMD="sudo"
G_CONFIRM=${CONFIRM:-""}
OS="`uname -s`"

create_user() {
	if [ ! -d "${SERVICE_HOME}" ]; then
		USER_SHELL="/bin/sh"
		if [ "${OS}" = "FreeBSD" ]; then
			pw groupshow ${SERVICE_GROUP} > /dev/null
			if [ ${?} -ne 0 ]; then
				pw groupadd ${SERVICE_GROUP}
			fi
			${SUDO_CMD} pw user add -n ${SERVICE_USER} -g ${SERVICE_GROUP} -d ${SERVICE_HOME} -m -w no -s ${USER_SHELL} -c 'Jenkins Node Service'
		else
			if [ "${OS}" = "SunOS" ]; then
				USER_SHELL="/usr/sbin/sh"
			fi
			${SUDO_CMD} groupadd ${SERVICE_GROUP}
			${SUDO_CMD} useradd -g ${SERVICE_GROUP} -d ${SERVICE_HOME} -m -s ${USER_SHELL} -c 'Jenkins Node Service' ${SERVICE_USER}
			${SUDO_CMD} passwd -l ${SERVICE_USER}
		fi
	fi
	SERVICE_CONF=${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.conf
	SERVICE_WRKSPC=${SERVICE_HOME}/org.jenkins-ci.slave.jnlp
}

create_user_osx() {
	# see if user exists
	if dscl /Local/Default list /Users | grep -q ${SERVICE_USER} ; then
		echo "Using pre-existing service account ${SERVICE_USER}"
		SERVICE_HOME=$( dscl /Local/Default read /Users/${SERVICE_USER} NFSHomeDirectory | awk '{ print $2 }' )
		SERVICE_GROUP=$( dscl /Local/Default search /Groups gid $( dscl /Local/Default read /Users/${SERVICE_USER} PrimaryGroupID | awk '{ print $2 }' ) | head -n1 | awk '{ print $1 }' )
	else
		echo "Creating service account ${SERVICE_USER}..."
		if dscl /Local/Default list /Groups | grep -q ${SERVICE_GROUP} ; then
			NEXT_GID=$( dscl /Local/Default list /Groups gid | grep ${SERVICE_GROUP} | awk '{ print $2 }' )
		else
			# create jenkins group
			NEXT_GID=$((`dscl /Local/Default list /Groups gid | awk '{ print $2 }' | sort -n | grep -v ^[5-9] | tail -n1` + 1))
			${SUDO_CMD} dscl /Local/Default create /Groups/${SERVICE_GROUP}
			${SUDO_CMD} dscl /Local/Default create /Groups/${SERVICE_GROUP} PrimaryGroupID $NEXT_GID
			${SUDO_CMD} dscl /Local/Default create /Groups/${SERVICE_GROUP} Password \*
			${SUDO_CMD} dscl /Local/Default create /Groups/${SERVICE_GROUP} RealName 'Jenkins Node Service'
		fi
		# create jenkins user
		NEXT_UID=$((`dscl /Local/Default list /Users uid | awk '{ print $2 }' | sort -n | grep -v ^[5-9] | tail -n1` + 1))
		${SUDO_CMD} dscl /Local/Default create /Users/${SERVICE_USER}
		${SUDO_CMD} dscl /Local/Default create /Users/${SERVICE_USER} UniqueID $NEXT_UID
		${SUDO_CMD} dscl /Local/Default create /Users/${SERVICE_USER} PrimaryGroupID $NEXT_GID
		${SUDO_CMD} dscl /Local/Default create /Users/${SERVICE_USER} UserShell /bin/bash
		${SUDO_CMD} dscl /Local/Default create /Users/${SERVICE_USER} NFSHomeDirectory ${SERVICE_HOME}
		${SUDO_CMD} dscl /Local/Default create /Users/${SERVICE_USER} Password \*
		${SUDO_CMD} dscl /Local/Default create /Users/${SERVICE_USER} RealName 'Jenkins Node Service'
		${SUDO_CMD} dseditgroup -o edit -a ${SERVICE_USER} -t user ${SERVICE_USER}
	fi
	SERVICE_CONF=${SERVICE_HOME}/Library/Preferences/org.jenkins-ci.slave.jnlp.conf
	SERVICE_WRKSPC=${SERVICE_HOME}/Library/Developer/org.jenkins-ci.slave.jnlp
}

install_files() {
	# create the jenkins home dir
	if [ ! -d ${SERVICE_WRKSPC} ]; then
		${SUDO_CMD} mkdir -p ${SERVICE_WRKSPC}
	fi

	SEC_HELPER="security.sh"
	if [ "${OS}" = "Darwin" ]; then
		SEC_HELPER="security-osx.sh"
		JNLP_HELPER="org.jenkins-ci.slave.jnlp.plist"
		JNLP_HELPER_DEST="/Library/LaunchAgents/org.jenkins-ci.slave.jnlp.plist"
		INSTALL_OPTS="-o root -g wheel -m 644 ${SERVICE_WRKSPC}/${JNLP_HELPER} ${JNLP_HELPER_DEST}"
	elif [ "${OS}" = "SunOS" ]; then
		JNLP_HELPER="jenkins-slave.xml"
		JNLP_HELPER_DEST="/var/svc/manifest/application/jenkins-slave.xml"
		INSTALL_OPTS="-u root -g ${SERVICE_GROUP} -m 644 -c /var/svc/manifest/application ${SERVICE_WRKSPC}/${JNLP_HELPER}"
	elif [ "${OS}" = "FreeBSD" ]; then
		JNLP_HELPER="jenkins-slave.rc.d.sh"
		JNLP_HELPER_DEST="/etc/rc.d/jenkins_slave"
		INSTALL_OPTS="-o root -g ${SERVICE_GROUP} -m 744 ${SERVICE_WRKSPC}/${JNLP_HELPER} ${JNLP_HELPER_DEST}"
	elif [ "${OS}" = "Linux" ]; then
		if [ -d "/lib/systemd/system" ]; then
			JNLP_HELPER="jenkins-slave.service"
			JNLP_HELPER_DEST="/lib/systemd/system/jenkins-slave.service"
		else
			JNLP_HELPER="jenkins-slave.init.d.sh"
			JNLP_HELPER_DEST="/etc/init.d/jenkins-slave"
		fi
		INSTALL_OPTS="-o root -g root -m 644 ${SERVICE_WRKSPC}/${JNLP_HELPER} ${JNLP_HELPER_DEST}"
	fi

	# download the jenkins JNLP security helper script
	${SUDO_CMD} curl --silent -L --url ${DOWNLOADS_PATH}/${SEC_HELPER} -o ${SERVICE_WRKSPC}/security.sh
	${SUDO_CMD} chmod 755 ${SERVICE_WRKSPC}/security.sh

	# download the correct jnlp daemon helper
	${SUDO_CMD} curl --silent -L --url ${DOWNLOADS_PATH}/${JNLP_HELPER} -o ${SERVICE_WRKSPC}/${JNLP_HELPER}
	if [ "${OS}" = "SunOS" ]; then
		${SUDO_CMD} sed "s#\${JENKINS_HOME}#${SERVICE_HOME}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER} > /tmp/jnlp.tmp
		${SUDO_CMD} mv /tmp/jnlp.tmp ${SERVICE_WRKSPC}/${JNLP_HELPER}
		${SUDO_CMD} sed "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER} > /tmp/jnlp.tmp
		${SUDO_CMD} mv /tmp/jnlp.tmp ${SERVICE_WRKSPC}/${JNLP_HELPER}
	elif [ "${OS}" = "Linux" ]; then
		${SUDO_CMD} sed -i "s#\${JENKINS_HOME}#${SERVICE_WRKSPC}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
		${SUDO_CMD} sed -i "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
	else
		${SUDO_CMD} sed -i '' "s#\${JENKINS_HOME}#${SERVICE_WRKSPC}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
		${SUDO_CMD} sed -i '' "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
	fi
	${SUDO_CMD} rm -f ${JNLP_HELPER_DEST}
	${SUDO_CMD} install ${INSTALL_OPTS}

	if [ "${OS}" = "SunOS" ]; then
		svccfg import ${JNLP_HELPER_DEST}
		svcadm restart svc:/system/manifest-import
	elif [ "${OS}" = "FreeBSD" ]; then
		grep -q '^jenkins_slave_enable' /etc/rc.conf
		if [ ${?} -ne 0 ]; then
			echo "jenkins_slave_enable=\"YES\"" >> /etc/rc.conf
		fi
	fi

	# download the jenkins JNLP slave script
	${SUDO_CMD} curl --silent -L --url ${DOWNLOADS_PATH}/slave.jnlp.sh -o ${SERVICE_WRKSPC}/slave.jnlp.sh
	${SUDO_CMD} chmod 755 ${SERVICE_WRKSPC}/slave.jnlp.sh

	# jenkins should own jenkin's home directory and all its contents
	${SUDO_CMD} chown -R ${SERVICE_USER}:${SERVICE_GROUP} ${SERVICE_HOME}
	# create a logging space
	if [ ! -d /var/log/${SERVICE_USER} ]; then
		${SUDO_CMD} mkdir /var/log/${SERVICE_USER}
		${SUDO_CMD} chown ${SERVICE_USER}:${SERVICE_GROUP} /var/log/${SERVICE_USER}
	fi
}

process_conf() {
	if [ -f ${SERVICE_CONF} ]; then
		${SUDO_CMD} chmod 666 ${SERVICE_CONF}
		. ${SERVICE_CONF}
		${SUDO_CMD} chmod 400 ${SERVICE_CONF}
		SLAVE_NODE="${SLAVE_NODE:-$JENKINS_SLAVE}"
		MASTER=${MASTER:-$JENKINS_MASTER}
		MASTER_HTTP_PORT=${HTTP_PORT}
		MASTER_USER=${MASTER_USER:-$JENKINS_USER}
	fi
	if [ "${OS}" = "Darwin" ] && [ -f ${SERVICE_HOME}/Library/.keychain_pass ]; then
		${SUDO_CMD} chmod 666 ${SERVICE_HOME}/Library/.keychain_pass
		. ${SERVICE_HOME}/Library/.keychain_pass
		${SUDO_CMD} chmod 400 ${SERVICE_HOME}/Library/.keychain_pass
	fi
}

process_args() {
	while [ $# -gt 0 ]; do
		case $1 in
			--node=*) SLAVE_NODE="${1#*=}"     ;;
			--token=*) SLAVE_TOKEN="${1#*=}"   ;;
			--user=*) MASTER_USER=${1#*=}      ;;
			--master=*) MASTER=${1#*=}         ;;
			--java-args=*) JAVA_ARGS="${1#*=}" ;;
			--confirm) G_CONFIRM="yes"         ;;
		esac
		shift
	done
}

configure_daemon() {
	if [ -z $MASTER ]; then
		MASTER=${MASTER:-"http://jenkins"}
		echo
		read -p "URL for Jenkins master [$MASTER]: " RESPONSE
		MASTER=${RESPONSE:-$MASTER}
	fi
	while ! curl -L --url ${MASTER}/jnlpJars/slave.jar --insecure --location --silent --fail --output ${INSTALL_TMP}/slave.jar ; do
		echo "Unable to connect to Jenkins at ${MASTER}"
		read -p "URL for Jenkins master: " MASTER
	done
	MASTER_NAME=`echo $MASTER | cut -d':' -f2 | cut -d'.' -f1 | cut -d'/' -f3`
	PROTOCOL=`echo $MASTER | cut -d':' -f1`
	MASTER_HTTP_PORT=`echo $MASTER | cut -d':' -f3`
	if [ "$PROTOCOL" = "$MASTER" ] ; then
		PROTOCOL="http"
		MASTER_HTTP_PORT=`echo $MASTER | cut -d':' -f2`
		[ -z $MASTER_HTTP_PORT ] || MASTER="${PROTOCOL}://`echo $MASTER | cut -d':' -f2`"
	else
		[ -z $MASTER_HTTP_PORT ] || MASTER="${PROTOCOL}:`echo $MASTER | cut -d':' -f2`"
	fi
	[ -z $MASTER_HTTP_PORT ] && MASTER_HTTP_PORT="443"
	[ ! -z $MASTER_HTTP_PORT ] && MASTER_HTTP_PORT=":${MASTER_HTTP_PORT}"
	if [ -z "$SLAVE_NODE" ]; then
		SLAVE_NODE=${SLAVE_NODE:-`hostname -s | tr '[:upper:]' '[:lower:]'`}
		echo
		read -p "Name of this slave on ${MASTER_NAME} [$SLAVE_NODE]: " RESPONSE
		SLAVE_NODE="${RESPONSE:-$SLAVE_NODE}"
	fi
	if [ -z $MASTER_USER ]; then
		[ "${SERVICE_USER}" != "jenkins" ] && MASTER_USER=${SERVICE_USER} || MASTER_USER=`whoami`
		echo
		read -p "Account that ${SLAVE_NODE} connects to ${MASTER_NAME} as [${MASTER_USER}]: " RESPONSE
		MASTER_USER=${RESPONSE:-$MASTER_USER}
	fi
	echo
	if [ -z "${SLAVE_TOKEN}" ]; then
		echo "${MASTER_USER}'s API token is required to authenticate a JNLP slave."
		echo "The API token is listed at ${MASTER}${MASTER_HTTP_PORT}/user/${MASTER_USER}/configure"
		read -p "API token for ${MASTER_USER}: " SLAVE_TOKEN
	else
		echo "Trying ${MASTER_USER}'s API token ${SLAVE_TOKEN}"
	fi
	while ! curl -L --url ${MASTER}${MASTER_HTTP_PORT}/user/${MASTER_USER} --user ${MASTER_USER}:${SLAVE_TOKEN} --insecure --silent --head --fail --output /dev/null ; do
		echo "Unable to authenticate ${MASTER_USER} with this token"
		read -p "API token for ${MASTER_USER}: " SLAVE_TOKEN
	done

	if [ "${OS}" = "Darwin" ]; then
		tr="`which tr`"
		if [ -d "/usr/local/Cellar/coreutils" ]; then
			tr_tmp=`find /usr/local/Cellar/coreutils -name tr`
			if [ "${tr_tmp}" ]; then tr="${tr_tmp}"; fi
		fi
		OSX_KEYCHAIN_PASS=${OSX_KEYCHAIN_PASS:-`env LC_CTYPE=C ${tr} -dc "a-zA-Z0-9-_" < /dev/urandom | head -c 20`}
		create_keychain
		sudo -i -u ${SERVICE_USER} ${SERVICE_WRKSPC}/security.sh set-password --password=${SLAVE_TOKEN} --account=${MASTER_USER} --service=\"${SLAVE_NODE}\"
		KEYSTORE_PASS=`sudo -i -u ${SERVICE_USER} ${SERVICE_WRKSPC}/security.sh get-password --account=${SERVICE_USER} --service=java_truststore`
		KEYSTORE_PASS=${KEYSTORE_PASS:-`env LC_CTYPE=C ${tr} -dc "a-zA-Z0-9-_" < /dev/urandom | head -c 20`}
		sudo -i -u ${SERVICE_USER} ${SERVICE_WRKSPC}/security.sh set-password --password=${KEYSTORE_PASS} --account=${SERVICE_USER} --service=java_truststore
	elif [ "${OS}" = "FreeBSD" ]; then
		KEYSTORE_PASS=${KEYSTORE_PASS:-`head -c 32768 /dev/urandom | sha1`}
	else
		KEYSTORE_PASS=${KEYSTORE_PASS:-`head -n 16 /dev/urandom | sha1sum | awk '{print $1}'`}
	fi

	if [ "${PROTOCOL}" = "https" ]; then
		echo "Trying to auto import ${MASTER} SSL certificate ..."

		MASTER_HOST=`echo $MASTER | cut -d':' -f2 | cut -d'/' -f3`
		openssl s_client -connect ${MASTER_HOST}${MASTER_HTTP_PORT} < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ${SERVICE_WRKSPC}/${MASTER_NAME}.cer
		keytool -import -noprompt -trustcacerts -alias ${MASTER_NAME} -file ${SERVICE_WRKSPC}/${MASTER_NAME}.cer -keystore ${SERVICE_HOME}/.keystore -storepass ${KEYSTORE_PASS}
		keytool -list -v -keystore ${SERVICE_HOME}/.keystore -storepass ${KEYSTORE_PASS}

		echo
		echo "
If the certificate for ${MASTER_NAME} is not trusted by Java, you will need
to install public certificates required for Java to trust ${MASTER_NAME}.
NOTE: The installer is not capable of testing that Java trusts ${MASTER_NAME}.

If ${MASTER_NAME} has a self-signed certifate, the public certificate
must be imported. If the certificate for ${MASTER_NAME} is signed by
a certificate authority, you may need to import both the root and server CA
certificates.

To install certificates, you will need to:
1) copy or download the certificates into ${SERVICE_HOME}
2) use the following command:
sudo -i -u ${SERVICE_USER} ${SERVICE_WRKSPC}/security.sh add-java-certificate \
--alias=AN_ALIAS --certificate=/path/to/certificate
If the certificate is a Root CA cert, add the --ca-cert flag to the above
command.
"
	fi
	create_ssh_keys
	configure_github
	echo
	echo "
If you need to do additional tasks to setup ${SERVICE_USER}, you can
sudo -i -u ${SERVICE_USER}
in Terminal to open a shell running as ${SERVICE_USER}
"
}

contains() { case $2 in *$1*) true;; *) false;; esac; }
beginswith() { case $2 in $1*) true;; *) false;; esac; }

create_ssh_keys() {
	if [ ! -f ${SERVICE_HOME}/.ssh/id_rsa ]; then
		echo "
Do you wish to create SSH keys for this ${SERVICE_USER}? These keys will be
suitable for GitHub, amoung other services. Keys generated at this point will
not be protected by a password.
"
		if [ "${G_CONFIRM}" = "yes" ]; then
			CONFIRM="yes"
		else
			read -p "Create SSH keys? (yes/no) [yes]" CONFIRM
			CONFIRM=${CONFIRM:-yes}
		fi
		if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
			if [ "${OS}" = "Darwin" ]; then
				echo n | sudo -i -u ${SERVICE_USER} ssh-keygen -t rsa -N \'\' -f ${SERVICE_HOME}/.ssh/id_rsa -C \"${SERVICE_USER}@${SLAVE_NODE}\"
			else
				echo n | sudo su - ${SERVICE_USER} -c "ssh-keygen -t rsa -N '' -f ${SERVICE_HOME}/.ssh/id_rsa -C ${SERVICE_USER}@${SLAVE_NODE}"
			fi
		fi
		echo "
You will need to connect to each SSH host as ${SERVICE_USER} to add the host
to the known_hosts file to allow the service to use SSH. This can be done
using the following command:
sudo -i -u ${SERVICE_USER} ssh account@service

To get ${SERVICE_USER}'s public key to add to a service to allow SSH:
sudo -i -u ${SERVICE_USER} cat ${SERVICE_HOME}/.ssh/id_rsa.pub
"
	fi
}

configure_github() {
	if [ "${G_CONFIRM}" = "yes" ]; then
		CONFIRM="no"
	else
		read -p "Will this slave need to connect to GitHub? (yes/no) [no]" CONFIRM
		CONFIRM=${CONFIRM:-no}
	fi
	if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
		echo "Attempting to SSH to GitHub... You may be prompted to trust github.com."
		sudo -i -u ${SERVICE_USER} ssh -T git@github.com
		RESULT=$?
		if [ $RESULT -eq 255 ] ; then
			echo "
You need to add the ssh keys to the GitHub account that Jenkins uses

Copy the following key to https://github.com/settings/ssh after you have
logged into GitHub as the user that Jenkins connects to GitHub as
"
			sudo -i -u ${SERVICE_USER} cat ${SERVICE_HOME}/.ssh/id_rsa.pub
		fi
	fi
}

configure_adc() {
	if [ "${G_CONFIRM}" = "yes" ]; then
		CONFIRM="yes"
	else
		read -p "Will this slave need Apple Developer Certificates? (yes/no) [yes]" CONFIRM
		CONFIRM=${CONFIRM:-yes}
	fi
	if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
		echo "Importing WWDR intermediate certificate..."
		sudo -i -u ${SERVICE_USER} curl  --silent -L --remote-name --url https://developer.apple.com/certificationauthority/AppleWWDRCA.cer
		sudo -i -u ${SERVICE_USER} ${SERVICE_WRKSPC}/security.sh add-apple-certificate --certificate=${SERVICE_HOME}/AppleWWDRCA.cer
		sudo -i rm ${SERVICE_HOME}/AppleWWDRCA.cer
		echo "
You will need to import your own developer certificates following these steps:
1) Export the Certificate and Key from Keychain for your developer profiles.
2) sudo cp /path/to/exported-keys-and-certificates ${SERVICE_HOME}
3) For each certificate and key (this is a single multiline command):
   sudo -i -u ${SERVICE_USER} ${SERVICE_WRKSPC}/security.sh \
   add-apple-certificate --certificate=${SERVICE_HOME}/name-of-exported-cert
"
	fi
}

create_keychain() {
	local KEYCHAINS=${SERVICE_HOME}/Library/Keychains
	if [ ! -d ${KEYCHAINS} ]; then
		sudo mkdir -p ${KEYCHAINS}
		sudo chown -R ${SERVICE_USER}:${SERVICE_GROUP} ${KEYCHAINS}
	fi
	if [ ! -f ${KEYCHAINS}/${OSX_KEYCHAIN} ]; then
		sudo -i -u ${SERVICE_USER} security create-keychain -p ${OSX_KEYCHAIN_PASS} ${OSX_KEYCHAIN}
		if [ -f ${KEYCHAINS}/.keychain_pass ]; then
			sudo chmod 666 ${KEYCHAINS}/.keychain_pass
		fi
		sudo chmod 777 ${KEYCHAINS}
		sudo sh -c "echo 'OSX_KEYCHAIN_PASS=${OSX_KEYCHAIN_PASS}' > ${KEYCHAINS}/.keychain_pass"
		sudo chown -R ${SERVICE_USER}:${SERVICE_GROUP} ${KEYCHAINS}
		sudo chmod 400 ${KEYCHAINS}/.keychain_pass
		sudo chmod 755 ${KEYCHAINS}
	fi
	echo "
The OS X Keychain password for ${SERVICE_USER} is ${OSX_KEYCHAIN_PASS}
You will need to copy this into the Jenkins configuration on ${MASTER_NAME}
for every project that will be compiled on this slave, or copy a special
per-project Keychain to ${SERVICE_HOME}/Library/Keychains.

Note that the login Keychain for ${SERVICE_USER} contains secrets needed for
${SLAVE_NODE} to connect to ${MASTER_NAME}.
"
}

write_config() {
	# ensure JAVA_ARGS specifies a setting for java.awt.headless (default to true)
	tmp="-Djava.awt.headless=true"
	if ! contains "${tmp}" "${JAVA_ARGS}"; then
		JAVA_ARGS="${JAVA_ARGS} ${tmp}"
	fi
	# create config directory
	sudo mkdir -p `dirname ${SERVICE_CONF}`
	sudo chmod 777 `dirname ${SERVICE_CONF}`
	# make the config file writable
	if [ -f ${SERVICE_CONF} ]; then
		sudo chmod 666 ${SERVICE_CONF}
	fi
	# write the config file
	if beginswith ":" "${MASTER_HTTP_PORT}"; then
		MASTER_HTTP_PORT=${MASTER_HTTP_PORT#":"}
	fi
	CONF_TMP=${INSTALL_TMP}/org.jenkins-ci.slave.jnlp.conf
	:> ${CONF_TMP}
	echo "JENKINS_SLAVE=\"${SLAVE_NODE}\"" >> ${CONF_TMP}
	echo "JENKINS_MASTER=${MASTER}" >> ${CONF_TMP}
	echo "HTTP_PORT=${MASTER_HTTP_PORT}" >> ${CONF_TMP}
	echo "JENKINS_USER=${MASTER_USER}" >> ${CONF_TMP}
	echo "JAVA_ARGS=\"${JAVA_ARGS}\"" >> ${CONF_TMP}
	if [ "${OS}" != "Darwin" ]; then
		echo "JAVA_TRUSTSTORE_PASS=${KEYSTORE_PASS}" >> ${CONF_TMP}
		echo "SLAVE_TOKEN=${SLAVE_TOKEN}" >> ${CONF_TMP}
	fi
	sudo mv ${CONF_TMP} ${SERVICE_CONF}
	# secure the config file
	sudo chmod 755 `dirname ${SERVICE_CONF}`
	sudo chmod 644 ${SERVICE_CONF}
	sudo chown -R ${SERVICE_USER}:${SERVICE_GROUP} ${SERVICE_HOME}
}

start_daemon() {
	case ${OS} in
		'Darwin')
			BOOT_CMD=""
			START_CMD="sudo launchctl load /Library/LaunchAgents/org.jenkins-ci.slave.jnlp.plist"
			STOP_CMD="sudo launchctl unload /Library/LaunchAgents/org.jenkins-ci.slave.jnlp.plist"
			;;
		'FreeBSD')
			BOOT_CMD=""
			START_CMD="sudo service jenkins_slave start"
			STOP_CMD="sudo service jenkins_slave stop"
			;;
		'SunOS')
			BOOT_CMD=""
			START_CMD="sudo svcadm enable jenkins-slave"
			STOP_CMD="sudo svcadm disable jenkins-slave"
			;;
		'Linux')
			OS_DISTRO="Unknown"
			if [ -f /etc/redhat-release ]; then
				OS_DISTRO="Redhat"
			elif [ -f /etc/debian_version ]; then
				OS_DISTRO="Debian"
			else
				OS_DISTRO="Other"
			fi

			if [ -d "/lib/systemd/system" ]; then
				systemctl daemon-reload
				BOOT_CMD="systemctl enable jenkins-slave"
				START_CMD="sudo service jenkins-slave start"
				STOP_CMD="sudo service jenkins-slave stop"
			fi

			case ${OS_DISTRO} in
				'Debian')
					BOOT_CMD="systemctl enable jenkins-slave"
					START_CMD="sudo service jenkins-slave start"
					STOP_CMD="sudo service jenkins-slave stop"
					;;
				'Redhat')
					BOOT_CMD="chkservice jenkins-slave on"
					START_CMD=""
					STOP_CMD=""
					;;
				*)
					echo
					echo "Sorry but ${OS_DISTRO} is not supported"
					;;
			esac
			;;
		*)
			echo
			echo "Sorry but ${OS} is not supported"
			exit 1
		;;
	esac

	echo "
The Jenkins JNLP Slave service is installed

This service can be started using the command
    ${START_CMD}
and stopped using the command
    ${STOP_CMD}

This service logs to /var/log/${SERVICE_USER}/org.jenkins-ci.slave.jnlp.log
"
	if [ "${G_CONFIRM}" = "yes" ]; then
		CONFIRM="yes"
	else
		read -p "Start the slave service now (yes/no) [yes]? " CONFIRM
		CONFIRM=${CONFIRM:-yes}
	fi
	if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
		if [ "${START_CMD}" ]; then
			${START_CMD}
		fi
		if [ "${OS}" = "Darwin" ]; then
			echo
			if [ "${G_CONFIRM}" = "yes" ]; then
				CONFIRM="no"
			else
				read -p "Open Console.app to view logs now (yes/no) [no]? " CONFIRM
				CONFIRM=${CONFIRM:-no}
			fi
			if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
				open /var/log/${SERVICE_USER}/org.jenkins-ci.slave.jnlp.log
			fi
		fi
	fi
}

cleanup() {
	rm -rf ${INSTALL_TMP}
	exit $1
}

echo "
        _          _   _              _ _  _ _    ___   ___ _              
     _ | |___ _ _ | |_(_)_ _  ___  _ | | \| | |  | _ \ / __| |__ ___ _____ 
    | || / -_) ' \| / / | ' \(_-< | || | .\` | |__|  _/ \__ \ / _\` \ V / -_)
     \__/\___|_||_|_\_\_|_||_/__/  \__/|_|\_|____|_|   |___/_\__,_|\_/\___|

This script will download, install, and configure a Jenkins JNLP Slave on ${OS}.

You must be an administrator on the system you are installing the Slave on,
since this installer will add a user to the system and then configure the slave
as that user.

A Java Development Kit (JDK) must be installed prior to installing the Jenkins
JNLP Slave.

During the configuration, you will be prompted for necessary information. The
suggested or default response will be in brackets [].
"
case ${OS} in
	'Darwin')  ;;
	'FreeBSD') ;;
	'SunOS')   ;;
	'Linux')   ;;
	*)
		echo
		echo "Sorry but ${OS} is not supported"
		exit 1
	;;
esac
# $@ must be quoted in order to handle arguments that contain spaces
# see http://stackoverflow.com/a/8198970/14731
process_args "$@"
if [ "${G_CONFIRM}" = "yes" ]; then
	CONFIRM="yes"
else
	read -p "Continue (yes/no) [yes]? " CONFIRM
	CONFIRM=${CONFIRM:-yes}
fi
if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
	echo
	echo "Verifying that you may use sudo. You may be prompted for your password"
	if ! sudo -v ; then
		echo "Unable to use sudo. Aborting installation"
		cleanup 1
	fi
	if [ "${OS}" = "Darwin" ]; then
		create_user_osx
	else
		create_user
	fi
	process_conf
	echo "Installing files..."
	install_files
	echo "Configuring daemon..."
	configure_daemon
	if [ "${OS}" = "Darwin" ]; then
		configure_adc
	fi
	write_config
	start_daemon
else
	echo "Aborting installation"
	cleanup 1
fi

cleanup 0
