#!/bin/sh

# PROVIDE: jenkins_slave
# REQUIRE: LOGIN
# KEYWORD: shutdown

#
# Configuration settings for jenkins in /etc/rc.conf:
#
# jenkins_slave_enable (bool):
#   Set to "NO" by default.
#   Set it to "YES" to enable jenkins
#
# jenkins_home (str)
#   Set to "%%JENKINS_HOME%%" by default.
#   Set the JENKINS_HOME variable for jenkins process
#
# jenkins_user (str):
#   Set to "%%JENKINS_USER%%" by default.
#   User to run jenkins as.
#

. /etc/rc.subr

name="jenkins_slave"
rcvar=jenkins_slave_enable

load_rc_config "${name}"

: ${jenkins_slave_enable="NO"}
: ${jenkins_home="${JENKINS_HOME}"}
: ${jenkins_user="${JENKINS_USER}"}

pidfile="/var/lib/jenkins/org.jenkins-ci.slave.jnlp/.slave.pid"
command="${jenkins_home}/slave.jnlp.sh"
procname="/usr/local/openjdk7/bin/java"
logfile="/var/log/org.jenkins-ci.slave.jnlp.log"
command_args="> ${logfile}"
required_files=""

start_cmd="jenkins_start"

jenkins_start()
{
	if [ ! -f ${logfile} ]; then
		touch ${logfile}
		chown ${jenkins_user} ${logfile}
	fi
	check_startmsgs && echo "Starting ${name}."
	su -l ${jenkins_user} -c "/usr/sbin/daemon ${command} ${command_args}"
}

run_rc_command "$1"
