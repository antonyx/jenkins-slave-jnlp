#!/bin/sh

### BEGIN INIT INFO
# Provides:          jenkins-slave
# Required-Start:    $remote_fs $syslog $network
# Required-Stop:     $remote_fs $syslog $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start Jenkins Slave at boot time
# Description:       Controls Jenkins Continuous Integration Slave
### END INIT INFO

# chkconfig: 2345 20 80
# description: Jenkins Continuous Integration Slave
# processname: jenkins-slave
# pidfile: ${JENKINS_WRKSPC}/.slave.pid

PATH=/bin:/usr/bin:/sbin:/usr/sbin

DESC="Jenkins Continuous Integration Slave Server"
NAME=jenkins-slave
SCRIPTNAME=/etc/init.d/$NAME

JENKINS_HOME="${JENKINS_HOME}"

[ -r /etc/default/$NAME ] && . /etc/default/$NAME

DAEMON=/usr/bin/daemon
DAEMON_ARGS="${JENKINS_HOME}/slave.jnlp.sh"

# load environments
if [ -r /etc/default/locale ]; then
  . /etc/default/locale
  export LANG LANGUAGE
elif [ -r /etc/environment ]; then
  . /etc/environment
  export LANG LANGUAGE
fi

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

# Source function library.
. /etc/rc.d/init.d/functions

export PATH=$PATH:/usr/bin:/usr/local/bin

# See how we were called.
case "$1" in
  start)
        # Start daemon.
        echo -n "Starting $NAME: "
        su -p -s /bin/sh $JENKINS_USER -c "$DAEMON $DAEMON_ARGS"
        RETVAL=$?
        echo
        [ $RETVAL = 0 ] && touch $LOCKFILE
        ;;
  stop)
        # Stop daemons.
        echo -n "Shutting down $NAME: "
        su -p -s /bin/sh $JENKINS_USER -c "$DAEMON $DAEMON_ARGS stop"
        RETVAL=$?
        echo
        [ $RETVAL = 0 ] && rm -f $LOCKFILE
        ;;
  restart)
        $0 stop
        sleep 1
        $0 start
        ;;
  condrestart)
       [ -e $LOCKFILE ] && $0 restart
       ;;
  status)
        status -p $CATALINA_PID -l $(basename $LOCKFILE) jenkins
        ;;
  *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
esac

exit 0
