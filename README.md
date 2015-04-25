# Jenkins Slave JNLP

Scripts to create and run a [Jenkins](http://jenkins-ci.org) slave via [Java Web Start](https://wiki.jenkins-ci.org/display/JENKINS/Distributed+builds#Distributedbuilds-LaunchslaveagentviaJavaWebStart) (JNLP) on different OS.

Currently the following OS are supported:
- Debian Linux
- Ubuntu Linux
- CentOS
- Fedora
- FreeBSD 10
- Solaris 10.x, 11.x
- Mac OS X (tested on Yosemite)

## Requirements
You need to have the Oracle Java or Open JDK already installed before running this script.



## Quick Start
`sh <( curl -L https://raw.github.com/antonyx/jenkins-slave-jnlp/master/install.sh )`



## Features
Slaves created with this script:
* Start on system boot
* Run as an independent user
* Use an independent Java Truststore for self-signed certificates (so your Jenkins master can use a self-signed certificate, and you do not have to instruct the slave to trust all certificates regardless of source)
* If you're using https the ssl certificate is imported automatically inside the keystore

on OS X the following features is added:
* Use an independent OS X Keychain for secrets (Slave token and Java truststore password)



## Install
`sh <( curl -L https://raw.github.com/antonyx/jenkins-slave-jnlp/master/install.sh ) [options]`

The install script has the following options:
* `--java-args="ARGS"` to specify any optional java arguments. *Optional;* the installer does not test these arguments.
* `--master=URL` to specify the Jenkins Master on the command line. *Optional;* the installer prompts for this if not specified on the command line.
* `--node=NAME` to specify the Slave's node name. *Optional;* this defaults to the OS X hostname and is verified by the installer.
* `--user=NAME` to specify the Jenkins user who authenticates the slave. *Optional;* this defaults to your username on the OS X slave and is verified by the installer.
* `--token=NAME` to specify the Jenkins user token who authenticates the slave. *Optional;* this is verified by the installer.
* `--confirm` to auto answer yes to all question asked by the installer. You always have to provide the other informations (see Configuration).



## Update
Simply rerun the installer. It will reinstall the scripts, but use existing configuration settings.



## Configuration
The file ``org.jenkins-ci.slave.jnlp.conf`` (or on OS-X ``Library/Preferences/org.jenkins-ci.slave.jnlp.conf``) in ``/var/lib/jenkins`` (assuming an installation in the default location) can be used to configure this service with these options:
* `JAVA_ARGS` specifies any optional java arguments to be passed to the slave. This may be left blank.
* `JENKINS_SLAVE` specifies the node name for the slave. This is required.
* `JENKINS_MASTER` specifies the URL for the Jenkins master. This is required.
* `JENKINS_USER` specifies the Jenkins user used to bind the master to the slave. This is required.
* `HTTP_PORT` specifies the nonstandard port used to communicate with the Jenkins master. This may be left blank for port 80 (http) or 443 (https).
* `JAVA_TRUSTSTORE_PASS` specifies the password for the Java truststore used by Jenkins. This is required only on OS different than OS-X.
* `SLAVE_TOKEN` specifies the token to be used for authentication with the Jenkins master. This is required only on OS different than OS-X.
These settings are initially set by the installation script, and only need to be changed if that script is invalidated. The slave must be restarted for changes to take effect.

## Adding Developer Certificates
Building application targets for iOS requires OS-X and that your iPhone Developer certificates be available to the Jenkins slave.

1. Export the Certificate and Key from Keychain for your developer profiles.
2. `sudo cp /path/to/exported-keys-and-certificates /var/lib/jenkins`
3. For each certificate and key:
   `sudo -i -u jenkins /var/lib/jenkins/security.sh add-apple-certificate --certificate=/var/lib/jenkins/name-of-exported-cert`
4. Delete the exported certificate file if is not password protected.

## Adding Server Certificates
If you decide to secure the Jenkins master, or need to add additional certificates for the slave to trust the Jenkins master, you only need (assuming your service account is "jenkins", and your CA is StartSSL.com) from a command line:

On OS-X:

1. `sudo launchctl unload /Library/LaunchAgents/org.jenkins-ci.slave.jnlp.plist`
2. `sudo -i -u jenkins`
3. `curl -O http://www.startssl.com/certs/ca.crt`
4. `./security.sh add-java-certificate --authority --alias=root-ca --certificate=./ca.crt`
5. `curl -O http://www.startssl.com/certs/sub.class1.server.ca.crt`
6. `./security.sh add-java-certificate --alias=ca-server --certificate=./sub.class1.server.ca.crt`
7. `rm ./*ca.crt`
8. `exit`
9. `sudo launchctl load /Library/LaunchAgents/org.jenkins-ci.slave.jnlp.plist`

On the other OS in general:

1. Stop the jenkins-slave service using the specific OS command
2. `sudo -i -u jenkins`
3. `./security.sh add-java-certificate --host=your.jenkins.host:port`
   or
   `./security.sh add-java-certificate --alias=your.alias --certificate=server.crt`
4. `exit`
5. Start the jenkins-slave service using the specific OS command



## Known Issues
None yet.



## Credits
This project is based on [jenkins-slave-osx](https://github.com/rhwood/jenkins-slave-osx.git) by Randall Wood.
