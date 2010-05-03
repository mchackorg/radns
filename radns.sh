#! /bin/sh
#
# PROVIDE: radns
# REQUIRE: network
# KEYWORD: shutdown
# 
# Add the following lines to /etc/rc.conf to enable radns:
#
# radns_enable (bool):	Set it to "YES" to enable radns
#			Default is "NO".
# radns_conf (path):	Set full path to radns' own resolv.conf
# radns_pidfile (path):	Set full path to pid file.
#

. /etc/rc.subr

name=radns
rcvar=`set_rcvar`

load_rc_config $name

# Default values
: ${radns_enable="NO"}
: ${radns_pidfile="/var/run/${name}.pid"}
: ${radns_resolv="/etc/radns-resolv.conf"}
: ${radns_script="NO"}
: ${radns_username="ftp"}

command="/usr/local/bin/${name}"

start_precmd=start_precmd
stop_postcmd=stop_postcmd

start_precmd()
{
    touch ${radns_resolv}
    chown ${radns_username} ${radns_resolv}
}

stop_postcmd()
{
    rm -f ${radns_resolv}
    rm -f ${radns_pidfile}
}

# if script:
if [ x${radns_script} != "xNO" ]
then
    command_args="-f ${radns_resolv} -s ${radns_script} -u ${radns_username} \
    -p ${radns_pidfile}"
else
    command_args="-f ${radns_resolv} -u ${radns_username} -p ${radns_pidfile}"
fi

reload_precmd()
{
    echo "Stopping ${name} and start gracefully."
}

reload_postcmd()
{
	rm -f ${radns_pidfile}
	run_rc_command start
}

# actually execute the program
run_rc_command "$1"
