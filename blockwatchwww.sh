#!/bin/bash
#
# blockwatchwww.sh - populate an ipset from Apache httpd failures
#
# This script is a light-weight defense against brute-force attacks
# on an Apache http server.  It watches the /var/log/httpd/ssl_access_log 
# (or /var/log/httpd/access_log if you're not using SSL) for entries
# with a 400-series error code.  The IP address of the offending system is
# extracted, and added to a defensive ipset.  The iptables firewall then
# drops all further traffic from that address.  This is simple, but 
# effective.
#
# It was developed and tested on RedHat/Centos/Fedora, but should
# be adaptable to other distros.  It expects the Apache logs to be
# in the default format.  If you change the log output, you'll have
# to modify the regular expression in grep below.
#
# This must be run as root, since it tails sensitive log files.
#
# This function could be done in Python, Perl, Java, c, etc..  But the small 
# system it was designed for has none of those.  It has just enough Linux 
# to support Apache and some admin functions, so we can only use what we
# have.  This script requires bash >= version 4, tail, grep, tr, and the ipset 
# module in iptables.
#
# Before running this script, create the ipset like this:
#
#  ipset create inblockwwwip hash:ip
#
# and add this rule to your iptables firewall:
#
# iptables -A INPUT -p tcp --dport 443 -m set --match-set inblockwwwip src -j DROP
#
# Start the script like this:
#
# nohup /<path to the script>/blockwatchwww.sh >/tmp/blockwatchwww.log 2>&1 &
#
#
# This script not only adds to the ipset, but it writes a logfile
# in CSV format.  The fields are:
#
# timestamp,"IP addresss",http code,"url"
#
# timestamp is the epoch time when the log entry was read by blockwatch
# "IP address" is the ip of the intruder
# http code is the 400-series error code from the server (i.e. 400, 404, etc.)
# "url" is the method and URL from the server, like this:
#
#   "GET /.git/config HTTP/1.1"
#
# Sending a SIGUSR1 to the process ID of the script will cause it to
# rotate the logfile to a date-based name, and then continue recording to
# a new copy of the original name.  You can do this with:
#
#   pkill -USR1 -f 'blockwatchwww.sh'
#
# Mark Anacker  closecrowd@pm.me
# Version 1.0
# -----------------------------------------------------


# ipset command
IPSET=/sbin/ipset

# The name of the ipset to add the bogey IPs to.  If this is "",
# then no ipset update is made.
SETNAME="inblockwwwip"

# The name of the apache log file to watch for ssl error messages
SYSLOG="/var/log/httpd/ssl_access_log"

# The name of a file to write the script's PID to.  Useful for
# monitoring the script and automatically restarting it.  If
# this is "", no file will be created.
PIDFILE="/var/run/blockwatchwww.pid"

# This IP is never added to the ipset.  Set to "" to disable.
# This is a safety measure to keep you from locking yourself
# out of your own system.
HOMEIP=""

# The name of the current logfile.  If this is "", then
# no logfile will be written.
LOGFILE="/var/log/blockwatchwww.log"

##########

# Logfile rotate flag global - set by a SIGUSR1
ROTFLAG=""      # leave undefined

# ---------------------------------------------------------------------------
#
# Support functions
#
# ---------------------------------------------------------------------------


#
# set the flag to rotate the logfile.  Called by
# the trap SIGUSR1
#
flag_rotate()
{
    printf -v "ROTFLAG" -- "Y"
}

#
# clear out the pidfile (if defined) at exit time
#
remove_pidfile()
{
  if [ "$PIDFILE" ]
  then rm -f "$PIDFILE"; fi
}

#
# save the current logfile under a new name
#
rotate_log()
{
    # return if there is no logfile
    if [ -z "$LOGFILE" ]
    then return; fi

    LOGDATE="$(date +'%F-%H-%M')"

    # make sure it's a new entry
    rm -f "$LOGFILE.$LOGDATE.sav"
    # link the file to the new archive name
    ln $LOGFILE "$LOGFILE.$LOGDATE.sav"
    # get rid of the old name
    rm -f $LOGFILE
    # create a new file
    touch $LOGFILE
    # reset the rotate flag
    printf -v "ROTFLAG" -- ""
}

#
# write a line to the current logfile, if one is defined
#
write_log()
{
local MSG="$@"

    IFS="$OLDIFS"
    if [ "$LOGFILE" ]
    then echo "$MSG" >>$LOGFILE; fi
    IFS=","
}

# ---------------------------------------------------------------------------
#
# Main loop
#
# ---------------------------------------------------------------------------

# ignore USR1 in the main shell
trap '' SIGUSR1

# remove any left-over PIDFILE when this script exits
trap remove_pidfile EXIT SIGINT SIGTERM

# try to write a PIDFILE if defined
if [ "$PIDFILE" ]
then echo "$$" > $PIDFILE; fi

# create the logfile if needed (and defined)
if [ "$LOGFILE" ]
then touch "$LOGFILE"; fi


OLDIFS="$IFS"
IFS=","

# read the lines from the apache log
# we use --follow=name to continue when logrotate switches 
# to a new file

tail --follow=name $SYSLOG|while true
do

    # catch a SIGUSR1 signal and set the rotate flag
    trap flag_rotate SIGUSR1

    # wait up to 10 seconds for a log line
    read -t 10 INL

    # if we were signalled to do a log rotate
    if [ "$ROTFLAG" ]
    then
        # switch to a new logfile
        rotate_log
        # reset the rotate flag
        ROTFLAG=""
    fi

    # timed out or an empty line
    if [ -z "$INL" ]
    then continue; fi

    # extract the juicy bits from the log file
    #
    # Log lines look like this:
    #
    # 43.158.213.246 - - [20/Mar/2024:22:57:33 -0400] "GET /wh/glass.php HTTP/1.1" 404 210
    #
    # This is a rather nasty regex, but it does the job with a little help from tr
    #
    echo "$INL"" !"| grep -E -o '("([^"]*)")|(([0-9]{1,3}\.){3}[0-9]{1,3})|( 40[0-9])|(!$)'|tr '\n' ','|tr '!' '\n'|while read IP URL RCODE 
    do
        # strip the mebedded space
        RCODE=${RCODE// }
        # skip invalid entries
        if [ -z "$RCODE" ]
        then break; fi

        # skip the allowed IP
        if [ "$IP" == "$HOMEIP" ]
        then continue; fi

        # In a future version, you may want to add additional
        # filtering on the URL string at this point.  Maybe 
        # not all errors should result in a block?


        # get the current epoch timestamp for the csv log
        NOW="$(date +'%s')"

        # add the ip to the ipset (if defined)
        if [ "$SETNAME" ]
        then $IPSET add $SETNAME $IP 2>/dev/null; fi

        # write the log
        OUT="$NOW,\"$IP\",$RCODE,$URL"
        write_log $OUT
    done
done

# restore the normal separator
IFS="$OLDIFS"

