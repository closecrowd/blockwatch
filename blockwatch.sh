#!/bin/bash
#
# blockwatch - populate an ipset from ssh auth failures
#
# This little script is a light-weight defense against
# brute-force ssh attacks, for very resource-limited
# systems.  It doesn't need Python, Perl, Java, c - or
# much of anything else except a few standard Linux utilities.
#
# It was developed and tested on RedHat/Centos/Fedora, but should
# be adaptable to other distros.
#
# This must be run as root, since it tails sensitive log files.
#
# The script watches /var/log/syslog for lines indicating 
# invalid login attempts via ssh.  It assumes that your
# sshd is hardened against the most common attacks, and 
# that you have an iptables firewall with the following 
# rule in the INPUT chain:
#
#   iptables -A INPUT -m set --match-set inblockip src -j DROP
# 
# This script will extract the IP addresses of failed logins,
# add them to the ipset.  Your system will then effectively 
# and efficiently disappear from the Internet to that attacker.
#
# Before running this script, create the ipset like this:
#
#  ipset create inblockip hash:ip
#
# You can add this to the system startup script just before 
# launching blockwatch.sh like this:
#
# ipset create inblockip hash:ip
# nohup /<path to the script>/blockwatch.sh >/tmp/blockwatch.log 2>&1 &
#
# This version not only adds to the ipset, but it writes a logfile
# in CSV format.  The fields are:
#
# timestamp,"IP addresss","username","violation"
#
# timestamp is the epoch time when the log entry was read by blockwatch
# "IP address" is the ip of the intruder
# "username" is the ssh username they tried
# "violation" is either "invalid" or "disallowed"
#       "invalid" means the username is not in the system (/etc/passwd)
#       "disallowed" means the username is not in AllowUsers in sshd_config
#
# Sending a SIGUSR1 to the process ID of the script will cause it to
# rotate the logfile to a date-based name, and then continue recording to
# a new copy of the original name.  You can do this with:
#
#   pkill -USR1  'blockwatch2.sh'
#
# Use this to keep your logfile from growing forever.
#
# This script uses only native tools found on nearly every 
# Linux installation, and it very light on resources.  Namely,
# bash >= version 4, itail, grep, and the ipset module in
# iptables.
#
# It's a tiny SOAR!
#
# Mark Anacker  closecrowd@pm.me
# Version 2.0
# -----------------------------------------------------
#

# verbose flag
FLAGS="$1"

# ipset command
IPSET=/sbin/ipset

# The name of the ipset to add the bogey IPs to.  If this is "",
# then no ipset update is made.
SETNAME="inblockip"

# The name of the system log file to watch for sshd auth messages
SYSLOG="/var/log/secure"

# The name of a file to write the script's PID to.  Useful for
# monitoring the script and automatically restarting it.  If
# this is "", no file will be created.
PIDFILE="/var/run/blockwatch.pid"

# This IP is never added to the ipset.  Set to "" to disable.
# This is a safety measure to keep you from locking yourself
# out of your own system.
HOMEIP=""

# The name of the current logfile.  If this is "", then
# no logfile will be written.
LOGFILE="/var/log/blockwatch.log"



# Logfile rotate flag global - set by a SIGUSR1
ROTFLAG=""      # leave undefined

# ---------------------------------------------------------------------------
#
# Support functions
#
# ---------------------------------------------------------------------------

#
# test a string to see if it's a dotted-quad IP address
#   i.e. 8.8.8.8
# and make sure each octet is in the range 0-255.
#
# return:   0 if it's an apparently-valid IP 
#           1 if it's not in the n.n.n.n format
#           2 if any of the octets are out of range
#
is_numeric_ip() 
{
local IPARG="$1"
# regex matching nnn.nnn.nnn.nnn where nnn is 0-255
local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
local octets

    # see if the string matches the regex
    if [[ $IPARG =~ $regex ]]
    then
        # convert each octet into an array entry
        IFS='.' read -ra octets <<< "$IPARG"
        # for each entry in the array
        for octet in "${octets[@]}"
        do
            # see if it's in the 8-bit range
            if ((octet < 0 || octet > 255))
            then
                # return as invalid
                return 2
            fi
        done
        # this one seems to be a valid format
        return 0
    else
        # bad IP - not dotted-quad format
        return 1
    fi
}

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
local MSG=$1

    if [ "$LOGFILE" ]
    then echo "$MSG" >>$LOGFILE; fi
}

# ---------------------------------------------------------------------------
#
# Log entry processing
#
# ---------------------------------------------------------------------------

#
# Process lines that look like this:
#
# Nov  2 14:01:55 myhost sshd[1866]: Invalid user user1 from 190.55.141.229 port 36051
#
typea()
{
local OUT

  # extract the bits that we want from the log line
  echo "$@"|grep -E --line-buffered -o '(Invalid user).*'|while read J1 J2 USRNAME J3 IP J4 PORT JUNK
  do
    # skip invalid lines
    if [ ! "$IP" ]
    then continue; fi

    # skip the allowed IP
    if [ "$IP" == "$HOMEIP" ]
    then continue; fi

    # add the ip to the ipset (if defined)
    if [ "$SETNAME" ]
    then $IPSET add $SETNAME $IP 2>/dev/null; fi

    # write the log
    OUT="$NOW,\"$IP\",\"$USRNAME\",\"invalid\""
    write_log $OUT 

  done
}

#
# Process lines that look like this:
#
#  Nov  3 10:43:12 myhost sshd[9922]: User root from vps-5ceba4be.vps.ovh.net not allowed becausot listed in AllowUsers
#  
# Note that this format may record the DNS name of the remote system, so we
# have to check the IP string and resolve it to an IP address if needed
#
typeb()
{
local IP
local OUT

  # extract the right end of the line from 'User' on
  echo "$@"|grep -E --line-buffered -o '(User .*)'|while read J1 USRNAME J2 IP JUNK
  do

    # skip invalid lines
    if [ ! "$IP" ]
    then continue; fi

    # check to see if the IP field is a numeric IP
    is_numeric_ip "$IP"; RV=$?
    # no, try to resolve it - sometimes it's an FQDN
    if [ $RV -ne 0 ]
    then
        # resolve the domain to IP and extract the last IP address
        IP="`nslookup -query=A $IP|grep -E -o '([0-9]{1,3}.){3}[0-9]{1,3}$'|tail -1`"
    fi

    if [ ! "$IP" ]
    then continue; fi

    # skip the allowed IP
    if [ "$IP" == "$HOMEIP" ]
    then continue; fi

    # add the ip to the ipset (if defined)
    if [ "$SETNAME" ]
    then $IPSET add $SETNAME $IP 2>/dev/null; fi

    # write the log
    OUT="$NOW,\"$IP\",\"$USRNAME\",\"disallowed\""
    write_log $OUT

  done
}


#
# Process lines that look like this:
#
# Mar  8 22:37:28 myhost sshd[27176]: Bad protocol version identification '003' from 45.227.254.49 port 65158
#
typec()
{
local USRNAME
local OUT

  # extract the bits that we want from the log line
  echo "$@"|grep -E --line-buffered -o '(identification).*'|while read J1 PROT J2 IP J3 PORT JUNK
  do
    # skip invalid lines
    if [ ! "$IP" ]
    then continue; fi

    # skip the allowed IP
    if [ "$IP" == "$HOMEIP" ]
    then continue; fi

    # strip the single-quotes from the protocol field (if any)
    USRNAME="${PROT//\'/}"

    # add the ip to the ipset (if defined)
    if [ "$SETNAME" ]
    then $IPSET add $SETNAME $IP 2>/dev/null; fi

    # write the log
    OUT="$NOW,\"$IP\",\"$USRNAME\",\"protocol\""
    write_log $OUT 

  done
}


# ---------------------------------------------------------------------------
#
# Main loop
#
# ---------------------------------------------------------------------------

# catch a SIGUSR1 signal and set the rotate flag
trap 'flag_rotate' SIGUSR1

# remove any left-over PIDFILE when this script exits
trap 'remove_pidfile' EXIT INT TERM

# verbose mode
if [ "$FLAGS" == "-v" ]
then echo "Send SIGUSR1 to $$ to rotate the logfile"; fi

# try to write a PIDFILE if defined
if [ "$PIDFILE" ]
then echo "$$" > $PIDFILE; fi

# create the logfile if needed (and defined)
if [ "$LOGFILE" ]
then touch "$LOGFILE"; fi

# read the lines from syslog
# we use --follow=name to continue when logrotate switches 
# to a new fil3

tail --follow=name $SYSLOG|while read INL
do

    # skip blank lines
    if [ ! "$INL" ]
    then continue; fi

    # verbose mode
    if [ "$FLAGS" == "-v" ]
    then echo "$INL"; fi

    # if we were signalled to do a log rotate
    if [ "$ROTFLAG" ]
    then
        # switch to a new logfile
        rotate_log
        # reset the rotate flag
        printf -v "ROTFLAG" -- ""
    fi

    # get the current epoch timestamp for the csv log
    NOW="$(date +'%s')"

    # process the different log messages

    # they have to be processed in this order - typeb before typea
    if [[ $INL =~ 'not allowed' ]]
    then 
        typeb "$INL"    # disallowed
        continue
    fi

    if [[ $INL =~ 'Invalid user' ]]
    then 
        typea "$INL"    # invalid
        continue
    fi

    if [[ $INL =~ 'Bad protocol' ]]
    then 
        typec "$INL"    # protocol
        continue
    fi

done

