# blockwatch
        Version 2.0

This little script is a light-weight defense against brute-force ssh attacks, for very resource-limited systems.  It doesn't need Python, Perl, Java, c - or much of anything else except a few standard Linux utilities.

It was developed and tested on RedHat/Centos/Fedora, but should be adaptable to other distros.

This must be run as root, since it tails sensitive log files.

The script watches /var/log/syslog for lines indicating  invalid login attempts via ssh.  It assumes that your sshd is hardened against the most common attacks, and  that you have an iptables firewall with the following  rule in the INPUT chain:

~~~
  iptables -A INPUT -m set --match-set inblockip src -j DROP
~~~

This script will extract the IP addresses of failed logins, add them to the ipset.  Your system will then effectively  and efficiently disappear from the Internet to that attacker.

Before running this script, create the ipset like this:

~~~
  ipset create inblockip hash:ip
~~~

You can add this to the system startup script just before  launching blockwatch.sh like this:

~~~
 ipset create inblockip hash:ip
 nohup /<path to the script>/blockwatch.sh >/tmp/blockwatch.log 2>&1 &
~~~

This version not only adds to the ipset, but it writes a logfile in CSV format.  The fields are:

 timestamp,"IP addresss","username","violation"

- timestamp is the epoch time when the log entry was read by blockwatch
- "IP address" is the ip of the intruder
- "username" is the ssh username they tried
- "violation" is either "invalid" or "disallowed"
       "invalid" means the username is not in the system (/etc/passwd)
       "disallowed" means the username is not in AllowUsers in sshd_config

Sending a SIGUSR1 to the process ID of the script will cause it to rotate the logfile to a date-based name, and then continue recording to a new copy of the original name.  You can do this with:

~~~
   pkill -USR1  'blockwatch2.sh'
~~~

Use this to keep your logfile from growing forever.

This script uses only native tools found on nearly every Linux installation, and it very light on resources.  Namely, bash >= version 4, tail, grep, and the ipset module in iptables.

It's a tiny SOAR!

