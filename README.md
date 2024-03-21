# blockwatch
        Version 2.1

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
   pkill -USR1 -f 'blockwatch.sh'
~~~

Use this to keep your logfile from growing forever.

This script uses only native tools found on nearly every Linux installation, and it very light on resources.  Namely, bash >= version 4, tail, grep, and the ipset module in iptables.

It's a tiny SOAR!

# blockwatchwww
        Version 1.0

This script is a light-weight defense against brute-force attacks on an Apache http server.  It watches the /var/log/httpd/ssl_access_log (or /var/log/httpd/access_log if you're not using SSL) for entries with a 400-series error code.  The IP address of the offending system is extracted, and added to a defensive ipset.  The iptables firewall then drops all further traffic from that address.  This is simple, but effective.

It was developed and tested on RedHat/Centos/Fedora, but should be adaptable to other distros.  It expects the Apache logs to be in the default format.  If you change the log output, you'll have to modify the regular expression in grep below.

This must be run as root, since it tails sensitive log files.

This function could be done in Python, Perl, Java, c, etc..  But the small system it was designed for has none of those.  It has just enough Linux to support Apache and some admin functions, so we can only use what we have.  This script requires bash >= version 4, tail, grep, tr, and the ipset module in iptables.

Before running this script, create the ipset like this:

~~~
  ipset create inblockwwwip hash:ip
~~~

and add this rule to your iptables firewall:

~~~
  iptables -A INPUT -p tcp --dport 443 -m set --match-set inblockwwwip src -j DROP
~~~

Start the script like this:

~~~
  nohup /<path to the script>/blockwatchwww.sh >/tmp/blockwatchwww.log 2>&1 &
~~~

This script not only adds to the ipset, but it writes a logfile in CSV format.  The fields are:

 timestamp,"IP addresss",http code,"url"

- timestamp is the epoch time when the log entry was read by blockwatch
- "IP address" is the ip of the intruder
- http code is the 400-series error code from the server (i.e. 400, 404, etc.)
- "url" is the method and URL from the server, like this:

   "GET /.git/config HTTP/1.1"

Sending a SIGUSR1 to the process ID of the script will cause it to rotate the logfile to a date-based name, and then continue recording to a new copy of the original name.  You can do this with:

   pkill -USR1 -f 'blockwatchwww.sh'

