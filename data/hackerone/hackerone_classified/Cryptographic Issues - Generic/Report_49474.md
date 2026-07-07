# HackerOne Report: Cross site Port Scanning bug in twitter developers console 
**Report ID:** 49474
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
This vulnerability allow a port scanning a remote machine on internet . an attacker can scan a remote machine through this vulnerability using twitter ip as a proxy .

The vulnerability exit  on url https://dev.twitter.com/rest/tools/console
through console an attacker can use GET or POST request with basic authentication or no authentication for a successful port scan on a remote machine using any service .
let take as http://www.sd-host.net as target(which i setup with open port 80,2082,2083)

in the Request url i put this http://www.sd-host.net:80
and i get the following respond 
url: 
 it seems that port 80 is open on the remote machine 
then i changed the port to 8080 
hence its a close port i got following respond
refer poc 2
then i changed the port to 2082 (cpanel)
as it a password protected page (cpanel)

i got access denied 
refer poc 3

then i tried to access http://www.ibm.com/robots.txt over port 80
and got succeed 
following respond i got  refer poc 4 

when i changed the port to 809
i got respond  like this poc 5

hence its clear that we can access and perform attack on a remote machine using developer console 

by this vulnerability we can use twitter ip as proxy and exploit a remote service running on a remote machine


## Discussion & Remediation Timeline
