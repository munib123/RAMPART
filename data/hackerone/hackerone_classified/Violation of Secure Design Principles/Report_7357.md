# HackerOne Report: Host Header is not validated resulting in Open Redirect
**Report ID:** 7357
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Please see the attached screenshot where I am sending a request to irccloud.com with an invalid HOST header and I am getting redirected to that domain. This is because the HOST header is not validated to ensure that the request is originating from that target host or not.

http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html http://carlos.bueno.org/2008/06/host-header-injection.html 
The above links mention 2 different ways to exploit this issue:
1. web-cache poisoning and/or 
2. Using alternate channels like password reset emails. 

For the first way, it can be exploited by poisoning a cache with the attacker's domain and then serving that poisoned response to legitimate users, causing them to redirect to the attacker's domain. This attack kind of varies depending on different web servers as they interpret duplicate Host headers in different ways. The attack vectors are very well explained in the above blogs so I don't want to re-iterate them here again. 

For the second way, I verified that the password reset functionality on the IRC Cloud website does not retrieve the Host header when sending emails. But, validating the Host header is always a good practice. 

## Discussion & Remediation Timeline
