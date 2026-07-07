# HackerOne Report: Multiple sub domain are vulnerable because of leaking full path 
**Report ID:** 62778
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
At the following address i have found debug.log file disclose the application full path onthe server.

https://business.udemy.com/wp-content/debug.log

http://about.udemy.com/wp-content/debug.log

THe below URLs showing the version number of the application :

http://about.udemy.com/readme.html

http://about.udemy.com/wp-content/plugins/all-in-one-seo-pack/readme.txt



## Discussion & Remediation Timeline
