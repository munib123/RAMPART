# HackerOne Report: Flaw in login with twitter to steal Oauth tokens
**Report ID:** 44492
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hey hi,

Steps to reproduce:
=============================================

I have been testing the twitter kit in fabric.
I added login with twitter integration to my application.
I pushed the application to my android phone , clicked login with twitter.
entered my username and password.

Searched my logcat for everything with the word "twitter" in it. 
I found the oauth token getting leaked via login with twitter integration on Fabric.
So any app that is using fabric's twitter kit ( login with twitter) is vulnerable to it.
Any other app installed on that particular phone hasaccess to logcat, and can read the logs.
which results in oauth token stealing.

Regards,
karthik
Wesecureapp


## Discussion & Remediation Timeline
