# HackerOne Report: Broken Authentication and session management OWASP A2
**Report ID:** 284
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Description:
Session management issue in https://www.hackerone.com

Cookies are used to maintain session of the particular user and they should expire once the user logs out of his hackerone account.In secure web application,Cookies immediately expire once the user logs out of his account.

But this is not happening in the case of hackerone same cookies can be used again and again  to open the session of the victim.
Extensions required and Browser Version:
Google chrome
Version 26.0.1410.64 m

Edit this cookie extension

Steps to reproduce the issue:
=======================
1) Create a Hackerone account and log in into the newly created account or you can use your existing account as well.
2) Copy the cookies using Edit this cookie extension when you are logged in using "Import Cookies" option of the extension.
3) Now log out from your Hackerone account and save the cookies in the Notepad file.
4) After 6 hrs or 8 hrs copy the same cookies in your Chrome using the same extension and you will be logged into your account.The cookies are not getting expired once the user logs out of his account.

Benefits :)

Suppose if a XSS vulnerability is exploited in the web application (there is not any )  the hacker can use same cookies again and again to open the session of the victim but what if there are new cookies when the victim logs out from his account on the other end the hacker session also expires.

Please have a look,
Looking forward to hear from you.
Best Regards,
Anand Prakash 
https://www.twitter.com/sehacure

## Discussion & Remediation Timeline
