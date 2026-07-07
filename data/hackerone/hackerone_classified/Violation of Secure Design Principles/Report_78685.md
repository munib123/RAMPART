# HackerOne Report: Email spoofing configuration missing
**Report ID:** 78685
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC

Email spoofing in 
flox.io
buddypress.org
bbpress.org


There are few email spoofing tool is available free.one them is

http://emkei.cz/

when I tried to send a email from admin@flox.io  or admin@buddypress.org  or  admin@bbpress.org   to my email ,it was successful but when i tried to send the another from admin@facebook.com or any other , i did not receive any email.Hence, there might be some configuration missing in your mail servers (i would love to know how this is happening).

This can be dangerous ,as attacker can send some fake email about free offer .., free money or password reset etc.. , and victims may claim on  flox.io
buddypress.org
bbpress.org
( which can lead to reputation loss :)

any it can be missued in many ways

note:- check spam if you cannot find the mail in inbox
EXTRA INFO
it is Issues with the SPF, DKIM or DMARC records on flox.io
buddypress.org
bbpress.org
Thanks

## Discussion & Remediation Timeline
