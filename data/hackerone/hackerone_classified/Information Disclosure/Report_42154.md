# HackerOne Report: Gain access to any user's email address
**Report ID:** 42154
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
An attacker can gain access to any user's email address by accessing the /points/buy page. This is a serious issue because the email address is used as one of the login credentials for the website.

Steps to reproduce : 
1. Go to https://www.wnmlive.com/account/points
2. Select "Get more points"
    + You should now be at https://www.wnmlive.com/points/buy/ [YOUR PID]
3. Change the PID portion for the PID of any other user.
    + You now see the email address of that user.

This is the PID of my test account : Cqx3vGgl4RD3NNIBqeJtrg.
 You will see the email c2576767@trbvm.com instead of your own email account.

The best solution would be to use the UID stored in the cookie files rather than using the PID in the URL.


## Discussion & Remediation Timeline
