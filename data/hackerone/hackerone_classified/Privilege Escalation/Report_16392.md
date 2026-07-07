# HackerOne Report: Abusing daemon logs for Privilege escalation under certain scenarios
**Report ID:** 16392
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
# Setup Needed

+ A normal user account
+ A momentary disruption of mail services

# Replication steps

+ Login as **normal user**
+ Wait for **momentary disruption** of mail services
+ Use **Password Reset Link** for admin mail address
+ BOOM!!!
+ You can see the password reset link in the daemon logs because of interrupted mail service (check the screenshot)
+ Click on the link and upgrade to **Admin**

# Attack Scenarios

(Virtually unlimited) 
A moment misconfiguration of 
+ Mail configuration
+ Firewall settings
+ Mail Service down
etc.. etc.. (we just need a moment :P)

I actually discovered this bug when gmail rejected my smtp credentials to prevent suspicious login :P.



## Discussion & Remediation Timeline
