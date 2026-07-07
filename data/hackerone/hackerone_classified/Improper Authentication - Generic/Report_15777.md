# HackerOne Report: Process of changing email address and password does not asks old Password.
**Report ID:** 15777
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
This Vulnerability could be destructive if The user uses a shared computer,or if he uses wordpress in a cyber cafe and forgets to logout from wordpress.
If any user uses his wordpress account in some other computer and forgets to logout,his accounts remain insecure.I was wondered that wordpress did not asked me to enter my password before changing the email address/password of my account.
So,in this particular case,if someone forgets to logout from wordpress after using on shared computer, or think that while he was using wordpress on some others computer at that time something happens with his connection.That time he will be unable to logout from wordpress .And his account will be in deep danger.
Cause anyone who have access to the account can change the account email address/password and takeover the account.As the process does not require to enter his old password for verification.

## Discussion & Remediation Timeline
