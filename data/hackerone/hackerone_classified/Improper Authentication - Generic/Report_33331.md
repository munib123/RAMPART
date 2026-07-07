# HackerOne Report: Flaw in valid password policy.
**Report ID:** 33331
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
**Steps to reproduce**
1. Go to twitter.com
2. Login with your existing password
3. Change your password from settings.Make 6 space character as your password.
4. After successful update of your password,logout from twitter.com
5. Now login from mobile.twitter.com with existing password (which is 6 or more or less space characters)
6. Now go to settings.
7. Try to update your password.
8. Every time you you request for update,it will say password can't be blank.So you will never be able to update your password from mobile.twitter.com again.


## Discussion & Remediation Timeline
