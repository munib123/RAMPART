# HackerOne Report: Old Sessions remain valid after the password change.
**Report ID:** 10186
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
**Industry Standard Procedure**
When the password is changed or email address has been updated for any particular account,all the sessions which were active with the old password/email should be destroyed.
**Reason**
If somehow anybody hacked into your account and you understand that someone has trespassed into your account,then what will you do?You will change your password to secure your account.But in relateIQ changing the password doesnot destroys the other sessions which are logged in with old passwords.So,your account remains insecure even after the changing of password.


## Discussion & Remediation Timeline
