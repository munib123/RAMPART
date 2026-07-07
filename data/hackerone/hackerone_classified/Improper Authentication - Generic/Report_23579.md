# HackerOne Report: Broken Authentication and Session Management
**Report ID:** 23579
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi,

Hope you are good!

Steps to Reproduce:
1) Create a Secret account having email address "a@email.com".
2) Now Logout and ask for password reset link. Don't use the password reset link.
3) Login using the same password back and update your email address to "b@email.com" and verify the same.
4) Now logout and use the password reset link which was mailed to "a@email.com" in step 2.
5) Password will be changed.

All previous password reset links should automatically expire once a user changes his email address.
Please let me know if this can be fixed.

Best Regards,
Vinoth Kumar J

## Discussion & Remediation Timeline
