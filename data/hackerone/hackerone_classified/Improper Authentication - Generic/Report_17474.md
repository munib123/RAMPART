# HackerOne Report: Broken Authentication and Session Management
**Report ID:** 17474
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi,

Hope you are good!

Steps to repro:
1) Create a Phabricator account having email address "a@x.com".
2) Now Logout and ask for password reset link. Don't use the password reset link sent to your mail address.
3) Login using the same password back and update your email address to "b@x.com" and verify the same. Remove "a@x.com".
4) Now logout and use the password reset link which was mailed to "a@x.com" in step 2.
5) Password will be changed.

All previous password reset links should automatically expire once a user changes his email address.
Please fix this.

Best Regards
Anand Prakash

## Discussion & Remediation Timeline
