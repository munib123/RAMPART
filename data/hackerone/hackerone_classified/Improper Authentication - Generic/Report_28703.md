# HackerOne Report: Weak password policy
**Report ID:** 28703
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi there,

I noticed that the website does not prevent an user from using this email address as a password. 
This can lead to some poor password decisions on the clientside.  

#Steps to reproduce

- 1. Create a new account and use the email address as the password.
- 2. Reset your password and choose your email address as the password. 

In both cases, the application does not prevent this decision. 

To improve the password strength, the application should avoid 1-to-1 usage of personal information as the account password. 

I'm aware that you're using rate-limiting to prevent brute-force attacks, but in that case it's just a single email/email authentication request.

Let me know what you think about it.

Best regards,
Sebastian

## Discussion & Remediation Timeline
