# HackerOne Report: Information disclosure (No rate limting in forgot password & other login)
**Report ID:** 91343
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi there,
I noticed a small information leak which allows an attacker to check whether an email address is associated with an account.If your account is not associated with website then an error will become raise that **"That username or email was not found."**
You should always return a status message like: **"If your email exists in our database, you'll receive a reset link"**. That way an attacker cannot distinguish between the two cases.
Also you should add rate limiting :)

Thanks,

## Discussion & Remediation Timeline
