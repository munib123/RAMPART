# HackerOne Report: User guessing/enumeration at  https://app.c2fo.com/api/password-reset
**Report ID:** 5688
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi there,

I noticed a small information leak which allows an attacker to check whether an email address is associated with an account. 

###Steps to reproduce:

1.  Send a POST-Request to the url https://app.c2fo.com/api/password-reset as the following example shows:

```
POST /api/password-reset HTTP/1.1
Host: app.c2fo.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 37

emailAddress=test%40internetwache.org
```

2. I registered an account with the email address, thus the server will respond with ```{"inReset":true}```, which means that the address is in use.

3. Now resend the request again, but with an invalid address like "foobar123@internetwache.org". The application will tell use the following: ```{"error":"invalid_email_address"}```. 

This way I can validate email addresses against your service.

###Suggested fix: 
You should always return a status message like: "If your email exists in our database, you'll receive a reset link". That way an attacker cannot distinguish between the two cases.

Thanks,
Sebastian

## Discussion & Remediation Timeline
