# HackerOne Report: Bypass auth.email-domains
**Report ID:** 4795
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Email addresses are stored as VARCHAR(64). the length is verified on client side only , using a proxy(temper data) attacker can add  longer length email which can be further abused .Exploiting this is rather straightforward: get an email address of 128 characters long . Now register with your 128 character email address with @allowed-domain.com appended to it. The @allowed-domain.com part will be truncated because MySQL can’t store it, and you will receive a verification email on your 128 character email address.

This is especially easy if you’re using a Gmail address: if you own attacker@gmail.com, you’ll also receive any mails sent to attacker+aaaaaaaaaaa…aaa@gmail.com.

snap attached : a POC for a truncated email address



## Discussion & Remediation Timeline
