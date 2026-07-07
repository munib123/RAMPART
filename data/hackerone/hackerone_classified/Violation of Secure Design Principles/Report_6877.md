# HackerOne Report: Unsecure cookies, cookie flag secure not set
**Report ID:** 6877
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Since you are running on a secure connection, https, you should be ensuring that everything runs securely on your client's / visitors case. I have check the cookie session of IRCCloud and found out that it is not flag as secure.

Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted tunnel. For example, after logging into an application and a session token is set using a cookie, then verify it is tagged using the ";secure" flag. If it is not, then the browser believes it safe to pass via an unencrypted channel such as using HTTP.

Clifford Trigo

## Discussion & Remediation Timeline
