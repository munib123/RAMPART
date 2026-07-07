# HackerOne Report: CSRF token leakage
**Report ID:** 46736
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi,
I have noticed that when the account verification fails here : https://wallet.robocoin.com/verify/ due to an error, the CSRF token is being leaked via GET method like : https://wallet.robocoin.com/verify/id?_csrf=b8ede20d-0c0b-4e16-9d05-6ad2ed8b72c4
So the authenticity token is being stored in the web browser history and can be retrieved by a malicious attacker in order to mount a successful CSRF attack against the victim. Besides, that the token can be reused multiple times and do not get expired on first use.
Best regards.

## Discussion & Remediation Timeline
