# HackerOne Report: Session not expired on logout
**Report ID:** 353
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
hackerone.com website is not expiring the user's session immediately after logout. 

Steps to verify:
1. Log into the website - hackerone.com.
2. Capture any request. For ex, profile edit page using burp proxy.
3. Logout from the website.
4. Replay the request captured in step 3 and notice it displays the proper response.

## Discussion & Remediation Timeline
