# HackerOne Report: Improper session management
**Report ID:** 737
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
When a request with an invalid authenticity_token is received, the user is logged out (tested for updating user's profile, which is available here: https://hackerone.com/diekatze/profile/edit) and the user receives a new session cookie, which is not authenticated at this point. However, the authenticated session cookie used by a user before logging out is still active.

Regards,
Dawid Czagan

## Discussion & Remediation Timeline
