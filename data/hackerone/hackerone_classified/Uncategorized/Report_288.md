# HackerOne Report: Session Management
**Report ID:** 288
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hackerone fails to expire the session cookie from the server side even when the user logs off upon clicking "Sign-Out" from the application. The cookie is cleared from the client side (browser), but is not cleared from the server side. If reused, it provides access to the user's account.
                Upon logging in again, a new session cookie is created, but the old session cookies still stay active on the server side. Therefore, any session cookie can be reused to gain access to the user's account.

## Discussion & Remediation Timeline
