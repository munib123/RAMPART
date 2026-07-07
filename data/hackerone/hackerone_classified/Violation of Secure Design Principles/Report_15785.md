# HackerOne Report: Session not invalidated after password reset
**Report ID:** 15785
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
After a password reset link is requested and a user's password is then changed, not all existing sessions are logged out automatically. The automatic removal of existing sessions linked to a user whose password was changed is only the case if the session was initiated with the 'Remember me for a week' box NOT checked at the log-in page; sessions with the 'remember' option enabled will persist after the password change.

Logging in with the new password doesn't invalidate the older session either: I could browse HackerOne using two sessions (in two different browsers) which were initiated using two different passwords.

## Discussion & Remediation Timeline
