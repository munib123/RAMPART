# HackerOne Report: Leaking Referrer in Reset Password Link
**Report ID:** 6884
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
I have found that you are leaking via the referrer the reset password link. I am attaching the photo as proof of concept that the site is indeed leaking the reset password link via the referrer.

Thats when someone loads the reset password link and decided to click on external links.

Its the time the referrer is leak ( see attached photo )

Clifford Trigo

## Discussion & Remediation Timeline
