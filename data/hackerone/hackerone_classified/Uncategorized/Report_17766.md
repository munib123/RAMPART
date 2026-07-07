# HackerOne Report: Tap Jacking Attack on Button Tags
**Report ID:** 17766
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
UI Redressing (Tap jacking) attack may trick users into tapping a specifically crafted malicious App popup window (e.g. toast view), making it a gateway for varied threats such as framing attack. Using this technique, a malicious App could potentially trick a user into making purchases, clicking on ads, installing Apps, or even wiping all of the data from the phone.

Button Tags in the layout folder they need to be protect with an attribute "filterTouchesWhenObscured='true".

## Discussion & Remediation Timeline
